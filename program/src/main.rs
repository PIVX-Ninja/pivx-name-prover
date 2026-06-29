#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use sha2::{Sha256, Digest};
use alloy_sol_types::{sol, SolValue};

sol! {
    struct BatchResultABI {
        bytes32 old_root;
        bytes32 new_root;
        uint32 end_block_height;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub tx_id: String,
    pub op: String,
    pub domain_name: String,
    pub old_target_address: String,
    pub target_address: String,
    pub old_pubkey: [u8; 32],
    pub pubkey: [u8; 32],
    pub price: u64,
    pub old_price: u64,
    pub nonce: u64,
    pub old_nonce: u64,
    pub signature: Vec<u8>,
    pub merkle_proof: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchPayload {
    pub old_root: [u8; 32],
    pub end_block_height: u32,
    pub transactions: Vec<Transaction>,
}

enum EitherKey<'a> {
    New(&'a VerifyingKey),
    Old(VerifyingKey),
}

impl<'a> EitherKey<'a> {
    fn get(&self) -> &VerifyingKey {
        match self {
            EitherKey::New(key) => key,
            EitherKey::Old(key) => key,
        }
    }
}

pub fn main() {
    let payload: BatchPayload = sp1_zkvm::io::read();
    let mut current_root = payload.old_root;

    for tx in payload.transactions {
        // Parse new pubkey once
        let new_pubkey = VerifyingKey::from_bytes(&tx.pubkey)
            .expect("CRITICAL: New pubkey is not a valid Ed25519 curve point");

        // Write hex of new pubkey once on stack
        let mut pubkey_hex_bytes = [0u8; 64];
        write_hex(&mut pubkey_hex_bytes, &tx.pubkey);

        // 1. REPLAY PROTECTION
        assert!(
            tx.nonce > tx.old_nonce,
            "CRITICAL: Replay attack detected! Nonce {} is not greater than {}", tx.nonce, tx.old_nonce
        );

        // 2. INPUT DATA VALIDATION
        assert!(
            is_domain_valid(&tx.domain_name),
            "CRITICAL: Domain name '{}' failed validation rules", tx.domain_name
        );
        assert!(
            is_address_valid(&tx.target_address),
            "CRITICAL: Target address '{}' is not a valid Bech32 string", tx.target_address
        );

        // 3. STRICT LOGICAL CHECKS & INVARIANT VERIFICATION
        match tx.op.as_str() {
            "REG" => {
                assert_eq!(tx.old_pubkey, [0u8; 32], "CRITICAL: REG old_pubkey must be empty");
                assert_ne!(tx.pubkey, [0u8; 32], "CRITICAL: REG pubkey cannot be empty");
                assert_eq!(tx.old_price, 0, "CRITICAL: REG old_price must be 0");
                // to be strict to PHP Protocol logic
                assert_eq!(tx.price, 0, "CRITICAL: REG price must be 0");
            },
            "UPD" => {
                assert_ne!(tx.pubkey, [0u8; 32], "CRITICAL: UPD pubkey cannot be empty");
                assert_eq!(tx.old_pubkey, tx.pubkey, "CRITICAL: UPD pubkeys must match");
                assert_ne!(tx.old_target_address, tx.target_address, "CRITICAL: UPD must change target address");
                // to be strict to PHP Protocol logic
                assert_eq!(tx.price, 0, "CRITICAL: UPD price must be 0");
                assert_eq!(tx.old_price, 0, "CRITICAL: UPD old_price must be 0");
            },
            "CHG" => {
                assert_ne!(tx.pubkey, [0u8; 32], "CRITICAL: CHG pubkey cannot be empty");
                assert_ne!(tx.old_pubkey, [0u8; 32], "CRITICAL: CHG old_pubkey cannot be empty");
                assert_ne!(tx.old_pubkey, tx.pubkey, "CRITICAL: CHG pubkeys must not match");
                // to be strict to PHP Protocol logic
                assert_eq!(tx.price, 0, "CRITICAL: CHG price must be 0");
                assert_eq!(tx.old_price, 0, "CRITICAL: CHG old_price must be 0");
            },
            "LST" => {
                assert_eq!(tx.old_pubkey, tx.pubkey, "CRITICAL: LST pubkeys must match");
                assert!(tx.price > 0, "CRITICAL: LST price must be greater than 0");
                assert_eq!(tx.old_price, 0, "CRITICAL: LST old_price must be 0");
            },
            "ULT" => {
                assert_eq!(tx.old_pubkey, tx.pubkey, "CRITICAL: ULT pubkeys must match");
                assert!(tx.old_price > 0, "CRITICAL: ULT domain must be listed");
                assert_eq!(tx.price, 0, "CRITICAL: ULT new price must be 0");
            },
            "BUY" => {
                assert_ne!(tx.pubkey, [0u8; 32], "CRITICAL: BUY pubkey cannot be empty");
                assert_ne!(tx.old_pubkey, [0u8; 32], "CRITICAL: BUY old_pubkey cannot be empty");
                assert_ne!(tx.old_pubkey, tx.pubkey, "CRITICAL: BUY pubkeys must not match");
                assert!(tx.old_price > 0, "CRITICAL: Cannot buy unlisted domain");
                assert_eq!(tx.old_price, tx.price, "CRITICAL: Paid price does not match listed price");
            },
            _ => panic!("CRITICAL: Unknown operation '{}' in TX {}", tx.op, tx.tx_id),
        }

        // 4. SIGNATURE CHECKING (Allocation-free byte buffer construction)
        let (signer_pubkey, message_bytes) = match tx.op.as_str() {
            "REG" | "UPD" => {
                let mut msg = Vec::with_capacity(64 + tx.domain_name.len() + tx.target_address.len());
                msg.extend_from_slice(b"PiNS:1:");
                msg.extend_from_slice(tx.op.as_bytes());
                msg.push(b':');
                msg.extend_from_slice(tx.domain_name.as_bytes());
                msg.push(b':');
                msg.extend_from_slice(tx.target_address.as_bytes());
                msg.push(b':');
                msg.extend_from_slice(&pubkey_hex_bytes);
                msg.push(b':');
                push_u64_bytes(&mut msg, tx.nonce);
                (EitherKey::New(&new_pubkey), msg)
            },
            "CHG" => {
                // Signer is the CURRENT owner (old_pubkey).
                let old_pubkey = VerifyingKey::from_bytes(&tx.old_pubkey)
                    .expect("CRITICAL: Old pubkey is not a valid Ed25519 curve point");
                let mut msg = Vec::with_capacity(32 + tx.domain_name.len());
                msg.extend_from_slice(b"PiNS:1:CHG:");
                msg.extend_from_slice(tx.domain_name.as_bytes());
                msg.push(b':');
                msg.extend_from_slice(&pubkey_hex_bytes);
                msg.push(b':');
                push_u64_bytes(&mut msg, tx.nonce);
                (EitherKey::Old(old_pubkey), msg)
            },
            "LST" => {
                let mut msg = Vec::with_capacity(32 + tx.domain_name.len());
                msg.extend_from_slice(b"PiNS:1:LST:");
                msg.extend_from_slice(tx.domain_name.as_bytes());
                msg.push(b':');
                msg.extend_from_slice(&pubkey_hex_bytes);
                msg.push(b':');
                push_u64_bytes(&mut msg, tx.price);
                msg.push(b':');
                push_u64_bytes(&mut msg, tx.nonce);
                (EitherKey::New(&new_pubkey), msg)
            },
            "ULT" => {
                let mut msg = Vec::with_capacity(32 + tx.domain_name.len());
                msg.extend_from_slice(b"PiNS:1:ULT:");
                msg.extend_from_slice(tx.domain_name.as_bytes());
                msg.push(b':');
                msg.extend_from_slice(&pubkey_hex_bytes);
                msg.push(b':');
                push_u64_bytes(&mut msg, tx.nonce);
                (EitherKey::New(&new_pubkey), msg)
            },
            "BUY" => {
                let mut msg = Vec::with_capacity(64 + tx.domain_name.len() + tx.target_address.len());
                msg.extend_from_slice(b"PiNS:1:BUY:");
                msg.extend_from_slice(tx.domain_name.as_bytes());
                msg.push(b':');
                msg.extend_from_slice(tx.target_address.as_bytes());
                msg.push(b':');
                msg.extend_from_slice(&pubkey_hex_bytes);
                msg.push(b':');
                push_u64_bytes(&mut msg, tx.nonce);
                (EitherKey::New(&new_pubkey), msg)
            },
            _ => unreachable!(),
        };

        assert!(
            is_signature_valid(&signer_pubkey, &message_bytes, &tx.signature),
            "CRITICAL: Invalid signature for TX {}", tx.tx_id
        );

        // 5. SMT LEAF TRANSITIONS
        let (expected_old_leaf, new_leaf) = match tx.op.as_str() {
            "REG" => {
                let new_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.target_address, 0, tx.nonce);
                ([0u8; 32], new_leaf)
            },
            "UPD" => {
                let old_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.old_target_address, 0, tx.old_nonce);
                let new_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.target_address, 0, tx.nonce);
                (old_leaf, new_leaf)
            },
            "CHG" => {
                let old_leaf = hash_leaf(&tx.domain_name, &tx.old_pubkey, &tx.target_address, 0, tx.old_nonce);
                let new_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.target_address, 0, tx.nonce);
                (old_leaf, new_leaf)
            },
            "LST" => {
                let old_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.target_address, tx.old_price, tx.old_nonce);
                let new_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.target_address, tx.price, tx.nonce);
                (old_leaf, new_leaf)
            },
            "ULT" => {
                let old_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.target_address, tx.old_price, tx.old_nonce);
                let new_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.target_address, 0, tx.nonce);
                (old_leaf, new_leaf)
            },
            "BUY" => {
                let old_leaf = hash_leaf(&tx.domain_name, &tx.old_pubkey, &tx.old_target_address, tx.old_price, tx.old_nonce);
                let new_leaf = hash_leaf(&tx.domain_name, &tx.pubkey, &tx.target_address, 0, tx.nonce);
                (old_leaf, new_leaf)
            },
            _ => unreachable!(),
        };

        current_root = verify_and_update_smt(&tx.domain_name, expected_old_leaf, new_leaf, &tx.merkle_proof, current_root);
    }

    let result_abi = BatchResultABI {
        old_root: payload.old_root.into(),
        new_root: current_root.into(),
        end_block_height: payload.end_block_height,
    };

    sp1_zkvm::io::commit_slice(&result_abi.abi_encode());
}

fn is_signature_valid(pubkey: &EitherKey, message: &[u8], sig_bytes: &[u8]) -> bool {
    if let Ok(signature) = Signature::from_slice(sig_bytes) {
        return pubkey.get().verify(message, &signature).is_ok();
    }
    false
}

fn hash_leaf(domain: &str, pubkey: &[u8; 32], target_address: &str, price: u64, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(pubkey);
    hasher.update(target_address.as_bytes());
    hasher.update(price.to_le_bytes()); 
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

fn verify_and_update_smt(
    domain: &str,
    old_leaf: [u8; 32],
    new_leaf: [u8; 32],
    proof: &[[u8; 32]], 
    current_root: [u8; 32]
) -> [u8; 32] {
    assert_eq!(proof.len(), 128, "CRITICAL: Merkle proof must be exactly 128 levels deep");

    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    let path_hash: [u8; 32] = hasher.finalize().into();

    let mut calc_root = old_leaf;
    let mut new_calc_root = new_leaf;

    let mut i = 0;
    for byte_val in path_hash[..16].iter().rev() {
        let mut temp_byte = *byte_val;
        for _ in 0..8 {
            let is_right_node = (temp_byte & 1) == 1;
            temp_byte >>= 1;

            let sibling = &proof[i];

            let mut hasher_old = Sha256::new();
            let mut hasher_new = Sha256::new();

            if is_right_node {
                hasher_old.update(sibling);
                hasher_old.update(&calc_root);

                hasher_new.update(sibling);
                hasher_new.update(&new_calc_root);
            } else {
                hasher_old.update(&calc_root);
                hasher_old.update(sibling);

                hasher_new.update(&new_calc_root);
                hasher_new.update(sibling);
            }

            calc_root = hasher_old.finalize().into();
            new_calc_root = hasher_new.finalize().into();
            i += 1;
        }
    }

    assert_eq!(
        calc_root, current_root, 
        "CRITICAL: Merkle proof verification failed for domain '{}'", domain
    );

    new_calc_root
}

// Helper functions
fn is_domain_valid(domain: &str) -> bool {
    let bytes = domain.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    
    if bytes.iter().filter(|&&b| b == b'.').count() != 1 {
        return false;
    }

    if bytes[0] == b'-' || domain.contains("--") {
        return false;
    }

    let mut split = domain.splitn(3, '.');
    let prefix = match split.next() {
        Some(p) => p,
        None => return false,
    };
    let zone = match split.next() {
        Some(z) => z,
        None => return false,
    };
    if split.next().is_some() {
        return false;
    }

    if prefix.is_empty() || prefix.as_bytes().last() == Some(&b'-') {
        return false;
    }

    if !prefix.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return false;
    }

    let allowed_zones = ["pivx", "private", "secure", "safe"];
    allowed_zones.contains(&zone)
}

fn is_address_valid(address: &str) -> bool {
    if let Ok((hrp, _, _)) = bech32::decode(address) {
        return hrp == "pts";
    }
    false
}

fn write_hex(buf: &mut [u8], bytes: &[u8]) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in bytes.iter().enumerate() {
        buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
        buf[i * 2 + 1] = HEX_CHARS[(b & 0xf) as usize];
    }
}

fn push_u64_bytes(buf: &mut Vec<u8>, mut val: u64) {
    if val == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut idx = 20;
    while val > 0 {
        idx -= 1;
        tmp[idx] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    buf.extend_from_slice(&tmp[idx..]);
}
