# PiNS Prover (PIVX Name Service ZK Prover)

**PiNS Prover** is a Zero-Knowledge (ZK) state-transition prover for the **PIVX Name Service (PiNS)**. It executes batch validation of off-chain domain updates inside a zero-knowledge Virtual Machine (zkVM) and generates succinct cryptographic proofs (Groth16 SNARKs) to update domain state roots securely on-chain.

---

## 📌 Overview & Functionality

The PiNS Prover processes batches of domain transactions, verifying all cryptographic and state transition rules off-chain before committing state changes to the blockchain.

### Supported Operations
- **`REG` (Register)**: Initial registration of a domain mapped to a Bech32 (`ps...`) target address and Ed25519 public key.
- **`UPD` (Update)**: Updating target addresses for existing domains.
- **`CHG` (Change Owner)**: Transferring domain ownership to a new Ed25519 public key.
- **`LST` (List)**: Listing a domain for sale on the marketplace at a specified price.
- **`ULT` (Unlist)**: Removing a domain listing from the marketplace.
- **`BUY` (Buy)**: Purchasing a listed domain and transferring ownership.

### What the Guest Program (`program`) Does
For each transaction in a batch, the guest program running inside the zkVM strictly enforces:
1. **Replay Protection**: Verifies sequential nonces (`nonce > old_nonce`).
2. **Input Validation**: Ensures valid domain string rules and Bech32 address formats.
3. **Cryptographic Signatures**: Validates Ed25519 signatures of domain owners.
4. **State Transition Integrity**: Validates and updates leaf nodes in a 128-level Sparse Merkle Tree (SMT).
5. **ABI Commit**: Encodes and commits the initial root (`old_root`), final root (`new_root`), and target block height (`end_block_height`) as public values.

---

## 🛠 Tech Stack & Dependencies

- **[Succinct SP1](https://github.com/succinctlabs/sp1)**: A performant 100% open-source zero-knowledge virtual machine (zkVM) that executes arbitrary Rust code compiled to RISC-V.
- **Zero-Knowledge Proofs (Groth16 SNARKs)**: Utilizes SP1's proof generation capabilities to produce succinct Groth16 proofs suitable for cost-effective EVM verification.
- **[Alloy](https://github.com/alloy-rs/alloy)**: Solidity type definitions and ABI encoding/decoding for EVM interoperability.
- **Ed25519 & SHA-256**: Acceleration for signature verification and Merkle tree hashing inside the zkVM.

---

## 🔗 Smart Contract Integration & Trustless State

The PiNS Prover operates in tandem with the **Arbitrum Smart Contract**:  
👉 **[PIVX_Ninja/pivx-name-evm-anchor](https://github.com/PIVX_Ninja/pivx-name-evm-anchor)**

### How Trustlessness is Achieved
1. **Off-Chain Execution, On-Chain Verification**: Sequencers bundle domain transactions off-chain and run the PiNS Prover script to generate a Groth16 SNARK proof along with public outputs (`old_root`, `new_root`).
2. **Cryptographic Proof Verification**: The proof and public values are submitted to the EVM smart contract deployed on Arbitrum. The contract verifies the proof via the SP1 Verifier contract on-chain.
3. **No-Trust Obligation**: The smart contract does not need to trust the sequencer or operator executing the prover. The cryptographic proof mathematically guarantees that:
   - All transactions inside the batch were validly signed by their respective owners.
   - The state root transition from `old_root` to `new_root` strictly follows protocol rules without state corruption.
   - No invalid registrations, double-spends, or unauthorized domain transfers occurred.

### Verification Key (`vKey`) & On-Chain Connection
- **What is a `vKey`?** When the guest program code (`program`) is compiled into a RISC-V ELF binary, SP1 computes a unique cryptographic 32-byte identifier called the **Program Verification Key (`vKey`)**. Any modification to the guest logic, dependencies, or code will alter this `vKey`.
- **Connecting to Smart Contract**: The Arbitrum smart contract stores this exact `programVKey` on-chain. When a proof is submitted, the on-chain SP1 Verifier contract checks that the proof was generated specifically by the program matching this registered `vKey`. If a registrar attempts to run modified or malicious program code, the generated proof will be bound to a different `vKey` and rejected by the smart contract.

### Proving Open-Source Immutability (Reproducible Builds)
- Anyone can audit and verify that the registrar is running the exact, untampered open-source code from this repository.
- By running a deterministic Docker build (`cargo prove build --docker`), SP1 compiles the Rust guest code inside a standardized environment, producing an identical RISC-V ELF binary and `vKey` anywhere.
- Comparing your locally compiled `vKey` with the `programVKey` registered in the Arbitrum smart contract mathematically proves that the deployed, active prover on the registrar side corresponds 1:1 with this open-source code.

---

## 📁 Repository Structure

```
├── program/           # ZK Guest Program (runs inside SP1 zkVM)
│   ├── Cargo.toml
│   └── src/main.rs    # Core validation & SMT state transition logic
├── script/            # Host Prover Executable (CLI script)
│   ├── Cargo.toml
│   └── src/main.rs    # SP1 Prover Client runner & proof generator
├── Cargo.toml         # Workspace manifest with SP1 patched cryptographic crates
└── README.md
```

---

## 🚀 Usage

### Requirements
- **Rust toolchain** (compatible with SP1)
- **SP1 toolchain (`sp1up`)** installed

### Building the Guest Program
To compile the zkVM guest program into ELF format, navigate to the `program` directory:
```bash
cd program
cargo prove build
```

For deterministic/reproducible builds using Docker (to verify `vKey` matching):
```bash
cd program
cargo prove build --docker
```
