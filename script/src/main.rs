use sp1_sdk::{include_elf, Elf, ProverClient, SP1Stdin, Prover, ProveRequest, HashableKey, ProvingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use clap::Parser;
use anyhow::{Context, Result};
use alloy_sol_types::{sol, SolType};
use tracing::{info, error};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

// MUST MATCH GUEST EXACTLY
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub tx_id: String,
    pub op: String,
    pub domain_name: String,
    pub old_target_address: String,
    pub target_address: String,
    pub old_pubkey: [u8; 32], // The previous owner
    pub pubkey: [u8; 32],     // The new/current owner
    pub price: u64,           // The requested action price
    pub old_price: u64,       // The previous price state
    pub nonce: u64,           // The current timestamp/nonce
    pub old_nonce: u64,       // The previous nonce from the DB
    pub signature: Vec<u8>,
    pub merkle_proof: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchPayload {
    pub old_root: [u8; 32],
    pub end_block_height: u32,
    pub transactions: Vec<Transaction>,
}

// ABI structure for decoding SP1 outputs
sol! {
    struct BatchResultABI {
        bytes32 old_root;
        bytes32 new_root;
        uint32 end_block_height;
    }
}

// Used to generate the {batch_id}_result.json file
#[derive(Serialize)]
pub struct FinalResultJson {
    pub old_root: String,
    pub new_root: String,
    pub end_block_height: u32,
}

// 1. Define the CLI Arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "SP1 Prover Script for PiNS")]
struct Args {
    #[arg(long)]
    batch_dir: String,

    #[arg(long)]
    batch_id: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let batch_dir = PathBuf::from(&args.batch_dir);
    
    let error_file_path = batch_dir.join(format!("{}_error.txt", args.batch_id));

    // 2. Clear any existing error file from a previous failed run
    if error_file_path.exists() {
        let _ = fs::remove_file(&error_file_path);
    }

    // 3. Configure robust logging (Writes to both Console AND debug.log)
    let log_filename = format!("{}_debug.log", args.batch_id);
    let file_appender = tracing_appender::rolling::never(&batch_dir, &log_filename);
    
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(file_appender).with_ansi(false)) // No colors in log file
        .with(fmt::layer().with_writer(std::io::stdout))                // Standard console output
        .init();

    // 4. Run the prover inside a safe Result block
    if let Err(e) = run_prover(&args, &batch_dir).await {
        // If an error bubbles up, log it and write the error.txt file
        let error_msg = format!("CRITICAL ERROR:\n{:#}\n", e);
        error!("{}", error_msg);
        
        if let Err(write_err) = fs::write(&error_file_path, &error_msg) {
            eprintln!("Failed to write error.txt file: {}", write_err);
        }
        
        std::process::exit(1); // Exit with a failure code for your PHP backend to detect
    }
    
    info!("Proving process completed successfully for Batch {}", args.batch_id);
}

// The core logic, but now using `?` operators to safely bubble errors up
async fn run_prover(args: &Args, batch_dir: &PathBuf) -> Result<()> {
    // Dynamically build all necessary file paths
    let input_json_path = batch_dir.join(format!("{}_batch.json", args.batch_id));
    let proof_bin_path = batch_dir.join(format!("{}_proof.bin", args.batch_id));
    let public_values_path = batch_dir.join(format!("{}_public_values.bin", args.batch_id));
    let result_json_path = batch_dir.join(format!("{}_result.json", args.batch_id));

    info!("Starting prover for Batch ID: {}", args.batch_id);
    
    // Read and parse input
    info!("Loading payload from: {}", input_json_path.display());
    let json_data = fs::read_to_string(&input_json_path)
        .with_context(|| format!("Missing input file: {}", input_json_path.display()))?;

    let payload: BatchPayload = serde_json::from_str(&json_data)
        .context("Failed to parse JSON into BatchPayload structure")?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&payload);

    // Initialize SP1
    info!("Initializing SP1 Prover Client");
    let client = ProverClient::from_env().await;
    let elf: Elf = include_elf!("pins-program");

    info!("Setting up keys...");
    let pk = client.setup(elf).await.context("Failed to setup proving keys")?;

    info!("Program Verification Key (vkey): {}", pk.verifying_key().bytes32());

    info!("Generating SNARK Proof (This will take a while)...");
    let proof = client.prove(&pk, stdin).groth16().await.context("Prover execution failed!")?;

    // Decode public values
    info!("Proof generated successfully. Decoding ABI...");
    let result_bytes = proof.public_values.as_slice();
    
    // Note: depending on your alloy version, you may need to use `BatchResultABI::abi_decode(result_bytes, true)`
    let result_abi = BatchResultABI::abi_decode(result_bytes)
        .context("Failed to decode ABI from public values")?;

    info!("Batch Ended at Block: {}", result_abi.end_block_height);
    info!("Old Root: 0x{}", hex::encode(result_abi.old_root));
    info!("New Root: 0x{}", hex::encode(result_abi.new_root));

    // Save outputs
    info!("Saving proof components to disk...");
    fs::write(&proof_bin_path, proof.bytes()).context("Failed to write proof.bin")?;
    fs::write(&public_values_path, result_bytes).context("Failed to write public_values.bin")?;

    // Create the final structured JSON result for your PHP/Sequencer script
    let final_result = FinalResultJson {
        old_root: format!("0x{}", hex::encode(result_abi.old_root)),
        new_root: format!("0x{}", hex::encode(result_abi.new_root)),
        end_block_height: result_abi.end_block_height,
    };

    let final_result_json = serde_json::to_string_pretty(&final_result)
        .context("Failed to serialize final result to JSON")?;

    fs::write(&result_json_path, final_result_json).context("Failed to write result.json")?;

    Ok(())
}
