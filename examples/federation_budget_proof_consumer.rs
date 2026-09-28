use synergy_pq_evm_core::federation_contracts::verify_budget_proof_root;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: dataset_id snapshot_id record_merkle_root record_count");
        std::process::exit(2);
    }
    let count = args[4].parse::<u64>().expect("record_count");
    if !verify_budget_proof_root(&args[1], &args[2], &args[3], count) {
        eprintln!("REJECT");
        std::process::exit(1);
    }
    println!("PASS {} {} {}", args[1], args[2], args[3]);
}
