use synergy_pq_evm_core::{verify_transport_evidence, TransportEvidenceInput};

fn hex32(s:&str)->Option<[u8;32]>{
    if s.len()!=64 { return None; }
    let mut out=[0u8;32];
    for i in 0..32 {
        out[i]=u8::from_str_radix(&s[i*2..i*2+2],16).ok()?;
    }
    Some(out)
}

fn main(){
    let args:Vec<String>=std::env::args().collect();
    if args.len()!=9 {
        eprintln!("usage: session sender receiver sha256 authenticated route_csv bytes_on_wire latency_ms");
        std::process::exit(2);
    }
    let content_sha256=hex32(&args[4]).expect("sha256");
    let authenticated=args[5]=="true";
    let route=args[6].split(',').map(|s|s.to_owned()).collect();
    let bytes_on_wire=args[7].parse::<u64>().expect("bytes");
    let latency_ms=args[8].parse::<f64>().expect("latency");
    let input=TransportEvidenceInput{
        session_id:args[1].clone(),sender_peer:args[2].clone(),receiver_peer:args[3].clone(),
        content_sha256,authenticated,route,bytes_on_wire,latency_ms
    };
    if !verify_transport_evidence(&input) {
        eprintln!("REJECT");
        std::process::exit(1);
    }
    println!("PASS {}",args[4]);
}
