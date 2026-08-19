use std::time::Instant;
use cl_se_rust::{KGC, UserKeys, encrypt_index, generate_trapdoor, search};

fn main() {
    println!("==================================================");
    println!("  CL-SE Scheme X: High-Performance Rust Benchmark ");
    println!("==================================================");

    // 1. Setup Phase
    let start = Instant::now();
    let kgc = KGC::setup();
    let setup_time = start.elapsed();
    println!("[+] Setup Phase (KGC): {:.3} ms", setup_time.as_micros() as f64 / 1000.0);

    // 2. KeyGen Phase (Data Owner, Data User, Cloud Server)
    let start = Instant::now();
    let do_keys = UserKeys::generate(&kgc, b"DataOwner@iot.net");
    let du_keys = UserKeys::generate(&kgc, b"DataUser@doctor.org");
    let cs_keys = UserKeys::generate(&kgc, b"CloudServer@aws.com");
    let keygen_time = start.elapsed();
    println!("[+] Key Generation (3 entities): {:.3} ms", keygen_time.as_micros() as f64 / 1000.0);

    let keyword = b"MEDICAL_RECORD_123";

    // 3. Encrypt Phase (Data Owner)
    let start = Instant::now();
    let (r_point, c_w) = encrypt_index(keyword, &du_keys.pk_1, &kgc.master_public);
    let encrypt_time = start.elapsed();
    println!("[+] Encrypt (Index Generation): {:.3} ms", encrypt_time.as_micros() as f64 / 1000.0);

    // 4. Trapdoor Phase (Data User)
    let start = Instant::now();
    let (t1, t3, t2) = generate_trapdoor(keyword, &do_keys.pk_1, &cs_keys.pk_1, &du_keys.user_secret);
    let trapdoor_time = start.elapsed();
    println!("[+] Trapdoor Generation (Dual-Blinded): {:.3} ms", trapdoor_time.as_micros() as f64 / 1000.0);

    // 5. Search / Test Phase (Cloud Server)
    let start = Instant::now();
    let is_match = search(&t1, &t3, &t2, &r_point, &c_w, &cs_keys.user_secret, &kgc.master_secret);
    let search_time = start.elapsed();
    println!("[+] Search / Test Phase: {:.3} ms", search_time.as_micros() as f64 / 1000.0);

    println!("==================================================");
    if is_match {
        println!("[*] RESULT: Trapdoor MATCHES Keyword successfully!");
    } else {
        println!("[*] RESULT: Trapdoor Mismatch!");
    }

    // Benchmark 1000 searches to show scalability
    println!("--------------------------------------------------");
    println!("Running Bulk Search Benchmark (1000 iterations)...");
    let bulk_start = Instant::now();
    for _ in 0..1000 {
        let _ = search(&t1, &t3, &t2, &r_point, &c_w, &cs_keys.user_secret, &kgc.master_secret);
    }
    let bulk_time = bulk_start.elapsed();
    println!("[+] 1000 Searches Completed in {:.3} ms ({:.3} ms per search)", 
             bulk_time.as_micros() as f64 / 1000.0,
             bulk_time.as_micros() as f64 / 1_000_000.0);
    println!("==================================================");
}
