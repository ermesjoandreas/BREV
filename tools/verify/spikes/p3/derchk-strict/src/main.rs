use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn main() {
    let text = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let (mut ok, mut high) = (0, 0);
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (key, msg, der) = (unhex(f[2]), unhex(f[3]), unhex(f[4]));
        let sig = Signature::from_der(&der).expect("from_der");
        let n = sig.normalize_s();
        if n != sig { high += 1; }
        let vk = VerifyingKey::from_sec1_bytes(&key).unwrap();
        vk.verify(&msg, &n).expect("verify normalised");
        // round trip: re-encode must equal input (DER is canonical)
        assert_eq!(sig.to_der().as_bytes(), &der[..], "re-encode");
        ok += 1;
    }
    // strictness negatives from the spike parser's tests
    let neg: &[&[u8]] = &[
        &[],
        &[0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x01,0x00],          // trailing byte
        &[0x30,0x06,0x02,0x01,0x81,0x02,0x01,0x01],               // negative r
        &[0x30,0x07,0x02,0x02,0x00,0x01,0x02,0x01,0x01],          // non-minimal r
        &[0x30,0x81,0x06,0x02,0x01,0x01,0x02,0x01,0x01],          // long-form length
        &[0x30,0x06,0x02,0x01,0x00,0x02,0x01,0x01],               // r = 0
    ];
    let mut refused = 0;
    for (i, n) in neg.iter().enumerate() {
        match Signature::from_der(n) { Err(_) => refused += 1, Ok(_) => println!("negative {i} ACCEPTED") }
    }
    println!("from_der ok {ok}, high-S {high}, negatives refused {refused}/{}", neg.len());
}
