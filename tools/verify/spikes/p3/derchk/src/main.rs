use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn main() {
    let text = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let (mut ok, mut high, mut raw_ok, mut flip_fail, mut mode_digest) = (0, 0, 0, 0, 0);
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[1] == "digest" { mode_digest += 1; }
        let (key, msg, der) = (unhex(f[2]), unhex(f[3]), unhex(f[4]));
        let sig = Signature::from_der(&der).expect("from_der");
        if sig.normalize_s() != sig { high += 1; }
        let vk = VerifyingKey::from_sec1_bytes(&key).unwrap();
        // verify exactly as produced (high-S not normalised)
        vk.verify(&msg, &sig).expect("verify as produced");
        ok += 1;
        // raw r||s round trip (the wire form)
        let raw: [u8; 64] = sig.to_bytes().into();
        let back = Signature::from_slice(&raw).unwrap();
        if vk.verify(&msg, &back).is_ok() { raw_ok += 1; }
        let mut m2 = msg.clone(); m2[0] ^= 1;
        if vk.verify(&m2, &sig).is_err() { flip_fail += 1; }
    }
    println!("as-produced verify ok {ok} (high-S {high}), raw round-trip ok {raw_ok}, flipped-msg refused {flip_fail}, digest-mode lines {mode_digest}");
}
