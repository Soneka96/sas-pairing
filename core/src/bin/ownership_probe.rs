use std::io::{self, Read, Write};

use sas_pairing_core::Authority;

fn main() {
    let scope = std::env::args().nth(1).expect("scope argument");
    let authority = Authority::register(scope.as_bytes()).expect("authority ownership");
    println!("READY");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);
    drop(authority);
}
