use std::io::{self, Read, Write};

use sas_pairing_core::TrustedAuthority;

fn main() {
    let scope = std::env::args().nth(1).expect("scope argument");
    if std::env::args().any(|arg| arg == "--race") {
        println!("ARMED");
        let _ = io::stdout().flush();
        let mut command = String::new();
        if io::stdin().read_line(&mut command).is_err() || command.trim() != "GO" {
            std::process::exit(2);
        }
        match TrustedAuthority::register(scope.as_bytes()) {
            Ok(authority) => {
                println!("WON");
                let _ = io::stdout().flush();
                command.clear();
                let _ = io::stdin().read_line(&mut command);
                drop(authority);
                println!("RELEASED");
            }
            Err(_) => {
                println!("LOST");
                let _ = io::stdout().flush();
                std::process::exit(1);
            }
        }
        let _ = io::stdout().flush();
        return;
    }
    let authority = TrustedAuthority::register(scope.as_bytes()).expect("authority ownership");
    println!("READY");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);
    drop(authority);
}
