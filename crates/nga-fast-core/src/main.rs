use std::fs;
use std::io::{self, Read};
use nga_fast_core::{extract_printable_ascii, fnv1a_64, is_safe_relative_entry};

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("check-entry") => {
            let val = args.next().unwrap_or_default();
            println!("{{\"safe\":{}}}", is_safe_relative_entry(&val));
        }
        Some("scan") => {
            let path = args.next().unwrap_or_default();
            if path.is_empty() {
                let mut stdin_buf = Vec::new();
                let _ = io::stdin().read_to_end(&mut stdin_buf);
                let strings = extract_printable_ascii(&stdin_buf, 4, 50, 256);
                println!("{{\"fnv1a_64\":{},\"strings_count\":{}}}", fnv1a_64(&stdin_buf), strings.len());
                return;
            }
            match fs::read(&path) {
                Ok(bytes) => {
                    let strings = extract_printable_ascii(&bytes, 4, 50, 256);
                    println!("{{\"fnv1a_64\":{},\"strings_count\":{}}}", fnv1a_64(&bytes), strings.len());
                }
                Err(e) => {
                    eprintln!("Error reading file: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            println!("{{\"ok\":true,\"crate\":\"nga-fast-core\"}}");
        }
    }
}
