#![forbid(unsafe_code)]

use std::env;
use std::io::{self, BufRead, Write};

use scitt_time_anchor_rs::engine::evaluate_line;
use scitt_time_anchor_rs::ots::VerifierMode;

fn parse_cli_mode() -> VerifierMode {
    let args: Vec<String> = env::args().collect();
    let mut i = 1usize;
    while i < args.len() {
        if args[i] == "--mode" && i + 1 < args.len() {
            if let Some(m) = VerifierMode::from_str_name(&args[i + 1]) {
                return m;
            }
            eprintln!(
                "Invalid --mode '{}'; expected draft08 or strict",
                args[i + 1]
            );
            std::process::exit(2);
        } else if let Some(rest) = args[i].strip_prefix("--mode=") {
            if let Some(m) = VerifierMode::from_str_name(rest) {
                return m;
            }
            eprintln!("Invalid --mode '{}'; expected draft08 or strict", rest);
            std::process::exit(2);
        }
        i += 1;
    }
    VerifierMode::Draft08
}

fn main() {
    let default_mode = parse_cli_mode();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp = evaluate_line(trimmed, default_mode);
        let _ = writeln!(out, "{}", resp);
    }
    let _ = out.flush();
}
