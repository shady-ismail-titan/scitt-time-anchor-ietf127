#![forbid(unsafe_code)]

use std::env;
use std::io::{self, BufRead, Write};

use scitt_time_anchor_rs::engine::{evaluate_line, MAX_JSON_LINE_BYTES};
use scitt_time_anchor_rs::ots::VerifierMode;

fn parse_cli_mode() -> VerifierMode {
    let args: Vec<String> = env::args().collect();
    let mut i = 1usize;
    while i < args.len() {
        if args[i] == "--help" || args[i] == "-h" {
            println!(
                "scitt_time_anchor_rs {} — Clean-room SCITT Time Anchor Verifier (Rust)\n\
                 Usage: scitt_time_anchor_rs [--mode draft08|strict] [--version] [--help]\n\
                 NOTE: Verifies temporal anchoring only; COSE cryptographic signature\n\
                 verification is delegated to your SCITT verifier / Trust Store.",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(0);
        }
        if args[i] == "--version" || args[i] == "-V" {
            println!("scitt_time_anchor_rs {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
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

enum BoundedLine {
    Eof,
    Ok,
    TooLong,
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> io::Result<BoundedLine> {
    buf.clear();
    let mut saw_any = false;
    let mut exceeded = false;

    loop {
        let avail = reader.fill_buf()?;
        if avail.is_empty() {
            break;
        }
        saw_any = true;
        let (consume_len, data_len, found_nl) = match avail.iter().position(|&b| b == b'\n') {
            Some(idx) => (idx + 1, idx, true),
            None => (avail.len(), avail.len(), false),
        };
        if !exceeded {
            // Allow +1 byte temporarily so a trailing '\r' before '\n' can be stripped cleanly.
            if buf.len().saturating_add(data_len) > max_bytes.saturating_add(1) {
                exceeded = true;
                buf.clear();
            } else {
                buf.extend_from_slice(&avail[..data_len]);
            }
        }
        reader.consume(consume_len);
        if found_nl {
            break;
        }
    }

    if !saw_any {
        return Ok(BoundedLine::Eof);
    }
    if exceeded {
        return Ok(BoundedLine::TooLong);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if buf.len() > max_bytes {
        buf.clear();
        return Ok(BoundedLine::TooLong);
    }
    Ok(BoundedLine::Ok)
}

fn main() {
    let default_mode = parse_cli_mode();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut line_buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        match read_bounded_line(&mut reader, &mut line_buf, MAX_JSON_LINE_BYTES) {
            Ok(BoundedLine::Eof) => break,
            Ok(BoundedLine::TooLong) => {
                let _ = writeln!(out, "{{\"error\": \"bad_json\"}}");
            }
            Ok(BoundedLine::Ok) => {
                let line = match core::str::from_utf8(&line_buf) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = writeln!(out, "{{\"error\": \"bad_json\"}}");
                        continue;
                    }
                };
                let trimmed = line.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
                if trimmed.is_empty() {
                    continue;
                }
                let resp = evaluate_line(trimmed, default_mode);
                let _ = writeln!(out, "{}", resp);
            }
            Err(_) => break,
        }
    }
    let _ = out.flush();
}
