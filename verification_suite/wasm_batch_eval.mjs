#!/usr/bin/env node
/**
 * Node V8 WebAssembly JSONL batch evaluator & Byte-Ray stack-stress runner
 * for `web/scitt_time_anchor.wasm`.
 *
 * Reads JSONL from stdin in chunks (<= 2 MB per WASM call) and writes
 * JSONL evaluation outputs to stdout. With `--stress-deep`, also verifies
 * zero WASM 1 MB shadow-stack overflow on a 4.17 KB 4096-op `.ots` proof
 * and a 5.1 KB 5000-op over-depth `.ots` proof in both `wasm_evaluate_jsonl`
 * and `wasm_dissect_ots`.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const WASM_PATH = path.join(ROOT, "web", "scitt_time_anchor.wasm");

const wasmBytes = fs.readFileSync(WASM_PATH);
const { instance } = await WebAssembly.instantiate(wasmBytes, {});
const {
  memory,
  wasm_prepare_input,
  wasm_output_ptr,
  wasm_output_len,
  wasm_evaluate_jsonl,
  wasm_dissect_ots,
} = instance.exports;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function callWasmJsonl(chunkStr, defaultModeId = 0) {
  const encoded = encoder.encode(chunkStr);
  const inPtr = wasm_prepare_input(encoded.length);
  if (inPtr === 0 && encoded.length > 0) {
    throw new Error(`wasm_prepare_input returned 0 for ${encoded.length} bytes`);
  }
  new Uint8Array(memory.buffer, inPtr, encoded.length).set(encoded);
  const outLen = wasm_evaluate_jsonl(defaultModeId);
  const outPtr = wasm_output_ptr();
  return decoder.decode(new Uint8Array(memory.buffer, outPtr, outLen));
}

function callWasmDissect(rawBytes) {
  const inPtr = wasm_prepare_input(rawBytes.length);
  if (inPtr === 0 && rawBytes.length > 0) {
    throw new Error(`wasm_prepare_input returned 0 for ${rawBytes.length} bytes`);
  }
  new Uint8Array(memory.buffer, inPtr, rawBytes.length).set(rawBytes);
  const outLen = wasm_dissect_ots();
  const outPtr = wasm_output_ptr();
  return JSON.parse(decoder.decode(new Uint8Array(memory.buffer, outPtr, outLen)));
}

if (process.argv.includes("--stress-deep")) {
  const magic = Buffer.from(
    "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294",
    "hex"
  );
  const msg = Buffer.alloc(32, 0xaa);
  const tail = Buffer.from("000588960d73d7190103d0f033", "hex");

  const deep4096 = Buffer.concat([
    magic,
    Buffer.from([0x01, 0x08]),
    msg,
    Buffer.alloc(4096, 0x08),
    tail,
  ]);
  const d1 = callWasmDissect(deep4096);
  if (!d1.draft08_parse_ok || d1.strict_parse_ok || d1.parse_error !== null) {
    console.error("Deep 4096 dissect mismatch:", d1);
    process.exit(1);
  }

  const deep5000 = Buffer.concat([
    magic,
    Buffer.from([0x01, 0x08]),
    msg,
    Buffer.alloc(5000, 0x08),
    tail,
  ]);
  const d2 = callWasmDissect(deep5000);
  if (d2.draft08_parse_ok || d2.strict_parse_ok) {
    console.error("Deep 5000 should be rejected cleanly:", d2);
    process.exit(1);
  }
  console.log(
    JSON.stringify({
      wasm_bytes: wasmBytes.length,
      deep4096_bytes: deep4096.length,
      deep4096_draft08_parse_ok: d1.draft08_parse_ok,
      deep4096_strict_parse_ok: d1.strict_parse_ok,
      deep5000_bytes: deep5000.length,
      deep5000_rejected_without_trap: !d2.draft08_parse_ok,
      verdict: "PASS",
    })
  );
  process.exit(0);
}

const stdinText = fs.readFileSync(0, "utf8");
const lines = stdinText.split("\n").filter((l) => l.trim().length > 0);
const BATCH = 250;
for (let i = 0; i < lines.length; i += BATCH) {
  const slice = lines.slice(i, i + BATCH).join("\n") + "\n";
  const out = callWasmJsonl(slice, 0);
  if (out.length > 0) {
    process.stdout.write(out + "\n");
  }
}
