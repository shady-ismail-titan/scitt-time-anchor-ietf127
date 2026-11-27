#!/usr/bin/env node
/**
 * Single-instance WebAssembly 100,000-mutation batch evaluator + 20,000-call
 * steady-state linear-memory leak verifier for `web/scitt_time_anchor.wasm`.
 *
 * Supports both:
 *   1. Piped JSONL stdin (used by `test_100k_mutation_fuzz.py`), emitting JSONL results.
 *   2. Standalone CLI execution (`node verification_suite/wasm_100k_leak_runner.mjs`),
 *      running 100,000 batched + 20,000 single-case calls from `strict_profile_z3_witness_vectors.json`.
 */

import fs from "node:fs";
import path from "node:path";
import tty from "node:tty";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const wasmPath = process.argv[2] || path.join(ROOT, "web", "scitt_time_anchor.wasm");
const telemetryOut = process.argv[3] || path.join(__dirname, "wasm_mem_telemetry.json");

const wasmBytes = fs.readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(wasmBytes, {});
const {
  memory,
  wasm_prepare_input,
  wasm_output_ptr,
  wasm_evaluate_jsonl,
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

let stdinText = "";
if (!tty.isatty(0)) {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  stdinText = Buffer.concat(chunks).toString("utf8");
}
const stdinLines = stdinText.split("\n").filter((l) => l.trim().length > 0);
const isPiped = stdinLines.length > 0;

const memStart = memory.buffer.byteLength;
const BATCH = 250;
const extraCalls = 20000;
let batchTotalCalls = 0;
let seedLines = stdinLines;

if (isPiped) {
  for (let i = 0; i < stdinLines.length; i += BATCH) {
    const slice = stdinLines.slice(i, i + BATCH).join("\n") + "\n";
    const out = callWasmJsonl(slice, 0);
    if (out.length > 0) {
      process.stdout.write(out + "\n");
    }
  }
  batchTotalCalls = stdinLines.length;
} else {
  const witnessPath = path.join(ROOT, "spec_vectors", "strict_profile_z3_witness_vectors.json");
  const witnessDoc = JSON.parse(fs.readFileSync(witnessPath, "utf8"));
  seedLines = witnessDoc.witness_cases.map((c) => JSON.stringify(c));
  seedLines.push(
    '{"id":"N19_DUP","mode":"draft08","mode":"strict"}',
    '{"id":"N19_NAN","x":NaN}',
    '{"id":"N19_OVF","min_confirmations":9223372036854775808}'
  );

  const TARGET_BATCH_CALLS = 100000;
  for (let done = 0; done < TARGET_BATCH_CALLS; done += BATCH) {
    const count = Math.min(BATCH, TARGET_BATCH_CALLS - done);
    const chunk = [];
    for (let k = 0; k < count; k += 1) {
      chunk.push(seedLines[(done + k) % seedLines.length]);
    }
    const out = callWasmJsonl(chunk.join("\n") + "\n", 1);
    const outLines = out.split("\n").filter((l) => l.length > 0);
    if (outLines.length !== count) {
      throw new Error(`Expected ${count} JSONL lines from WASM, got ${outLines.length}`);
    }
  }
  batchTotalCalls = TARGET_BATCH_CALLS;
}

const memAfter100kBatch = memory.buffer.byteLength;

// Execute 20,000 additional single-case calls in the SAME WASM instance
for (let i = 0; i < extraCalls; i += 1) {
  const sample = seedLines[i % seedLines.length];
  callWasmJsonl(sample, 1);
}

const memAfterExtra20kSingleCalls = memory.buffer.byteLength;
const deltaAfterSteadyStateBytes = memAfterExtra20kSingleCalls - memAfter100kBatch;

const telemetry = {
  mode: isPiped ? "piped" : "standalone",
  totalCalls: batchTotalCalls + extraCalls,
  memStart,
  memAfter100kBatch,
  memAfterExtra20kSingleCalls,
  deltaAfterSteadyStateBytes,
  verdict: deltaAfterSteadyStateBytes === 0 ? "PASS" : "FAIL",
};

fs.writeFileSync(telemetryOut, JSON.stringify(telemetry, null, 2) + "\n");

if (!isPiped) {
  process.stdout.write(JSON.stringify(telemetry, null, 2) + "\n");
}
if (deltaAfterSteadyStateBytes !== 0) {
  process.exit(1);
}
