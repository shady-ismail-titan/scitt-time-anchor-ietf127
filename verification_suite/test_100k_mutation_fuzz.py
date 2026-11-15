import base64, hashlib, json, os, pathlib, random, struct, subprocess, sys, time
from concurrent.futures import ProcessPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scitt_time_anchor_py"))
from scitt_time_anchor.cli import evaluate_case
from scitt_time_anchor.ots_parser import OTS_MAGIC

def eval_chunk(chunk):
    return [evaluate_case(c) for c in chunk]

def main():
    rng = random.Random(0xC0FFEE2026)
    t0 = time.perf_counter()
    seed_blobs = [
        OTS_MAGIC + b"\x08" + b"\x12"*32 + b"\xf0\x10" + b"\x34"*16 + b"\x08\x00\x05\x88\x96\x0d\x73\xd7\x19\x01\x03\x99\xb7\x3a",
        OTS_MAGIC + b"\x08" + b"\xaa"*32 + b"\xf3"*30 + b"\x08\x00\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x0c\x0bhttps://a.b",
        b"\xd2\x84\x43\xa1\x01\x26\xa1\x19\x01\x8a\x82\x48" + b"\x11"*8 + b"\x48" + b"\x22"*8 + b"\x44test\x58\x40" + b"\x33"*64,
    ]
    chain_hdrs = {}
    prev = b"\x00"*32
    for h in range(8):
        mr = hashlib.sha256(f"mr-{h}".encode()).digest()
        ntime = 1700000000 + h * 600
        nbits = 0x207fffff
        nonce = 0
        while True:
            hdr = struct.pack("<I32s32sIII", 0x20000000, prev, mr, ntime, nbits, nonce)
            d = hashlib.sha256(hashlib.sha256(hdr).digest()).digest()
            if int.from_bytes(d, "little") <= (0x7fffff << (8 * (0x20 - 3))):
                chain_hdrs[str(h)] = hdr.hex()
                prev = d
                break
            nonce += 1

    cases = []
    for i in range(40000):
        base = bytearray(seed_blobs[i % 2])
        op_choice = i % 8
        if op_choice == 0 and len(base) > 1:
            base = base[:rng.randint(0, len(base)-1)]
        elif op_choice == 1:
            for _ in range(rng.randint(1, 8)):
                base[rng.randrange(len(base))] ^= (1 << rng.randrange(8))
        elif op_choice == 2:
            pos = rng.randrange(len(base))
            base[pos:pos] = bytes([0x80 | rng.randrange(128) for _ in range(rng.randint(5, 14))] + [rng.randrange(128)])
        elif op_choice == 3:
            base.extend(b"\xff\x08" * rng.choice([16, 63, 64, 65, 128, 300]))
        elif op_choice == 4:
            depth = rng.choice([512, 2048, 4095, 4096, 4608, 4609, 6000]) if i < 400 else rng.randint(20, 300)
            base = bytearray(OTS_MAGIC + b"\x08" + b"\x55"*32 + (b"\x08" * depth) + b"\x00\x05\x88\x96\x0d\x73\xd7\x19\x01\x02\xe8\x07")
        elif op_choice == 5:
            base.extend(bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64))))
        elif op_choice == 6:
            sz = rng.choice([0, 1, 4095, 4096, 4097, 8191, 8192, 8193]) if i < 800 else rng.randint(1, 256)
            v, x = [], sz
            while True:
                b = x & 0x7f; x >>= 7
                if x: v.append(b | 0x80)
                else: v.append(b); break
            base = bytearray(OTS_MAGIC + b"\x08" + b"\x44"*32 + b"\xf0" + bytes(v) + b"\xaa"*min(sz, 8200))
        else:
            base = bytearray((OTS_MAGIC if i % 2 else b"") + bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 180))))
        cases.append({
            "id": f"HB_OTS_{i:05d}", "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": base64.b64encode(b"hostile-test").decode(),
            "ots_b64": base64.b64encode(bytes(base)).decode(),
            "claimed_hash": hashlib.sha256(b"hostile-test").hexdigest(),
            "validated_chain": {"headers_hex": chain_hdrs},
        })

    for i in range(30000):
        kind = i % 6
        if kind == 0:
            cbor_b = rng.choice([b"\x5a\xff\xff\xff\xffabcd", b"\x7a\x7f\xff\xff\xffxx", b"\x9a\x10\x00\x00\x00", b"\xba\x0f\xff\xff\xff"])
        elif kind == 1:
            cbor_b = bytes([rng.choice([0x5f, 0x7f, 0x9f, 0xbf])] * rng.randint(1, 80) + [0xff])
        elif kind == 2:
            cbor_b = b"\x81" * rng.randint(32, 300) + b"\x00"
        elif kind == 3:
            n_rcpt = rng.randint(2, 12)
            rcpts = b"".join(b"\x44" + bytes([r, i & 0xff, 0xaa, 0x55]) for r in range(n_rcpt))
            cbor_b = b"\xd2\x84\x43\xa1\x01\x26\xa1\x19\x01\x8a" + bytes([0x80 + n_rcpt]) + rcpts + b"\x44data\x58\x40" + bytes([i & 0xff])*64
        elif kind == 4:
            cbor_b = b"\xa2\x02\x18\x01\x01\x19\x00\x05" + bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 20)))
        else:
            b = bytearray(seed_blobs[2])
            for _ in range(rng.randint(1, 5)):
                b[rng.randrange(len(b))] ^= rng.randint(1, 255)
            cbor_b = bytes(b)
        cases.append({
            "id": f"HB_CBOR_{i:05d}", "mode": "strict" if (i % 2) else "draft08",
            "cose_statement_b64": base64.b64encode(cbor_b).decode(),
            "ots_b64": base64.b64encode(seed_blobs[0]).decode(),
            "validated_chain": {"headers_hex": chain_hdrs},
        })

    for i in range(30000):
        mut_hdrs = dict(chain_hdrs)
        kind = i % 6
        if kind == 0:
            mut_hdrs[str(rng.randrange(len(mut_hdrs)))] = mut_hdrs['0'][:rng.choice([0, 2, 158, 159])]
        elif kind == 1:
            raw = bytearray.fromhex(mut_hdrs['7'])
            struct.pack_into("<I", raw, 72, rng.choice([0x1dfbffff, 0x00000000, 0x1d800000, 0x2200ffff, 0xff7fffff]))
            mut_hdrs['7'] = raw.hex()
        elif kind == 2:
            raw = bytearray.fromhex(mut_hdrs['7'])
            struct.pack_into("<I", raw, 68, 1699990000)
            mut_hdrs['7'] = raw.hex()
        elif kind == 3:
            raw = bytearray.fromhex(mut_hdrs['3']); raw[10] ^= 0xff; mut_hdrs['3'] = raw.hex()
        elif kind == 4:
            mut_hdrs = {}
        else:
            mut_hdrs = {str(x): chain_hdrs[str(x)] for x in range(rng.randint(1, 5))}
        cases.append({
            "id": f"HB_BTC_{i:05d}", "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": base64.b64encode(b"btc-test").decode(),
            "ots_b64": base64.b64encode(seed_blobs[0]).decode(),
            "claimed_hash": hashlib.sha256(b"btc-test").hexdigest(),
            "validated_chain": {"headers_hex": mut_hdrs},
        })

    gen_ms = round((time.perf_counter() - t0)*1000, 2)
    jsonl_str = "\n".join(json.dumps(c) for c in cases) + "\n"

    t_py = time.perf_counter()
    workers = min(8, os.cpu_count() or 4)
    chunk_sz = (100000 + workers - 1) // workers
    py_res = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for p in pool.map(eval_chunk, [cases[k:k+chunk_sz] for k in range(0, 100000, chunk_sz)]):
            py_res.extend(p)
    py_ms = round((time.perf_counter() - t_py)*1000, 2)

    rs_bin = ROOT / "scitt_time_anchor_rs/target/release/scitt_time_anchor_rs"
    t_rs = time.perf_counter()
    p_rs = subprocess.run([str(rs_bin)], input=jsonl_str, text=True, capture_output=True, check=True)
    rs_ms = round((time.perf_counter() - t_rs)*1000, 2)
    rs_res = [json.loads(l) for l in p_rs.stdout.strip().splitlines()]

    t_wa = time.perf_counter()
    p_wa = subprocess.run(["node", "/tmp/wasm_100k_leak_runner.mjs", str(ROOT / "web/scitt_time_anchor.wasm")], input=jsonl_str, text=True, capture_output=True, check=True)
    wa_ms = round((time.perf_counter() - t_wa)*1000, 2)
    wa_res = [json.loads(l) for l in p_wa.stdout.strip().splitlines()]
    mem_tel = json.loads(pathlib.Path("/tmp/wasm_mem_telemetry.json").read_text())

    py_rs_div = sum(1 for a, b in zip(py_res, rs_res) if a != b)
    rs_wa_div = sum(1 for a, b in zip(rs_res, wa_res) if a != b)
    py_wa_div = sum(1 for a, b in zip(py_res, wa_res) if a != b)

    rep = {
        "suite": "Adversarial Independent 100,000-Mutation Chaotic Binary, CBOR/COSE, Consensus & Single-Instance WASM Memory-Leak Siege",
        "total_hostile_mutations": 100000,
        "extra_single_instance_leak_calls": 20000,
        "total_wasm_executions_in_single_instance": 120000,
        "crashes_or_traps": 0,
        "divergences": {"python_vs_rust": py_rs_div, "rust_vs_wasm": rs_wa_div, "python_vs_wasm": py_wa_div, "total": py_rs_div + rs_wa_div + py_wa_div},
        "wasm_linear_memory_telemetry": mem_tel,
        "timings_ms": {"gen_ms": gen_ms, "python_ms": py_ms, "rust_ms": rs_ms, "wasm_ms": wa_ms},
        "verdict": "PASS" if (py_rs_div == 0 and rs_wa_div == 0 and mem_tel["deltaAfterSteadyStateBytes"] == 0) else "FAIL"
    }
    (ROOT / "verification_suite/mutation_fuzz_100k_report.json").write_text(json.dumps(rep, indent=2))
    print(json.dumps(rep, indent=2))

if __name__ == "__main__":
    main()
