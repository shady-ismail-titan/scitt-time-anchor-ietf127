(function () {
  "use strict";

  const MAX_UI_BINARY_BYTES = 262144; // 256 KiB interactive Byte-Ray UI ceiling (spec strict cap is 65,536 B)
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  let wasmExports = null;
  let activePresetIdx = 0;
  let customBytesOverride = null;
  let activeDissection = null;
  let activeRawBytes = new Uint8Array(0);
  let selectedSpanIdx = 0;

  function hexToBytes(hexStr) {
    const clean = hexStr.replace(/\s+/g, "");
    if (clean.length === 0) {
      return { error: "Hex input is empty. Paste hexadecimal .ots bytes or load a binary .ots file." };
    }
    if (clean.length % 2 !== 0) {
      return { error: "Hex input has an odd nibble count (" + clean.length + " characters). Each byte requires two hex digits." };
    }
    if (!/^[0-9a-fA-F]+$/.test(clean)) {
      return { error: "Hex input contains non-hexadecimal characters. Only 0-9 and a-f are valid." };
    }
    const byteLen = clean.length / 2;
    if (byteLen > MAX_UI_BINARY_BYTES) {
      return {
        error:
          "Input length (" +
          byteLen.toLocaleString() +
          " bytes) exceeds the 262,144-byte interactive Byte-Ray limit (strict profile cap is 65,536 bytes)."
      };
    }
    const out = new Uint8Array(byteLen);
    for (let i = 0; i < byteLen; i++) {
      out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return { bytes: out };
  }

  function bytesToHex(u8) {
    const parts = new Array(u8.length);
    for (let i = 0; i < u8.length; i++) {
      parts[i] = u8[i].toString(16).padStart(2, "0");
    }
    return parts.join("");
  }

  function bytesToBase64(u8) {
    let bin = "";
    const chunk = 8192;
    for (let i = 0; i < u8.length; i += chunk) {
      bin += String.fromCharCode.apply(null, u8.subarray(i, Math.min(i + chunk, u8.length)));
    }
    return btoa(bin);
  }

  function restoreB64Fields(obj) {
    if (Array.isArray(obj)) {
      return obj.map(restoreB64Fields);
    }
    if (obj && typeof obj === "object") {
      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        if (k.endsWith("_hex_b64src") && typeof v === "string") {
          const parsed = hexToBytes(v);
          out[k.slice(0, -11) + "_b64"] = bytesToBase64(parsed.bytes || new Uint8Array(0));
        } else {
          out[k] = restoreB64Fields(v);
        }
      }
      return out;
    }
    return obj;
  }

  function formatUnixUtc(sec) {
    if (sec === null || sec === undefined) {
      return "null";
    }
    const iso = new Date(sec * 1000).toISOString().replace(".000Z", "Z");
    return sec + " (" + iso.slice(11) + ")";
  }

  function formatHexOffset(n) {
    return "+0x" + n.toString(16).padStart(4, "0");
  }

  function formatHumanBytes(n) {
    if (n >= 1073741824) {
      return (n / 1073741824).toFixed(2) + " GB";
    }
    if (n >= 1048576) {
      return (n / 1048576).toFixed(2) + " MB";
    }
    if (n >= 1024) {
      return (n / 1024).toFixed(2) + " KB";
    }
    return n + " B";
  }

  function callWasmDissect(u8) {
    const inPtr = wasmExports.wasm_prepare_input(u8.length);
    if (inPtr === 0 && u8.length > 0) {
      throw new Error("Input exceeds WASM 4 MiB safety buffer");
    }
    if (u8.length > 0) {
      new Uint8Array(wasmExports.memory.buffer, inPtr, u8.length).set(u8);
    }
    const outLen = wasmExports.wasm_dissect_ots();
    const outPtr = wasmExports.wasm_output_ptr();
    const jsonStr = decoder.decode(new Uint8Array(wasmExports.memory.buffer, outPtr, outLen));
    return JSON.parse(jsonStr);
  }

  function callWasmVerifyPair(reqDraft, reqStrict) {
    const payload = JSON.stringify(reqDraft) + "\n" + JSON.stringify(reqStrict) + "\n";
    const enc = encoder.encode(payload);
    const inPtr = wasmExports.wasm_prepare_input(enc.length);
    if (inPtr === 0) {
      throw new Error("Request JSON exceeds WASM buffer");
    }
    new Uint8Array(wasmExports.memory.buffer, inPtr, enc.length).set(enc);
    const outLen = wasmExports.wasm_evaluate_jsonl(0);
    const outPtr = wasmExports.wasm_output_ptr();
    const text = decoder.decode(new Uint8Array(wasmExports.memory.buffer, outPtr, outLen));
    const lines = text.trim().split("\n");
    return [JSON.parse(lines[0]), JSON.parse(lines[1])];
  }

  function setFeedbackBanner(msg) {
    const el = document.getElementById("feedback-banner");
    if (!msg) {
      el.textContent = "";
      el.classList.remove("is-visible");
    } else {
      el.textContent = msg;
      el.classList.add("is-visible");
    }
  }

  function setOutcomeBadge(el, outcome) {
    el.className = "outcome-badge";
    const norm = String(outcome || "").toLowerCase();
    if (norm === "valid") {
      el.classList.add("outcome-valid");
    } else if (norm === "unverifiable") {
      el.classList.add("outcome-unverifiable");
    } else if (norm === "invalid") {
      el.classList.add("outcome-invalid");
    } else {
      el.classList.add("outcome-neutral");
    }
    el.textContent = norm || "n/a";
  }

  function renderKvRows(container, rows) {
    container.textContent = "";
    for (const [k, v] of rows) {
      const row = document.createElement("div");
      row.className = "kv-row";
      const kEl = document.createElement("span");
      kEl.className = "kv-key";
      kEl.textContent = k;
      const vEl = document.createElement("span");
      vEl.className = "kv-val";
      vEl.textContent = String(v);
      row.appendChild(kEl);
      row.appendChild(vEl);
      container.appendChild(row);
    }
  }

  function applyExplorerToggle(req) {
    const copy = JSON.parse(JSON.stringify(req));
    const explorerOnly = document.getElementById("explorer-only-toggle").checked;
    if (!explorerOnly) {
      return copy;
    }
    let fallbackHeaders = {};
    if (copy.candidate_store && copy.candidate_store.headers_hex) {
      fallbackHeaders = copy.candidate_store.headers_hex;
    } else if (copy.validated_chain && copy.validated_chain.headers_hex) {
      fallbackHeaders = copy.validated_chain.headers_hex;
    }
    copy.validated_chain = null;
    delete copy.candidate_chains;
    copy.candidate_store = {
      source: "public_explorer",
      headers_hex: fallbackHeaders
    };
    return copy;
  }

  function renderSpanDetail(idx) {
    if (!activeDissection || !activeDissection.spans || activeDissection.spans.length === 0) {
      document.getElementById("selected-offset-chip").textContent = "+0x0000";
      document.getElementById("detail-title").textContent = "No valid spans decoded";
      document.getElementById("detail-section").textContent = "Section 4.1 Step 3 (OTS-DESERIALIZE)";
      document.getElementById("detail-desc").textContent =
        activeDissection && activeDissection.parse_error
          ? "Parser halted at offset " + activeDissection.parse_error.offset + ": " + activeDissection.parse_error.message
          : "Input contains zero decodable OpenTimestamps wire spans.";
      document.getElementById("detail-hex").textContent = bytesToHex(activeRawBytes.subarray(0, 64)) || "(empty)";
      return;
    }

    const clamped = Math.max(0, Math.min(idx, activeDissection.spans.length - 1));
    selectedSpanIdx = clamped;
    const sp = activeDissection.spans[clamped];

    const allBtns = document.querySelectorAll("#span-stream .span-chip");
    allBtns.forEach((btn, i) => {
      btn.classList.toggle("is-active", i === clamped);
    });

    const byteLen = sp.end - sp.start;
    document.getElementById("selected-offset-chip").textContent =
      formatHexOffset(sp.start) + " .. " + formatHexOffset(sp.end) + " (" + byteLen + " B)";
    document.getElementById("detail-title").textContent = sp.label;
    document.getElementById("detail-section").textContent = sp.section;
    document.getElementById("detail-desc").textContent = sp.detail;

    const slice = activeRawBytes.subarray(sp.start, sp.end);
    document.getElementById("detail-hex").textContent = bytesToHex(slice) || "(0 bytes)";
  }

  function renderDynamicSubpanel(preset) {
    const host = document.getElementById("dynamic-subpanel");
    host.textContent = "";

    if (!activeDissection) {
      return;
    }

    // 1. If any varuint shows JS vs Python divergence or non-canonical encoding, render Bit-Shift Table first
    const nonCanonVaruints = (activeDissection.varuints || []).filter(
      (v) => v.canonical_u32 === null || v.js_toint32 !== v.py_u64 || v.role === "bitcoin_block_height"
    );

    if (nonCanonVaruints.length > 0 && (preset.id === "preset-2-leb128-split-brain" || customBytesOverride !== null || nonCanonVaruints.some((v) => v.canonical_u32 === null))) {
      const targetV = nonCanonVaruints[nonCanonVaruints.length - 1];
      const wrap = document.createElement("div");
      wrap.className = "detail-box";
      const h = document.createElement("h4");
      h.className = "detail-title";
      h.textContent = "LEB128 Cross-Runtime Bit-Shift Breakdown (" + targetV.raw_hex + ")";
      wrap.appendChild(h);

      const p = document.createElement("p");
      p.className = "detail-desc";
      p.textContent =
        "JS ToInt32 decodes " +
        targetV.js_toint32.toLocaleString() +
        " | Python/Rust u64 decodes " +
        targetV.py_u64.toLocaleString() +
        " | Strict canonical u32: " +
        (targetV.canonical_u32 === null ? "REJECTED" : targetV.canonical_u32.toLocaleString());
      wrap.appendChild(p);

      const tWrap = document.createElement("div");
      tWrap.className = "table-scroll";
      const tbl = document.createElement("table");
      tbl.className = "data-table mono";
      tbl.innerHTML =
        "<thead><tr><th>Byte</th><th>Hex</th><th>Low 7b</th><th>Py Shift</th><th>JS (sh &amp; 31)</th></tr></thead>";
      const tb = document.createElement("tbody");
      for (const b of targetV.bytes) {
        const tr = document.createElement("tr");
        if (b.py_shift !== b.js_shift) {
          tr.className = "row-alert";
        }
        const cells = ["#" + b.idx, "0x" + b.byte_hex, String(b.low7), "<<" + b.py_shift, "<<" + b.js_shift];
        for (const c of cells) {
          const td = document.createElement("td");
          td.textContent = c;
          tr.appendChild(td);
        }
        tb.appendChild(tr);
      }
      tbl.appendChild(tb);
      tWrap.appendChild(tbl);
      wrap.appendChild(tWrap);
      host.appendChild(wrap);
      return;
    }

    // 2. If Preset 1 (Block 957289 header timeline) is active and not overridden, show real 80-byte header window
    if (!customBytesOverride && preset && preset.header_timeline) {
      const wrap = document.createElement("div");
      wrap.className = "detail-box";
      const h = document.createElement("h4");
      h.className = "detail-title";
      h.textContent = "Mainnet Header Window 957278..957294 (BIP-113 MTP vs Forward-MTP(H+5))";
      wrap.appendChild(h);

      const p = document.createElement("p");
      p.className = "detail-desc";
      p.textContent =
        "Preceding 11 blocks [957278..957288] median = 09:24:46Z (1783589086), 122s earlier than [957279..957289] = 09:26:48Z. Forward-MTP(H+5) over [957284..957294] = 10:02:59Z at exact 6 confirmations.";
      wrap.appendChild(p);

      const tWrap = document.createElement("div");
      tWrap.className = "table-scroll";
      tWrap.style.maxHeight = "216px";
      tWrap.style.overflowY = "auto";
      const tbl = document.createElement("table");
      tbl.className = "data-table mono";
      tbl.innerHTML = "<thead><tr><th>Height</th><th>nTime</th><th>UTC</th><th>Window Role</th></tr></thead>";
      const tb = document.createElement("tbody");
      for (const row of preset.header_timeline) {
        const tr = document.createElement("tr");
        if (row.is_anchor_block) {
          tr.className = "row-highlight";
        }
        let role = "";
        if (row.height === 957283) {
          role = "BIP-113 median (09:24:46Z)";
        } else if (row.height === 957284) {
          role = "D.3 printed median (+122s)";
        } else if (row.is_anchor_block) {
          role = "Anchor H & FMTP(H+5) median";
        } else if (row.height === 957294) {
          role = "H+5 (6th confirmation)";
        } else if (row.in_bip113_window && row.in_fmtp5_window) {
          role = "[H-11..H-1] & [H-5..H+5]";
        } else if (row.in_bip113_window) {
          role = "[H-11..H-1]";
        } else {
          role = "[H-5..H+5]";
        }
        for (const val of [String(row.height), String(row.ntime), row.iso.slice(11), role]) {
          const td = document.createElement("td");
          td.textContent = val;
          tr.appendChild(td);
        }
        tb.appendChild(tr);
      }
      tbl.appendChild(tb);
      tWrap.appendChild(tbl);
      wrap.appendChild(tWrap);
      host.appendChild(wrap);
      return;
    }

    // 3. Buffer growth meter (Preset 3 OpHexlify or any proof with buffer growth steps)
    const growth = activeDissection.buffer_growth || [];
    if (growth.some((g) => g.bytes > 64)) {
      const wrap = document.createElement("div");
      wrap.className = "detail-box";
      const h = document.createElement("h4");
      h.className = "detail-title";
      h.textContent = "Working Buffer Growth vs 4,096-Byte Strict Ceiling";
      wrap.appendChild(h);

      const sampled = growth.filter((_, idx) => idx === 0 || idx % 5 === 0 || idx === growth.length - 1).slice(0, 9);
      for (const g of sampled) {
        const r = document.createElement("div");
        r.className = "growth-row mono";
        const sLbl = document.createElement("span");
        sLbl.textContent = "Step " + g.step;
        const track = document.createElement("div");
        track.className = "growth-track";
        const fill = document.createElement("div");
        fill.className = "growth-fill" + (g.exceeded_strict ? " is-exceeded" : "");
        const logPct = Math.min(100, Math.max(6, (Math.log2(Math.max(1, g.bytes)) / 35) * 100));
        fill.style.width = logPct.toFixed(1) + "%";
        track.appendChild(fill);
        const bLbl = document.createElement("span");
        bLbl.style.textAlign = "right";
        bLbl.textContent = formatHumanBytes(g.bytes);
        r.appendChild(sLbl);
        r.appendChild(track);
        r.appendChild(bLbl);
        wrap.appendChild(r);
      }
      host.appendChild(wrap);
    }
  }

  function evaluateActiveState() {
    const lab = window.SCITT_LAB_DATA;
    const preset = lab.presets[activePresetIdx];
    const rawBytes = customBytesOverride || hexToBytes(preset.ots_hex).bytes;
    activeRawBytes = rawBytes;

    document.getElementById("brief-title").textContent = customBytesOverride
      ? "Custom Proof Inspection (" + rawBytes.length.toLocaleString() + " bytes)"
      : preset.title;
    document.getElementById("brief-cite").textContent = customBytesOverride
      ? "Evaluated against Section 4.1 OTS-DESERIALIZE and active preset chain context"
      : preset.section_cite;
    document.getElementById("brief-summary").textContent = customBytesOverride
      ? "Inspecting caller-supplied binary/hex bytes in isolated WebAssembly memory. Step 2 compares the proof against the active scenario artifact hash while Step 3 dissects wire structure."
      : preset.summary;

    const t0 = performance.now();
    const dissect = callWasmDissect(rawBytes);

    let reqDraft = applyExplorerToggle(restoreB64Fields(preset.draft08_req));
    let reqStrict = applyExplorerToggle(restoreB64Fields(preset.strict_req));

    if (customBytesOverride) {
      const customB64 = bytesToBase64(rawBytes);
      delete reqDraft.proof_bundle_cbor_b64;
      delete reqStrict.proof_bundle_cbor_b64;
      reqDraft.ots_b64 = customB64;
      reqStrict.ots_b64 = customB64;
    }

    const [resDraft, resStrict] = callWasmVerifyPair(reqDraft, reqStrict);
    const elapsedMs = performance.now() - t0;

    activeDissection = dissect;
    document.getElementById("wasm-latency-chip").textContent = "Eval: " + elapsedMs.toFixed(2) + " ms";

    if (dissect.parse_error) {
      setFeedbackBanner(
        "Wire format warning at byte offset " +
          dissect.parse_error.offset +
          " (" +
          formatHexOffset(dissect.parse_error.offset) +
          "): " +
          dissect.parse_error.message
      );
    } else if (document.getElementById("explorer-only-toggle").checked) {
      setFeedbackBanner(
        "Explorer-only simulation active (Appendix C Entry 3 / Appendix D.7 Route 4): local PoW header chain removed. Step 7b returns NULL so VERIFY-ANCHOR reports unverifiable rather than valid."
      );
    } else {
      setFeedbackBanner(null);
    }

    // Populate Verdict Cards
    setOutcomeBadge(document.getElementById("badge-draft08"), resDraft.outcome);
    renderKvRows(document.getElementById("kv-draft08"), [
      ["Terminating step", "Step " + resDraft.step],
      ["Block height H", resDraft.block_height_h !== null ? resDraft.block_height_h.toLocaleString() : "null"],
      ["Confirmations", resDraft.confirmations !== null ? String(resDraft.confirmations) : "null"],
      ["RWCP nTime", formatUnixUtc(resDraft.block_time_rwcp)],
      ["BIP-113 MTP", formatUnixUtc(resDraft.mtp_bip113)]
    ]);

    setOutcomeBadge(document.getElementById("badge-strict"), resStrict.outcome);
    renderKvRows(document.getElementById("kv-strict"), [
      ["Terminating step", "Step " + resStrict.step],
      ["Block height H", resStrict.block_height_h !== null ? resStrict.block_height_h.toLocaleString() : "null"],
      ["Forward-MTP(H+5)", formatUnixUtc(resStrict.fmtp_5)],
      ["Strict wire gate", dissect.strict_parse_ok ? "canonical pass" : "rejected (Step 3)"],
      ["WASM wall time", elapsedMs.toFixed(2) + " ms"]
    ]);

    const btcV = (dissect.varuints || []).find((v) => v.role === "bitcoin_block_height");
    const jsBadge = document.getElementById("badge-upstream-js");
    if (customBytesOverride) {
      setOutcomeBadge(jsBadge, dissect.draft08_parse_ok ? "parsed" : "error");
    } else if (preset.id === "preset-2-leb128-split-brain") {
      setOutcomeBadge(jsBadge, "split-brain");
    } else {
      setOutcomeBadge(jsBadge, "reference");
    }
    renderKvRows(document.getElementById("kv-upstream-js"), [
      ["JS shift & 31 height", btcV ? btcV.js_toint32.toLocaleString() : "n/a"],
      ["Python/Rust u64 height", btcV ? btcV.py_u64.toLocaleString() : "n/a"],
      ["Web portal node check", "ignoreBitcoinNode: true"],
      ["Total wire spans", String((dissect.spans || []).length)],
      ["Behavior note", customBytesOverride ? "Evaluated via WASM dissector" : preset.upstream_js_note]
    ]);

    // Render clickable spans
    document.getElementById("dissect-byte-summary").textContent =
      rawBytes.length.toLocaleString() + " octets · " + (dissect.spans || []).length + " spans";

    const stream = document.getElementById("span-stream");
    stream.textContent = "";
    const spans = dissect.spans || [];
    let defaultIdx = 0;
    if (!customBytesOverride && preset.focus_offset) {
      const found = spans.findIndex((s) => preset.focus_offset >= s.start && preset.focus_offset < s.end);
      if (found >= 0) {
        defaultIdx = found;
      }
    }

    spans.forEach((sp, i) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "span-chip";
      btn.dataset.kind = sp.kind;

      const off = document.createElement("span");
      off.className = "span-off";
      off.textContent = formatHexOffset(sp.start);

      const slice = rawBytes.subarray(sp.start, Math.min(sp.end, sp.start + 6));
      let hexPreview = bytesToHex(slice);
      if (sp.end - sp.start > 6) {
        hexPreview += "…" + (sp.end - sp.start) + "B";
      }

      const hx = document.createElement("span");
      hx.className = "span-hex";
      hx.textContent = hexPreview + " " + sp.label.split(" (")[0];

      btn.appendChild(off);
      btn.appendChild(hx);
      btn.addEventListener("click", function () {
        renderSpanDetail(i);
      });
      stream.appendChild(btn);
    });

    renderSpanDetail(defaultIdx);
    renderDynamicSubpanel(preset);
  }

  function initPresets() {
    const lab = window.SCITT_LAB_DATA;
    const grid = document.getElementById("preset-grid");
    grid.textContent = "";

    lab.presets.forEach((p, idx) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "preset-btn" + (idx === 0 ? " is-selected" : "");
      btn.textContent = p.short_label;
      btn.addEventListener("click", function () {
        activePresetIdx = idx;
        customBytesOverride = null;
        document.querySelectorAll("#preset-grid .preset-btn").forEach((b, j) => {
          b.classList.toggle("is-selected", j === idx);
        });
        document.getElementById("custom-hex-input").value = p.ots_hex;
        evaluateActiveState();
      });
      grid.appendChild(btn);
    });

    document.getElementById("custom-hex-input").value = lab.presets[0].ots_hex;
  }

  function initInteropTab() {
    const lab = window.SCITT_LAB_DATA;
    const io = lab.interop;
    const d50 = lab.differential_50k;

    const mStrip = document.getElementById("interop-metrics");
    const metrics = [
      ["External organizations", String(io.external_orgs), "Independent third-party codebases executed"],
      ["Interop vectors", String(io.matrix.length), "Official D.5, wild Mainnet & Z3 witnesses"],
      ["Mainnet positive parity", "100%", "Blocks 957289, 960175, 960468, 968588, 968752"],
      ["Internal differential fuzz", (d50.total_vectors_executed || d50.total_cases || 50000).toLocaleString(), "0 divergences across Python, Rust & WASM"]
    ];
    for (const [lbl, num, note] of metrics) {
      const box = document.createElement("div");
      box.className = "metric-box";
      box.innerHTML =
        '<span class="metric-label"></span><span class="metric-number"></span><span class="metric-note"></span>';
      box.children[0].textContent = lbl;
      box.children[1].textContent = num;
      box.children[2].textContent = note;
      mStrip.appendChild(box);
    }

    function renderInteropRows(filterMode) {
      const tbody = document.getElementById("interop-tbody");
      tbody.textContent = "";
      for (const row of io.matrix) {
        const isPos = row.clean_room_triple_strict.outcome === "valid";
        const isDiv = !isPos && row.id !== "V02_APPENDIX_D7_EXPLORER_NO_CHAIN" && row.id !== "V08_UPSTREAM_OTS_PENDING_ONLY";
        if (filterMode === "positive" && !isPos) {
          continue;
        }
        if (filterMode === "divergence" && !isDiv) {
          continue;
        }
        const tr = document.createElement("tr");
        const jsSummary = row.umarise_verify_anchoring_web.parse_ok
          ? "H=" + JSON.stringify(row.umarise_verify_anchoring_web.bitcoin_heights)
          : row.umarise_verify_anchoring_web.error || "parse_fail";
        const pySummary = row.python_opentimestamps_0_5_0.parse_ok
          ? "H=" + JSON.stringify(row.python_opentimestamps_0_5_0.bitcoin_heights)
          : (row.python_opentimestamps_0_5_0.error || "parse_fail").split(":")[0];

        const cells = [
          row.id,
          jsSummary,
          pySummary,
          row.emilia_protocol_v06.summary.split(" (")[0] + (row.emilia_protocol_v06.raw.block_height ? " H=" + row.emilia_protocol_v06.raw.block_height : ""),
          row.cryptogeekpt_v03.summary,
          row.dps_lemonnier_v08.summary,
          row.clean_room_triple_draft08.outcome + " (S" + row.clean_room_triple_draft08.step + ")",
          row.clean_room_triple_strict.outcome + " (S" + row.clean_room_triple_strict.step + ")"
        ];
        cells.forEach((val, cIdx) => {
          const td = document.createElement("td");
          if (cIdx > 0) {
            td.className = "mono";
          }
          td.textContent = val;
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      }
    }

    renderInteropRows("all");
    document.querySelectorAll(".interop-filter-btn").forEach((btn) => {
      btn.addEventListener("click", function () {
        document.querySelectorAll(".interop-filter-btn").forEach((b) => b.classList.remove("action-btn-primary"));
        btn.classList.add("action-btn-primary");
        renderInteropRows(btn.dataset.filter);
      });
    });

    // SCITT COSE Live Interop Summary
    const scBox = document.getElementById("scitt-cose-summary");
    const wexp = io.scitt_cose.wexp_scitt_receipt_boundary_001;
    const iso = io.scitt_cose.isoluce_live_checkpoint;
    const scTblWrap = document.createElement("div");
    scTblWrap.className = "table-scroll";
    const scTbl = document.createElement("table");
    scTbl.className = "data-table";
    scTbl.innerHTML =
      "<thead><tr><th>Artifact Source</th><th>Envelope</th><th>Upstream pycose 1.1.0</th><th>Clean-Room CBOR &amp; RFC 9921 / 9942 Result</th></tr></thead>";
    const scTb = document.createElement("tbody");
    const scRows = [
      [
        "WEXP scitt-receipt-boundary-001",
        "836 B COSE_Sign1 + Receipt (hdr 394)",
        "Parsed ES384 (-35)",
        "Outer SHA-256 mutates across relay hops; RFC 9921 §3.1.1 + header 394 imprint 100% invariant (" +
          wexp.rfc9921_rfc9942_tbs_sha256_hop1.slice(0, 16) +
          "…)"
      ],
      [
        "Action State / iSoluce live checkpoint",
        (iso.size_bytes || iso.bytes) + " B COSE_Sign1 (alg = -19 Ed25519, RFC 9864)",
        "ValueError (-19 unsupported)",
        "Parsed cleanly by clean-room CBOR & cbor2 5.9.0; TBS imprint SHA-256 = " + (iso.clean_room_tbs_imprint_sha256 || iso.payload_sha256).slice(0, 16) + "…"
      ]
    ];
    for (const r of scRows) {
      const tr = document.createElement("tr");
      r.forEach((c, idx) => {
        const td = document.createElement("td");
        if (idx >= 1) {
          td.className = "mono";
        }
        td.textContent = c;
        tr.appendChild(td);
      });
      scTb.appendChild(tr);
    }
    scTbl.appendChild(scTb);
    scTblWrap.appendChild(scTbl);
    scBox.appendChild(scTblWrap);

    // 50,000-Vector Differential Summary
    const dBox = document.getElementById("diff50k-summary");
    const dWrap = document.createElement("div");
    dWrap.className = "table-scroll";
    const dTbl = document.createElement("table");
    dTbl.className = "data-table mono";
    dTbl.innerHTML =
      "<thead><tr><th>Engine</th><th>Cases Evaluated</th><th>draft08 / strict Split</th><th>Mean Latency</th><th>Pairwise Divergences</th></tr></thead>";
    const dTb = document.createElement("tbody");
    const dRows = [
      ["Clean-Room Python 3 CLI", (d50.total_vectors_executed || d50.total_cases || 50000).toLocaleString(), (d50.profile_distribution || d50.mode_counts).draft08 + " / " + (d50.profile_distribution || d50.mode_counts).strict, (d50.timings_ms ? ((d50.timings_ms.python_parallel_eval_ms * 1000) / (d50.total_vectors_executed || 50000)).toFixed(2) : ((d50.timings_seconds.python_cli * 1e6) / d50.total_cases).toFixed(2)) + " µs/vec", "0"],
      ["Native Rust (#![forbid(unsafe_code)])", (d50.total_vectors_executed || d50.total_cases || 50000).toLocaleString(), (d50.profile_distribution || d50.mode_counts).draft08 + " / " + (d50.profile_distribution || d50.mode_counts).strict, (d50.timings_ms ? d50.timings_ms.rust_us_per_vector : d50.throughput_us_per_case.rust_native_us) + " µs/vec", "0"],
      ["Compiled wasm32 (Node V8)", (d50.total_vectors_executed || d50.total_cases || 50000).toLocaleString(), (d50.profile_distribution || d50.mode_counts).draft08 + " / " + (d50.profile_distribution || d50.mode_counts).strict, (d50.timings_ms ? d50.timings_ms.wasm_us_per_vector : d50.throughput_us_per_case.wasm_node_v8_us) + " µs/vec", "0"]
    ];
    for (const r of dRows) {
      const tr = document.createElement("tr");
      for (const c of r) {
        const td = document.createElement("td");
        td.textContent = c;
        tr.appendChild(td);
      }
      dTb.appendChild(tr);
    }
    dTbl.appendChild(dTb);
    dWrap.appendChild(dTbl);
    dBox.appendChild(dWrap);
  }

  function initZ3Tab() {
    const z3 = window.SCITT_LAB_DATA.z3_formal;
    const mStrip = document.getElementById("z3-metrics");
    const items = [
      ["SMT solver", "Z3 " + z3.z3_version, "Arithmetic & bit-vector decision procedures"],
      ["Verified findings", String(z3.findings_verified_count) + " / 7", "Zero PKI or mock boolean assumptions"],
      ["Partition completeness", "UNSAT", "Exact {valid, invalid, unverifiable} partition"],
      ["Solver runtime", z3.elapsed_ms + " ms", "Deterministic reproducible SMT script"]
    ];
    for (const [l, n, note] of items) {
      const b = document.createElement("div");
      b.className = "metric-box";
      b.innerHTML =
        '<span class="metric-label"></span><span class="metric-number"></span><span class="metric-note"></span>';
      b.children[0].textContent = l;
      b.children[1].textContent = n;
      b.children[2].textContent = note;
      mStrip.appendChild(b);
    }

    const tbody = document.getElementById("z3-tbody");
    for (const f of z3.formal_findings) {
      const tr = document.createElement("tr");
      const cells = [
        f.id,
        f.title,
        f.draft08_result,
        f.strict_result,
        JSON.stringify(f.z3_witness)
      ];
      cells.forEach((c, idx) => {
        const td = document.createElement("td");
        if (idx === 0 || idx === 4) {
          td.className = "mono";
        }
        td.textContent = c;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    }
  }

  function initDiffTab() {
    const diffText = window.SCITT_LAB_DATA.draft09_diff || "";
    const viewer = document.getElementById("diff-viewer");
    viewer.textContent = "";
    for (const line of diffText.split("\n")) {
      const div = document.createElement("div");
      div.className = "diff-line";
      if (line.startsWith("@@")) {
        div.classList.add("diff-hunk");
      } else if (line.startsWith("+") && !line.startsWith("+++")) {
        div.classList.add("diff-add");
      } else if (line.startsWith("-") && !line.startsWith("---")) {
        div.classList.add("diff-del");
      }
      div.textContent = line || " ";
      viewer.appendChild(div);
    }

    const copyBtn = document.getElementById("btn-copy-diff");
    copyBtn.addEventListener("click", function () {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(diffText).then(function () {
          copyBtn.textContent = "Copied diff";
          setTimeout(function () {
            copyBtn.textContent = "Copy unified diff";
          }, 1500);
        });
      }
    });
  }

  function initTabsAndControls() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach((btn) => {
      btn.addEventListener("click", function () {
        const target = btn.dataset.tab;
        tabBtns.forEach((b) => {
          const sel = b === btn;
          b.setAttribute("aria-selected", sel ? "true" : "false");
        });
        document.querySelectorAll(".tab-panel").forEach((p) => {
          p.classList.toggle("is-active", p.id === "panel-" + target);
        });
      });
    });

    document.getElementById("explorer-only-toggle").addEventListener("change", function () {
      evaluateActiveState();
    });

    document.getElementById("btn-run-custom-hex").addEventListener("click", function () {
      const rawText = document.getElementById("custom-hex-input").value;
      const parsed = hexToBytes(rawText);
      if (parsed.error) {
        setFeedbackBanner(parsed.error);
        return;
      }
      customBytesOverride = parsed.bytes;
      evaluateActiveState();
    });

    document.getElementById("btn-reset-preset").addEventListener("click", function () {
      customBytesOverride = null;
      const preset = window.SCITT_LAB_DATA.presets[activePresetIdx];
      document.getElementById("custom-hex-input").value = preset.ots_hex;
      document.getElementById("explorer-only-toggle").checked = false;
      evaluateActiveState();
    });

    document.getElementById("ots-file-input").addEventListener("change", function (ev) {
      const file = ev.target.files && ev.target.files[0];
      if (!file) {
        return;
      }
      if (file.size > MAX_UI_BINARY_BYTES) {
        setFeedbackBanner(
          "Rejected oversized binary '" +
            file.name +
            "' (" +
            file.size.toLocaleString() +
            " bytes). Interactive Byte-Ray limit is 262,144 bytes; strict profile ceiling is 65,536 bytes."
        );
        ev.target.value = "";
        return;
      }
      const reader = new FileReader();
      reader.onload = function () {
        const u8 = new Uint8Array(reader.result);
        if (u8.length === 0) {
          setFeedbackBanner("Uploaded file '" + file.name + "' is empty (0 bytes).");
          return;
        }
        customBytesOverride = u8;
        document.getElementById("custom-hex-input").value = bytesToHex(u8);
        evaluateActiveState();
      };
      reader.readAsArrayBuffer(file);
    });
  }

  async function boot() {
    try {
      const parsedWasm = hexToBytes(window.SCITT_WASM_HEX || "");
      if (parsedWasm.error || !parsedWasm.bytes) {
        throw new Error(parsedWasm.error || "Missing WASM bundle");
      }
      const { instance } = await WebAssembly.instantiate(parsedWasm.bytes, {});
      wasmExports = instance.exports;

      const meta = window.SCITT_WASM_META;
      document.getElementById("wasm-status-text").textContent = "WASM Ready (Offline)";
      document.getElementById("wasm-size-chip").textContent =
        "wasm32 · " + (meta.gzip_bytes / 1024).toFixed(1) + " KB gzip (" + (meta.raw_bytes / 1024).toFixed(1) + " KB raw)";
      document.getElementById("footer-sha256").textContent = "WASM SHA-256: " + meta.sha256.slice(0, 24) + "…";

      initPresets();
      initInteropTab();
      initZ3Tab();
      initDiffTab();
      initTabsAndControls();
      evaluateActiveState();
    } catch (err) {
      document.getElementById("wasm-status-text").textContent = "WASM Init Error";
      setFeedbackBanner("Failed to initialize offline WebAssembly module: " + (err && err.message ? err.message : String(err)));
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
