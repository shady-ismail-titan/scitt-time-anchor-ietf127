(function () {
  "use strict";

  const MAX_UI_BINARY_BYTES = 262144;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  let wasmExports = null;
  let wasmUnavailableReason = null;
  let activePresetIdx = 0;
  let activeMode = "strict";
  let customBytesOverride = null;
  let activeDissection = null;
  let activeRawBytes = new Uint8Array(0);

  function markNoTranslate(el) {
    el.setAttribute("translate", "no");
    el.classList.add("notranslate");
    return el;
  }

  function createCodeEl(cmd) {
    const code = document.createElement("code");
    code.className = "mono";
    markNoTranslate(code);
    code.textContent = cmd;
    return code;
  }

  function hexToBytes(hexStr) {
    const clean = hexStr.replace(/\s+/g, "");
    if (clean.length === 0) {
      return { error: "Hex input is empty. Paste hexadecimal .ots bytes or load a binary .ots file." };
    }
    if (clean.length % 2 !== 0) {
      return { error: "Hex input has an odd nibble count (" + clean.length + " characters)." };
    }
    if (!/^[0-9a-fA-F]+$/.test(clean)) {
      return { error: "Hex input contains non-hexadecimal characters. Only 0-9 and a-f are valid." };
    }
    const byteLen = clean.length / 2;
    if (byteLen > MAX_UI_BINARY_BYTES) {
      return {
        error: "Input length (" + byteLen.toLocaleString() + " bytes) exceeds the 262,144-byte interactive Byte-Ray limit."
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

  function buildTableHead(headers) {
    const thead = document.createElement("thead");
    const tr = document.createElement("tr");
    for (const h of headers) {
      const th = document.createElement("th");
      th.textContent = h;
      tr.appendChild(th);
    }
    thead.appendChild(tr);
    return thead;
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

  function callWasmEvalJsonlLines(lines, defaultModeId) {
    const payload = lines.join("\n") + "\n";
    const enc = encoder.encode(payload);
    const inPtr = wasmExports.wasm_prepare_input(enc.length);
    if (inPtr === 0) {
      throw new Error("Request JSON exceeds WASM buffer");
    }
    new Uint8Array(wasmExports.memory.buffer, inPtr, enc.length).set(enc);
    const outLen = wasmExports.wasm_evaluate_jsonl(defaultModeId);
    const outPtr = wasmExports.wasm_output_ptr();
    const text = decoder.decode(new Uint8Array(wasmExports.memory.buffer, outPtr, outLen));
    return text.trim().split("\n").map((l) => JSON.parse(l));
  }

  function setFeedbackBanner(content, isCalmNotice) {
    const el = document.getElementById("feedback-banner");
    el.textContent = "";
    el.classList.remove("outcome-unverifiable", "is-visible");
    if (!content) {
      return;
    }
    if (isCalmNotice) {
      el.classList.add("outcome-unverifiable");
    }
    if (Array.isArray(content)) {
      for (const item of content) {
        if (typeof item === "string") {
          el.appendChild(document.createTextNode(item));
        } else if (item) {
          el.appendChild(item);
        }
      }
    } else {
      el.textContent = String(content);
    }
    el.classList.add("is-visible");
  }

  function setOutcomeBadge(el, outcome, labelOverride) {
    el.className = "outcome-badge notranslate" + (el.classList.contains("outcome-badge-lg") ? " outcome-badge-lg" : "");
    el.setAttribute("translate", "no");
    const norm = String(outcome || "").toLowerCase();
    if (norm === "valid") {
      el.classList.add("outcome-valid");
    } else if (norm === "unverifiable") {
      el.classList.add("outcome-unverifiable");
    } else if (norm === "invalid" || norm === "bad_json") {
      el.classList.add("outcome-invalid");
    } else {
      el.classList.add("outcome-neutral");
    }
    el.textContent = labelOverride || norm || "n/a";
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
      markNoTranslate(vEl);
      if (v instanceof Node) {
        vEl.appendChild(v);
      } else {
        vEl.textContent = String(v);
      }
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

  function buildStepTrace(res, dissect, preset) {
    const stages = [
      { id: "S0", label: "JSONL / CBOR / COSE envelope gate" },
      { id: "S1–S2", label: "Artifact SHA-256 == claimed_hash" },
      { id: "S3", label: "OTS wire format & opcode whitelist" },
      { id: "S4–S5", label: "Branch Bitcoin attestation & replay" },
      { id: "S6–S7", label: "PoW, 0x1d00ffff/0x181fffff & 4x retarget" },
      { id: "S8–S9", label: "Merkle match & k >= 6 confirmations" },
      { id: "S10–S11", label: "RWCP, BIP-113 MTP & Forward-MTP(H+5)" }
    ];

    if (res.error) {
      return stages.map((st, idx) => ({
        ...st,
        status: idx === 0 ? "FAIL" : "SKIP",
        cls: idx === 0 ? "is-fail" : "is-skip"
      }));
    }

    const step = Number(res.step);
    let failIdx = -1;
    let warnInstead = false;
    if (step === 0) {
      failIdx = 0;
    } else if (step <= 2) {
      failIdx = 1;
    } else if (step === 3) {
      failIdx = 2;
    } else if (step === 4) {
      failIdx = 3;
      warnInstead = true;
    } else if (step === 8) {
      const hasMismatched = Number(res.mismatched_branches || 0) > 0;
      failIdx = hasMismatched ? 5 : 4;
      warnInstead = res.outcome === "unverifiable";
    } else if (step === 9) {
      failIdx = 5;
      warnInstead = true;
    }

    return stages.map((st, idx) => {
      if (res.outcome === "valid") {
        return { ...st, status: "PASS", cls: "is-pass" };
      }
      if (idx < failIdx) {
        return { ...st, status: "PASS", cls: "is-pass" };
      }
      if (idx === failIdx) {
        return {
          ...st,
          status: warnInstead ? "UNVERIF" : "FAIL",
          cls: warnInstead ? "is-warn" : "is-fail"
        };
      }
      return { ...st, status: "SKIP", cls: "is-skip" };
    });
  }

  function renderActiveVerdictBanner(preset, resActive, dissect, elapsedMs) {
    const banner = document.getElementById("active-verdict-banner");
    banner.classList.remove("is-valid", "is-invalid", "is-unverifiable");

    const modeLabel = activeMode === "strict" ? "strict (v2.0)" : "draft08";
    document.getElementById("avb-mode-pill").textContent = "Active Profile: " + modeLabel;

    const badge = document.getElementById("active-verdict-badge");
    const stepLabel = document.getElementById("active-verdict-step");

    if (resActive.error) {
      banner.classList.add("is-invalid");
      setOutcomeBadge(badge, "bad_json", "REJECTED: " + resActive.error);
      stepLabel.textContent = "Pre-Step 0 (RFC 8259 JSONL Gate)";
    } else if (resActive.outcome === "valid") {
      banner.classList.add("is-valid");
      setOutcomeBadge(badge, "valid", "PASS · VALID");
      stepLabel.textContent = "Terminated at Step " + resActive.step;
    } else if (resActive.outcome === "invalid") {
      banner.classList.add("is-invalid");
      setOutcomeBadge(badge, "invalid", "REJECTED · INVALID");
      stepLabel.textContent = "Rejected at Step " + resActive.step;
    } else {
      banner.classList.add("is-unverifiable");
      setOutcomeBadge(badge, "unverifiable", "REJECTED · UNVERIFIABLE");
      stepLabel.textContent = "Halted at Step " + resActive.step;
    }

    const traceList = document.getElementById("step-trace-list");
    traceList.textContent = "";
    for (const item of buildStepTrace(resActive, dissect, preset)) {
      const li = document.createElement("li");
      li.className = "step-trace-item";
      const sSpan = document.createElement("span");
      sSpan.className = "trace-stage";
      markNoTranslate(sSpan);
      sSpan.textContent = item.id;
      const lSpan = document.createElement("span");
      lSpan.className = "trace-label";
      lSpan.textContent = item.label;
      const pSpan = document.createElement("span");
      pSpan.className = "trace-pill " + item.cls;
      markNoTranslate(pSpan);
      pSpan.textContent = item.status;
      li.appendChild(sSpan);
      li.appendChild(lSpan);
      li.appendChild(pSpan);
      traceList.appendChild(li);
    }

    const cmeta = (!customBytesOverride && preset.consensus_meta) ? preset.consensus_meta : {};
    renderKvRows(document.getElementById("consensus-telemetry-kv"), [
      ["Verdict / Profile", (resActive.error ? "error:" + resActive.error : resActive.outcome) + " (" + modeLabel + ")"],
      ["Verification Scope", (resActive.verification_scope || "temporal_anchor_only") + " (COSE sig verified: " + String(Boolean(resActive.cose_signature_verified)) + ")"],
      ["Header Chain", cmeta.chain_label || "Preset header slice"],
      ["Target nBits", cmeta.nbits_hex || "per chain headers"],
      ["Mainnet Ceilings", "0x1d00ffff (powLimit) / 0x181fffff (h >= 419328)"],
      ["Block Height H", resActive.block_height_h !== null && resActive.block_height_h !== undefined ? resActive.block_height_h.toLocaleString() : "null"],
      ["Confirmations", resActive.confirmations !== null && resActive.confirmations !== undefined ? String(resActive.confirmations) : "null"],
      ["BIP-113 / FMTP(H+5)", formatUnixUtc(resActive.mtp_bip113) + " / " + formatUnixUtc(resActive.fmtp_5)],
      ["WASM Runtime", elapsedMs.toFixed(2) + " ms (0 external calls)"]
    ]);
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

    if (!customBytesOverride && preset && preset.raw_jsonl_preview) {
      const wrap = document.createElement("div");
      wrap.className = "detail-box";
      const h = document.createElement("h4");
      h.className = "detail-title";
      h.textContent = "Raw JSONL Wire Payload (Sent Directly to WASM Parser)";
      const p = document.createElement("p");
      p.className = "detail-desc";
      p.textContent = "Bypassed JS JSON.stringify so the duplicate key \"mode\" reaches the compiled WASM RFC 8259 parser intact:";
      const box = document.createElement("div");
      box.className = "hex-dump-box";
      markNoTranslate(box);
      box.textContent = preset.raw_jsonl_preview;
      wrap.appendChild(h);
      wrap.appendChild(p);
      wrap.appendChild(box);
      host.appendChild(wrap);
      return;
    }

    if (!customBytesOverride && preset && preset.cose_hex_preview) {
      const wrap = document.createElement("div");
      wrap.className = "detail-box";
      const h = document.createElement("h4");
      h.className = "detail-title";
      h.textContent = "COSE_Sign1 Envelope Hex (Non-Minimal Uint 18 01 in Protected Header)";
      const p = document.createElement("p");
      p.className = "detail-desc";
      p.textContent = "Notice protected_hdr bytes 44 a1 18 01 26: CBOR integer 1 encoded with overlong 2-byte prefix 0x18 0x01 instead of 0x01.";
      const box = document.createElement("div");
      box.className = "hex-dump-box";
      markNoTranslate(box);
      box.textContent = preset.cose_hex_preview;
      wrap.appendChild(h);
      wrap.appendChild(p);
      wrap.appendChild(box);
      host.appendChild(wrap);
      return;
    }

    if (!activeDissection) {
      return;
    }

    const nonCanonVaruints = (activeDissection.varuints || []).filter(
      (v) => v.canonical_u32 === null || v.js_toint32 !== v.py_u64 || v.role === "bitcoin_block_height"
    );

    if (nonCanonVaruints.length > 0 && (preset.id === "preset-5-leb128-split-brain" || customBytesOverride !== null || nonCanonVaruints.some((v) => v.canonical_u32 === null))) {
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
        "JS ToInt32: " +
        targetV.js_toint32.toLocaleString() +
        " | Python/Rust u64: " +
        targetV.py_u64.toLocaleString() +
        " | Strict canonical u32: " +
        (targetV.canonical_u32 === null ? "REJECTED" : targetV.canonical_u32.toLocaleString());
      wrap.appendChild(p);

      const tWrap = document.createElement("div");
      tWrap.className = "table-wrapper";
      const tbl = document.createElement("table");
      tbl.className = "data-table mono";
      markNoTranslate(tbl);
      tbl.appendChild(buildTableHead(["Byte", "Hex", "Low 7b", "Py Shift", "JS (& 31)"]));
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
        "Preceding 11 blocks [957278..957288] median = 09:24:46Z (1783589086), 122s earlier than [957279..957289] = 09:26:48Z. Forward-MTP(H+5) = 10:02:59Z at 6 confirmations.";
      wrap.appendChild(p);

      const tWrap = document.createElement("div");
      tWrap.className = "table-wrapper table-wrapper-bounded table-wrapper-compact";
      tWrap.tabIndex = 0;
      tWrap.setAttribute("role", "region");
      tWrap.setAttribute("aria-label", "Mainnet header window timestamps");
      const tbl = document.createElement("table");
      tbl.className = "data-table mono";
      markNoTranslate(tbl);
      const hdrs = ["Height", "nTime", "UTC", "Window Role"];
      tbl.appendChild(buildTableHead(hdrs));
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
        [String(row.height), String(row.ntime), row.iso.slice(11), role].forEach((val, i) => {
          const td = document.createElement("td");
          td.dataset.label = hdrs[i];
          td.textContent = val;
          tr.appendChild(td);
        });
        tb.appendChild(tr);
      }
      tbl.appendChild(tb);
      tWrap.appendChild(tbl);
      wrap.appendChild(tWrap);
      host.appendChild(wrap);
      return;
    }

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
        markNoTranslate(r);
        const sLbl = document.createElement("span");
        sLbl.textContent = "Step " + g.step;
        const meter = document.createElement("progress");
        meter.className = "growth-meter" + (g.exceeded_strict ? " is-exceeded" : "");
        meter.max = 100;
        const logPct = Math.min(100, Math.max(6, (Math.log2(Math.max(1, g.bytes)) / 35) * 100));
        meter.value = Number(logPct.toFixed(1));
        const bLbl = document.createElement("span");
        bLbl.className = "growth-bytes-lbl";
        bLbl.textContent = formatHumanBytes(g.bytes);
        r.appendChild(sLbl);
        r.appendChild(meter);
        r.appendChild(bLbl);
        wrap.appendChild(r);
      }
      host.appendChild(wrap);
    }
  }

  function formatCardRows(res, dissect, elapsedMs, modeLabel) {
    if (res.error) {
      return [
        ["Parser error", res.error],
        ["Profile", modeLabel],
        ["Block height H", "null"],
        ["Confirmations", "null"],
        ["WASM wall time", elapsedMs.toFixed(2) + " ms"]
      ];
    }
    if (modeLabel === "strict") {
      return [
        ["Terminating step", "Step " + res.step],
        ["Block height H", res.block_height_h !== null ? res.block_height_h.toLocaleString() : "null"],
        ["Forward-MTP(H+5)", formatUnixUtc(res.fmtp_5)],
        ["Strict wire gate", dissect.strict_parse_ok ? "canonical pass" : "rejected (Step 3)"],
        ["WASM wall time", elapsedMs.toFixed(2) + " ms"]
      ];
    }
    return [
      ["Terminating step", "Step " + res.step],
      ["Block height H", res.block_height_h !== null ? res.block_height_h.toLocaleString() : "null"],
      ["Confirmations", res.confirmations !== null ? String(res.confirmations) : "null"],
      ["RWCP nTime", formatUnixUtc(res.block_time_rwcp)],
      ["BIP-113 MTP", formatUnixUtc(res.mtp_bip113)]
    ];
  }

  function renderWasmUnavailableFallback(reason) {
    const lab = window.SCITT_LAB_DATA;
    const preset = lab && lab.presets ? lab.presets[activePresetIdx] : null;
    const rawBytes = customBytesOverride || (preset && hexToBytes(preset.ots_hex).bytes) || new Uint8Array(0);
    activeRawBytes = rawBytes;
    const detailText = reason || "WebAssembly disabled or blocked by browser environment";
    const activeCliCmd =
      activeMode === "draft08"
        ? "scitt-time-anchor --mode draft08 < cases.jsonl"
        : "scitt-time-anchor --mode strict < cases.jsonl";

    const statusChip = document.getElementById("wasm-status-chip");
    if (statusChip) {
      statusChip.classList.add("outcome-unverifiable");
    }
    const statusDot = document.getElementById("wasm-status-dot");
    if (statusDot) {
      statusDot.hidden = true;
    }
    document.getElementById("wasm-status-text").textContent = "WASM Disabled (CLI Fallback)";
    document.getElementById("wasm-latency-chip").textContent = "Eval: n/a (WASM off)";

    setFeedbackBanner(
      [
        "WebAssembly is disabled in the current browser environment (e.g., Apple Lockdown Mode or strict corporate CSP). Offline verification cannot run in-browser here; use the offline Python 3 or Rust CLI instead: ",
        createCodeEl(activeCliCmd),
        " or ",
        createCodeEl("scitt_time_anchor_rs --mode " + activeMode + " < cases.jsonl"),
        ". The Interop, Z3 Proofs, and Spec Diff tabs remain fully browsable."
      ],
      true
    );

    const banner = document.getElementById("active-verdict-banner");
    banner.classList.remove("is-valid", "is-invalid", "is-unverifiable");
    banner.classList.add("is-unverifiable");
    document.getElementById("avb-mode-pill").textContent = "Runtime: CLI Fallback (" + (activeMode === "strict" ? "strict v2.0" : "draft08") + ")";
    document.getElementById("brief-cite").textContent = "Apple Lockdown Mode / Strict CSP Graceful Fallback";
    document.getElementById("brief-title").textContent = "WebAssembly Disabled in Current Browser Environment";

    const summaryEl = document.getElementById("brief-summary");
    summaryEl.textContent = "";
    summaryEl.appendChild(
      document.createTextNode(
        "In-browser verification is unavailable because WebAssembly is disabled or blocked (" +
          (customBytesOverride ? "custom input " + rawBytes.length.toLocaleString() + " bytes" : (preset ? preset.short_label : "preset")) +
          "). Execute deterministic clean-room verification offline via CLI: "
      )
    );
    summaryEl.appendChild(createCodeEl(activeCliCmd));
    summaryEl.appendChild(document.createTextNode("."));

    setOutcomeBadge(document.getElementById("active-verdict-badge"), "unverifiable", "WASM DISABLED");
    document.getElementById("active-verdict-step").textContent = "Use Offline CLI";

    const stages = [
      { id: "S0", label: "JSONL / CBOR / COSE envelope gate" },
      { id: "S1–S2", label: "Artifact SHA-256 == claimed_hash" },
      { id: "S3", label: "OTS wire format & opcode whitelist" },
      { id: "S4–S5", label: "Branch Bitcoin attestation & replay" },
      { id: "S6–S7", label: "PoW, 0x1d00ffff/0x181fffff & 4x retarget" },
      { id: "S8–S9", label: "Merkle match & k >= 6 confirmations" },
      { id: "S10–S11", label: "RWCP, BIP-113 MTP & Forward-MTP(H+5)" }
    ];
    const traceList = document.getElementById("step-trace-list");
    traceList.textContent = "";
    for (const st of stages) {
      const li = document.createElement("li");
      li.className = "step-trace-item";
      const sSpan = document.createElement("span");
      sSpan.className = "trace-stage";
      markNoTranslate(sSpan);
      sSpan.textContent = st.id;
      const lSpan = document.createElement("span");
      lSpan.className = "trace-label";
      lSpan.textContent = st.label;
      const pSpan = document.createElement("span");
      pSpan.className = "trace-pill is-skip";
      markNoTranslate(pSpan);
      pSpan.textContent = "CLI";
      li.appendChild(sSpan);
      li.appendChild(lSpan);
      li.appendChild(pSpan);
      traceList.appendChild(li);
    }

    renderKvRows(document.getElementById("consensus-telemetry-kv"), [
      ["Browser WASM", "Disabled / Blocked"],
      ["Detection Detail", detailText],
      ["Python 3 CLI", createCodeEl("scitt-time-anchor --mode strict < cases.jsonl")],
      ["Native Rust CLI", createCodeEl("scitt_time_anchor_rs --mode strict < cases.jsonl")],
      ["Available Tabs", "Interop (7 Orgs), Z3 Proofs (11), Spec Diff (-09)"]
    ]);

    document.getElementById("card-draft08").classList.toggle("is-active-mode", activeMode === "draft08");
    document.getElementById("card-strict").classList.toggle("is-active-mode", activeMode === "strict");

    setOutcomeBadge(document.getElementById("badge-draft08"), "neutral", "cli-only");
    renderKvRows(document.getElementById("kv-draft08"), [
      ["Status", "WebAssembly disabled"],
      ["Offline CLI", createCodeEl("scitt-time-anchor --mode draft08 < cases.jsonl")],
      ["Selected preset", preset ? preset.short_label : "custom"]
    ]);

    setOutcomeBadge(document.getElementById("badge-strict"), "neutral", "cli-only");
    renderKvRows(document.getElementById("kv-strict"), [
      ["Status", "WebAssembly disabled"],
      ["Python 3 CLI", createCodeEl("scitt-time-anchor --mode strict < cases.jsonl")],
      ["Native Rust CLI", createCodeEl("scitt_time_anchor_rs --mode strict < cases.jsonl")]
    ]);

    setOutcomeBadge(document.getElementById("badge-upstream-js"), "reference", "reference");
    renderKvRows(document.getElementById("kv-upstream-js"), [
      ["Browser mode", "Static reference tabs active"],
      ["Active preset", customBytesOverride ? "Custom bytes" : (preset ? preset.short_label : "none")],
      ["Interop / Z3 / Diff", "Browsable without WebAssembly"]
    ]);

    document.getElementById("dissect-byte-summary").textContent =
      rawBytes.length.toLocaleString() + " octets (WASM dissector inactive)";
    document.getElementById("span-stream").textContent = "";
    document.getElementById("selected-offset-chip").textContent = "+0x0000";
    document.getElementById("detail-title").textContent = "Raw Wire Hex Preview (Offline CLI Required for Dissection)";
    document.getElementById("detail-section").textContent = customBytesOverride
      ? "Caller-supplied .ots bytes"
      : (preset ? preset.section_cite : "Section 4.1 Step 3");
    document.getElementById("detail-desc").textContent =
      "WebAssembly is disabled in this browser environment, so in-browser span decoding is paused. Use scitt-time-anchor --mode strict for full proof evaluation.";
    document.getElementById("detail-hex").textContent = bytesToHex(rawBytes.subarray(0, 128)) || "(empty)";
    document.getElementById("dynamic-subpanel").textContent = "";
  }

  function evaluateActiveState() {
    if (!wasmExports) {
      renderWasmUnavailableFallback(wasmUnavailableReason || "WebAssembly unavailable");
      return;
    }
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
      ? "Inspecting caller-supplied binary/hex bytes in isolated WebAssembly memory."
      : preset.summary;

    const t0 = performance.now();
    const dissect = callWasmDissect(rawBytes);

    let resDraft;
    let resStrict;
    const explorerOnly = document.getElementById("explorer-only-toggle").checked;

    if (!customBytesOverride && preset.raw_jsonl_draft08 && preset.raw_jsonl_strict) {
      [resDraft, resStrict] = callWasmEvalJsonlLines(
        [preset.raw_jsonl_draft08, preset.raw_jsonl_strict],
        activeMode === "strict" ? 1 : 0
      );
    } else {
      const reqDraft = applyExplorerToggle(restoreB64Fields(preset.draft08_req));
      const reqStrict = applyExplorerToggle(restoreB64Fields(preset.strict_req));
      if (customBytesOverride) {
        const customB64 = bytesToBase64(rawBytes);
        delete reqDraft.proof_bundle_cbor_b64;
        delete reqStrict.proof_bundle_cbor_b64;
        reqDraft.input_mode = "raw";
        reqStrict.input_mode = "raw";
        reqDraft.ots_b64 = customB64;
        reqStrict.ots_b64 = customB64;
      }
      [resDraft, resStrict] = callWasmEvalJsonlLines(
        [JSON.stringify(reqDraft), JSON.stringify(reqStrict)],
        activeMode === "strict" ? 1 : 0
      );
    }
    const elapsedMs = performance.now() - t0;

    activeDissection = dissect;
    document.getElementById("wasm-latency-chip").textContent = "Eval: " + elapsedMs.toFixed(2) + " ms";

    const resActive = activeMode === "strict" ? resStrict : resDraft;
    renderActiveVerdictBanner(preset, resActive, dissect, elapsedMs);

    if (dissect.parse_error) {
      setFeedbackBanner(
        "Wire format notice at byte offset " +
          dissect.parse_error.offset +
          " (" +
          formatHexOffset(dissect.parse_error.offset) +
          "): " +
          dissect.parse_error.message
      );
    } else if (explorerOnly) {
      setFeedbackBanner(
        "Explorer-only simulation active (Appendix D.7 Route 4): PoW header chain removed so Step 7b yields unverifiable rather than valid."
      );
    } else {
      setFeedbackBanner(null);
    }

    document.getElementById("card-draft08").classList.toggle("is-active-mode", activeMode === "draft08");
    document.getElementById("card-strict").classList.toggle("is-active-mode", activeMode === "strict");

    setOutcomeBadge(
      document.getElementById("badge-draft08"),
      resDraft.error ? "bad_json" : resDraft.outcome,
      resDraft.error ? "bad_json" : resDraft.outcome
    );
    renderKvRows(document.getElementById("kv-draft08"), formatCardRows(resDraft, dissect, elapsedMs, "draft08"));

    setOutcomeBadge(
      document.getElementById("badge-strict"),
      resStrict.error ? "bad_json" : resStrict.outcome,
      resStrict.error ? "bad_json" : resStrict.outcome
    );
    renderKvRows(document.getElementById("kv-strict"), formatCardRows(resStrict, dissect, elapsedMs, "strict"));

    const btcV = (dissect.varuints || []).find((v) => v.role === "bitcoin_block_height");
    const jsBadge = document.getElementById("badge-upstream-js");
    if (customBytesOverride) {
      setOutcomeBadge(jsBadge, dissect.draft08_parse_ok ? "parsed" : "error");
    } else if (preset.id === "preset-5-leb128-split-brain") {
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
      markNoTranslate(btn);

      const off = document.createElement("span");
      off.className = "span-off";
      markNoTranslate(off);
      off.textContent = formatHexOffset(sp.start);

      const slice = rawBytes.subarray(sp.start, Math.min(sp.end, sp.start + 6));
      let hexPreview = bytesToHex(slice);
      if (sp.end - sp.start > 6) {
        hexPreview += "…" + (sp.end - sp.start) + "B";
      }

      const hx = document.createElement("span");
      hx.className = "span-hex";
      markNoTranslate(hx);
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

  function initModeControls() {
    const btnDraft = document.getElementById("mode-btn-draft08");
    const btnStrict = document.getElementById("mode-btn-strict");
    function setMode(nextMode) {
      activeMode = nextMode;
      btnDraft.classList.toggle("is-selected", activeMode === "draft08");
      btnStrict.classList.toggle("is-selected", activeMode === "strict");
      btnDraft.setAttribute("aria-pressed", activeMode === "draft08" ? "true" : "false");
      btnStrict.setAttribute("aria-pressed", activeMode === "strict" ? "true" : "false");
      evaluateActiveState();
    }
    btnDraft.addEventListener("click", function () {
      setMode("draft08");
    });
    btnStrict.addEventListener("click", function () {
      setMode("strict");
    });
  }

  function initPresets() {
    const lab = window.SCITT_LAB_DATA;
    const grid = document.getElementById("preset-grid");
    grid.textContent = "";

    lab.presets.forEach((p, idx) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "preset-btn" + (idx === 0 ? " is-selected" : "");
      btn.dataset.presetId = p.id;
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

  function createMetricBox(lbl, num, note) {
    const box = document.createElement("div");
    box.className = "metric-box";
    const sLbl = document.createElement("span");
    sLbl.className = "metric-label";
    sLbl.textContent = lbl;
    const sNum = document.createElement("span");
    sNum.className = "metric-number";
    sNum.textContent = num;
    const sNote = document.createElement("span");
    sNote.className = "metric-note";
    sNote.textContent = note;
    box.appendChild(sLbl);
    box.appendChild(sNum);
    box.appendChild(sNote);
    return box;
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
      ["Internal differential fuzz", (d50.total_vectors_executed || 50000).toLocaleString(), "0 divergences across Python, Rust & WASM"]
    ];
    for (const [lbl, num, note] of metrics) {
      mStrip.appendChild(createMetricBox(lbl, num, note));
    }

    const interopHeaders = [
      "Vector",
      "Umarise & JS OTS",
      "Python OTS 0.5.0",
      "EMILIA (-06)",
      "CryptoGeekPT (-03)",
      "DPS Lemonnier (-08)",
      "Triple (draft08)",
      "Triple (strict)"
    ];

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
          td.dataset.label = interopHeaders[cIdx];
          if (cIdx > 0) {
            td.className = "mono";
            markNoTranslate(td);
          } else {
            markNoTranslate(td);
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

    const scBox = document.getElementById("scitt-cose-summary");
    const wexp = io.scitt_cose.wexp_scitt_receipt_boundary_001;
    const iso = io.scitt_cose.isoluce_live_checkpoint;
    const scTblWrap = document.createElement("div");
    scTblWrap.className = "table-wrapper table-wrapper-stack";
    scTblWrap.tabIndex = 0;
    scTblWrap.setAttribute("role", "region");
    scTblWrap.setAttribute("aria-labelledby", "scitt-cose-caption");
    const scTbl = document.createElement("table");
    scTbl.className = "data-table";
    const scHdrs = ["Artifact Source", "Envelope", "Upstream pycose 1.1.0", "Clean-Room CBOR & RFC 9921 / 9942 Result"];
    scTbl.appendChild(buildTableHead(scHdrs));
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
        td.dataset.label = scHdrs[idx];
        if (idx >= 1) {
          td.className = "mono";
          markNoTranslate(td);
        }
        td.textContent = c;
        tr.appendChild(td);
      });
      scTb.appendChild(tr);
    }
    scTbl.appendChild(scTb);
    scTblWrap.appendChild(scTbl);
    scBox.appendChild(scTblWrap);

    const dBox = document.getElementById("diff50k-summary");
    const dWrap = document.createElement("div");
    dWrap.className = "table-wrapper table-wrapper-stack";
    dWrap.tabIndex = 0;
    dWrap.setAttribute("role", "region");
    dWrap.setAttribute("aria-labelledby", "diff50k-caption");
    const dTbl = document.createElement("table");
    dTbl.className = "data-table mono";
    markNoTranslate(dTbl);
    const dHdrs = ["Engine", "Cases Evaluated", "draft08 / strict Split", "Mean Latency", "Pairwise Divergences"];
    dTbl.appendChild(buildTableHead(dHdrs));
    const dTb = document.createElement("tbody");
    const totalVecs = d50.total_vectors_executed || d50.total_cases || 50000;
    const splitObj = d50.profile_distribution || d50.mode_counts;
    const dRows = [
      ["Clean-Room Python 3 CLI", totalVecs.toLocaleString(), splitObj.draft08 + " / " + splitObj.strict, ((d50.timings_ms.python_parallel_eval_ms * 1000) / totalVecs).toFixed(2) + " µs/vec", "0"],
      ["Native Rust (#![forbid(unsafe_code)])", totalVecs.toLocaleString(), splitObj.draft08 + " / " + splitObj.strict, d50.timings_ms.rust_us_per_vector + " µs/vec", "0"],
      ["Compiled wasm32 (Node V8)", totalVecs.toLocaleString(), splitObj.draft08 + " / " + splitObj.strict, d50.timings_ms.wasm_us_per_vector + " µs/vec", "0"]
    ];
    for (const r of dRows) {
      const tr = document.createElement("tr");
      r.forEach((c, idx) => {
        const td = document.createElement("td");
        td.dataset.label = dHdrs[idx];
        td.textContent = c;
        tr.appendChild(td);
      });
      dTb.appendChild(tr);
    }
    dTbl.appendChild(dTb);
    dWrap.appendChild(dTbl);
    dBox.appendChild(dWrap);
  }

  function initZ3Tab() {
    const z3 = window.SCITT_LAB_DATA.z3_formal;
    const mStrip = document.getElementById("z3-metrics");
    const totalTheorems = (z3.formal_findings ? z3.formal_findings.length : 8) + Object.keys(z3.soundness_proof || {}).length;
    const items = [
      ["SMT solver", "Z3 " + z3.z3_version, "Arithmetic & bit-vector decision procedures"],
      ["Verified findings", String(z3.findings_verified_count) + " / 8", totalTheorems + " formal theorems verified (UNSAT)"],
      ["Partition completeness", "UNSAT", "Exact {valid, invalid, unverifiable} partition"],
      ["Solver runtime", z3.elapsed_ms + " ms", "Deterministic reproducible SMT script"]
    ];
    for (const [l, n, note] of items) {
      mStrip.appendChild(createMetricBox(l, n, note));
    }

    const z3Hdrs = [
      "Finding",
      "Protocol Property",
      "Baseline draft08 Counterexample (SAT)",
      "Strict Invariant (UNSAT)",
      "Concrete Witness"
    ];
    const tbody = document.getElementById("z3-tbody");
    for (const f of z3.formal_findings) {
      const tr = document.createElement("tr");
      const cells = [
        f.id,
        f.title,
        f.draft08_result,
        f.strict_result,
        JSON.stringify(f.z3_witness, null, 1).replace(/\n\s*/g, " ")
      ];
      cells.forEach((c, idx) => {
        const td = document.createElement("td");
        td.dataset.label = z3Hdrs[idx];
        if (idx === 0 || idx === 4) {
          td.className = "mono";
          markNoTranslate(td);
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
      markNoTranslate(div);
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
    const tabList = document.querySelector("[role='tablist']");
    const tabBtns = Array.from(document.querySelectorAll(".tab-btn"));

    function selectTab(targetBtn, moveFocus) {
      const target = targetBtn.dataset.tab;
      tabBtns.forEach((b) => {
        const sel = b === targetBtn;
        b.setAttribute("aria-selected", sel ? "true" : "false");
        b.tabIndex = sel ? 0 : -1;
      });
      document.querySelectorAll(".tab-panel").forEach((p) => {
        p.hidden = p.id !== "panel-" + target;
      });
      targetBtn.scrollIntoView({ block: "nearest", inline: "nearest" });
      if (moveFocus) {
        targetBtn.focus();
      }
    }

    tabBtns.forEach((btn, idx) => {
      btn.tabIndex = idx === 0 ? 0 : -1;
      btn.addEventListener("click", function () {
        selectTab(btn, false);
      });
    });

    tabList.addEventListener("keydown", function (ev) {
      const curIdx = tabBtns.indexOf(document.activeElement);
      if (curIdx < 0) {
        return;
      }
      let nextIdx = -1;
      if (ev.key === "ArrowRight") {
        nextIdx = (curIdx + 1) % tabBtns.length;
      } else if (ev.key === "ArrowLeft") {
        nextIdx = (curIdx - 1 + tabBtns.length) % tabBtns.length;
      } else if (ev.key === "Home") {
        nextIdx = 0;
      } else if (ev.key === "End") {
        nextIdx = tabBtns.length - 1;
      }
      if (nextIdx >= 0) {
        ev.preventDefault();
        selectTab(tabBtns[nextIdx], true);
      }
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
            " bytes). Interactive Byte-Ray limit is 262,144 bytes."
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

  function initThemeToggle() {
    const btn = document.getElementById("theme-toggle-btn");
    if (!btn) {
      return;
    }
    const THEME_KEY = "scitt-color-scheme";
    const meta = document.querySelector('meta[name="color-scheme"]');
    const mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

    function getStoredTheme() {
      try {
        const v = localStorage.getItem(THEME_KEY);
        return v === "light" || v === "dark" ? v : null;
      } catch (_) {
        return null;
      }
    }

    function getSystemTheme() {
      return mq && mq.matches ? "dark" : "light";
    }

    function applyTheme(stored) {
      if (stored === "light" || stored === "dark") {
        document.documentElement.dataset.theme = stored;
        if (meta) {
          meta.setAttribute("content", stored);
        }
      } else {
        delete document.documentElement.dataset.theme;
        if (meta) {
          meta.setAttribute("content", "light dark");
        }
      }
      const effective = stored || getSystemTheme();
      const target = effective === "dark" ? "light" : "dark";
      btn.textContent = "Theme: " + (effective === "dark" ? "Dark" : "Light");
      btn.setAttribute("aria-label", "Switch color theme to " + target + " mode");
      btn.setAttribute("aria-pressed", effective === "dark" ? "true" : "false");
    }

    applyTheme(getStoredTheme());

    btn.addEventListener("click", function () {
      const currentEffective = getStoredTheme() || getSystemTheme();
      const nextTarget = currentEffective === "dark" ? "light" : "dark";
      const nextStored = nextTarget === getSystemTheme() ? null : nextTarget;
      try {
        if (nextStored === null) {
          localStorage.removeItem(THEME_KEY);
        } else {
          localStorage.setItem(THEME_KEY, nextStored);
        }
      } catch (_) {
        /* Storage blocked; keep DOM override for current session */
        applyTheme(nextTarget);
        return;
      }
      applyTheme(nextStored);
    });

    if (mq && mq.addEventListener) {
      mq.addEventListener("change", function () {
        applyTheme(getStoredTheme());
      });
    }
    window.addEventListener("storage", function (ev) {
      if (ev.key === THEME_KEY || ev.key === null) {
        applyTheme(getStoredTheme());
      }
    });
  }

  async function boot() {
    initThemeToggle();

    const meta = window.SCITT_WASM_META;
    if (meta && typeof meta.raw_bytes === "number") {
      const decKb = (meta.raw_bytes / 1000).toFixed(1);
      const gzKb = (meta.gzip_bytes / 1000).toFixed(1);
      document.getElementById("wasm-size-chip").textContent =
        "wasm32 · " + decKb + " KB (" + gzKb + " KB gzip)";
      document.getElementById("btn-download-wasm").textContent =
        "Download .wasm (" + decKb + " KB)";
      const fSha = document.getElementById("footer-sha256");
      fSha.classList.add("footer-sha");
      fSha.textContent = "WASM SHA-256: " + meta.sha256.slice(0, 24) + "…";
    }

    initModeControls();
    initPresets();
    initInteropTab();
    initZ3Tab();
    initDiffTab();
    initTabsAndControls();

    if (typeof WebAssembly === "undefined" || typeof WebAssembly.instantiate !== "function") {
      wasmExports = null;
      wasmUnavailableReason = "window.WebAssembly is undefined (Apple Lockdown Mode or browser policy)";
      renderWasmUnavailableFallback(wasmUnavailableReason);
      return;
    }

    try {
      const parsedWasm = hexToBytes(window.SCITT_WASM_HEX || "");
      if (parsedWasm.error || !parsedWasm.bytes) {
        throw new Error(parsedWasm.error || "Missing WASM bundle");
      }
      const { instance } = await WebAssembly.instantiate(parsedWasm.bytes, {});
      wasmExports = instance.exports;
      wasmUnavailableReason = null;
      document.getElementById("wasm-status-text").textContent = "WASM Ready";
      evaluateActiveState();
    } catch (err) {
      wasmExports = null;
      wasmUnavailableReason = err && err.message ? err.message : String(err);
      renderWasmUnavailableFallback(wasmUnavailableReason);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
