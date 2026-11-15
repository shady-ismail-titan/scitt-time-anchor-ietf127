//! Thin WebAssembly export table forwarding directly into `#![forbid(unsafe_code)]`
//! `scitt_time_anchor_rs::wasm_api`. Contains zero `unsafe` blocks or pointer dereferences.

#[no_mangle]
pub extern "C" fn wasm_prepare_input(len: usize) -> usize {
    scitt_time_anchor_rs::wasm_api::wasm_prepare_input(len)
}

#[no_mangle]
pub extern "C" fn wasm_output_ptr() -> usize {
    scitt_time_anchor_rs::wasm_api::wasm_output_ptr()
}

#[no_mangle]
pub extern "C" fn wasm_output_len() -> usize {
    scitt_time_anchor_rs::wasm_api::wasm_output_len()
}

#[no_mangle]
pub extern "C" fn wasm_evaluate_jsonl(default_mode_id: u32) -> usize {
    scitt_time_anchor_rs::wasm_api::wasm_evaluate_jsonl(default_mode_id)
}

#[no_mangle]
pub extern "C" fn wasm_dissect_ots() -> usize {
    scitt_time_anchor_rs::wasm_api::wasm_dissect_ots()
}
