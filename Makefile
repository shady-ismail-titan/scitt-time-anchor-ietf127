.PHONY: check test-rust test-conformance test-z3 test-differential serve

check: test-rust test-conformance test-z3
	python3 verification_suite/run_verification_suite.py

test-rust:
	cargo test --release --manifest-path scitt_time_anchor_rs/Cargo.toml

test-conformance:
	python3 verification_suite/test_appendix_d_conformance.py

test-z3:
	python3 verification_suite/prove_z3_invariants.py

test-differential:
	python3 verification_suite/run_50k_triple_differential.py

serve:
	python3 web/server.py --host 127.0.0.1 --port 8080
