.PHONY: leak-test

# Builds SymVeil and runs the synthetic leak harness.
# Exits non-zero when a gated canary reaches the mock upstream, a benign word
# starts being masked, a restore or policy check fails, or the verdict is not
# the one this build must report.
leak-test:
	cargo test --test leak_harness -- --nocapture
