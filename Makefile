.PHONY: leak-test leak-streak

# Builds SymVeil and runs the synthetic leak harness.
# Exits non-zero when a gated canary reaches the mock upstream, a benign word
# starts being masked, a restore or policy check fails, or the verdict is not
# the one this build must report.
leak-test:
	cargo test --test leak_harness -- --nocapture

# Three leak measurements back to back. Each run deletes target/leak-report
# first, so a previous report cannot leak into the next one.
# Prints SAFE when all three have zero gated leaks. Prints NOT SAFE and the
# failing run number otherwise. This SAFE is the streak only. Work use also
# needs the real-client pass in tests/leak/RUNBOOK.md.
leak-streak:
	@set -eu; \
	for n in 1 2 3; do \
	  echo "leak-streak run $$n"; \
	  rm -rf target/leak-report; \
	  if ! cargo test --test leak_harness -- --nocapture; then \
	    echo "NOT SAFE (run $$n)"; \
	    exit 1; \
	  fi; \
	done; \
	echo SAFE
