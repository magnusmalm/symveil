.PHONY: leak-test leak-streak leak-corpus shellcheck

# POSIX launch scripts. Requires shellcheck.
shellcheck:
	shellcheck -s sh -x scripts/symveil-claude scripts/symveil-grok scripts/symveil-common.sh

# Builds SymVeil and runs the synthetic leak harness.
# Exits non-zero when a gated canary reaches the mock upstream, a benign word
# starts being masked, a restore or policy check fails, or the verdict is not
# the one this build must report.
# A passing run still prints NOT SAFE. That line is the work-use verdict.
# The next line is the gated-leak count. It is 0 when the test passes.
leak-test:
	cargo test --test leak_harness -- --nocapture

# Three leak measurements back to back. Each run deletes target/leak-report
# first, so a previous report cannot leak into the next one.
# Prints SAFE when all three cargo test invocations exit 0, which means each
# run had zero gated leaks. The report verdict inside each run stays NOT SAFE
# until a real-client pass. Prints NOT SAFE and the failing run number when a
# test exits non-zero. This SAFE is the streak only. Work use also needs the
# real-client pass in tests/leak/RUNBOOK.md.
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

# Writes the synthetic corpus to target/leak-corpus and leaves it there.
# make leak-test also writes a copy under target/leak-report/corpus, and the
# next measurement deletes that directory. There is no corpus-a directory.
leak-corpus:
	cargo test --test leak_harness -- leak_corpus --exact --nocapture
