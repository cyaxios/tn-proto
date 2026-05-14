# TN regression test platform — driver
#
# Conventions:
#   - One target per silo (e.g. `make c1`).
#   - Tier umbrellas: `make crawl`, `make walk`, `make all`.
#   - Runtime-scoped umbrellas: `make crawl-python`, `make crawl-ts`,
#     `make crawl-browser` — useful when you've broken one stack and
#     don't want noise from the other.
#   - Every silo writes a structured pass/fail report to
#     `.reports/<silo>/last.json` regardless of pass/fail.
#   - `make clean` blows away `.reports/` only.
#
# Each silo's recipe runs from the silo's own directory. The recipe is
# whatever runner is appropriate for that silo's primary runtime
# (pytest, node --test, playwright, etc.).

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPORTS := $(ROOT)/.reports

# Resolve repo root (one up from regression/) so silo recipes can call
# back into the SDKs without each one re-deriving paths.
REPO_ROOT := $(abspath $(ROOT)/..)
PYTHON ?= $(REPO_ROOT)/.venv/Scripts/python.exe
ifeq (,$(wildcard $(PYTHON)))
PYTHON := $(REPO_ROOT)/.venv/bin/python
endif
ifeq (,$(wildcard $(PYTHON)))
PYTHON := python
endif

export REGRESSION_ROOT := $(ROOT)
export REGRESSION_REPORTS := $(REPORTS)
export REGRESSION_REPO_ROOT := $(REPO_ROOT)
export REGRESSION_PYTHON := $(PYTHON)

# ---------------------------------------------------------------------------
# Default + umbrellas
# ---------------------------------------------------------------------------

.PHONY: help
help:
	@echo "TN regression suite. Useful targets:"
	@echo ""
	@echo "  make all              everything (currently == crawl)"
	@echo "  make crawl            all 9 crawl silos"
	@echo "  make walk             (not built yet — see walk/README.md)"
	@echo ""
	@echo "  make crawl-python     C1, C2, C5, C6, C7, C8"
	@echo "  make crawl-ts         C3, C4"
	@echo "  make crawl-browser    C9"
	@echo ""
	@echo "  make c1 .. c9         individual silos"
	@echo ""
	@echo "  make clean            remove .reports/"
	@echo ""
	@echo "Reports land in $(REPORTS)/<silo>/last.json regardless of pass/fail."

.PHONY: all
all: crawl

# ---------------------------------------------------------------------------
# Crawl tier
# ---------------------------------------------------------------------------

CRAWL_SILOS := c1 c2 c3 c4 c5 c6 c7 c8 c9

.PHONY: crawl
crawl: $(CRAWL_SILOS)

.PHONY: crawl-python
crawl-python: c1 c2 c5 c6 c7 c8

.PHONY: crawl-ts
crawl-ts: c3 c4

.PHONY: crawl-browser
crawl-browser: c9

# ---------------------------------------------------------------------------
# Per-silo targets
# ---------------------------------------------------------------------------
#
# Each silo recipe:
#   1. Ensures the report directory exists.
#   2. Runs the silo's runner.
#   3. The silo's runner is responsible for writing
#      `$(REPORTS)/<silo>/last.json` itself (via _shared/assertions).
#
# The recipes themselves are kept thin so adding a new silo doesn't
# require Make-fu — just add another silo block.

$(REPORTS)/%/.keep:
	@mkdir -p $(@D)
	@touch $@

# --- Python silos --------------------------------------------------------

.PHONY: c1
c1: $(REPORTS)/c1/.keep
	$(PYTHON) -m pytest crawl/c1_python_module_log -v --tb=short \
		--silo-report=$(REPORTS)/c1/last.json

.PHONY: c2
c2: $(REPORTS)/c2/.keep
	$(PYTHON) -m pytest crawl/c2_python_object_log -v --tb=short \
		--silo-report=$(REPORTS)/c2/last.json

.PHONY: c5
c5: $(REPORTS)/c5/.keep
	$(PYTHON) -m pytest crawl/c5_groups_recipients_inproc -v --tb=short \
		--silo-report=$(REPORTS)/c5/last.json

.PHONY: c6
c6: $(REPORTS)/c6/.keep
	$(PYTHON) -m pytest crawl/c6_cli_verbs -v --tb=short \
		--silo-report=$(REPORTS)/c6/last.json

.PHONY: c7
c7: $(REPORTS)/c7/.keep
	$(PYTHON) -m pytest crawl/c7_key_custody_default -v --tb=short \
		--silo-report=$(REPORTS)/c7/last.json

.PHONY: c8
c8: $(REPORTS)/c8/.keep
	$(PYTHON) -m pytest crawl/c8_restore_new_machine -v --tb=short \
		--silo-report=$(REPORTS)/c8/last.json

# --- TS silos -------------------------------------------------------------
#
# Node silos run via the ts-sdk's installed tooling so we don't have to
# wire up a parallel node_modules. The runner here just shells out to
# `node --test` with the silo's test glob.

NODE_RUNNER := cd $(REPO_ROOT)/ts-sdk && node --import tsx --test

.PHONY: c3
c3: $(REPORTS)/c3/.keep
	$(NODE_RUNNER) $(ROOT)/crawl/c3_ts_module_log/*.test.ts \
		2>&1 | tee $(REPORTS)/c3/run.log; \
	$(PYTHON) $(ROOT)/_shared/finalize_ts_report.py c3 $(REPORTS)/c3/run.log

.PHONY: c4
c4: $(REPORTS)/c4/.keep
	$(NODE_RUNNER) $(ROOT)/crawl/c4_ts_object_log/*.test.ts \
		2>&1 | tee $(REPORTS)/c4/run.log; \
	$(PYTHON) $(ROOT)/_shared/finalize_ts_report.py c4 $(REPORTS)/c4/run.log

# --- Browser silo ---------------------------------------------------------

.PHONY: c9
c9: $(REPORTS)/c9/.keep
	$(PYTHON) -m pytest crawl/c9_chrome_ext_decrypt -v --tb=short \
		--silo-report=$(REPORTS)/c9/last.json

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

.PHONY: clean
clean:
	@rm -rf $(REPORTS)
	@echo "removed $(REPORTS)"

# ---------------------------------------------------------------------------
# Status — show what's wired up and what isn't
# ---------------------------------------------------------------------------

.PHONY: status
status:
	@echo "Crawl silos (target → directory):"
	@for s in $(CRAWL_SILOS); do \
		dir=$$(ls -d crawl/$$s* 2>/dev/null || true); \
		if [ -n "$$dir" ] && [ -n "$$(find $$dir -maxdepth 2 -name 'test_*.py' -o -name '*.test.ts' 2>/dev/null)" ]; then \
			echo "  $$s → $$dir [BUILT]"; \
		elif [ -n "$$dir" ]; then \
			echo "  $$s → $$dir [SCAFFOLDED, no tests yet]"; \
		else \
			echo "  $$s → (missing)"; \
		fi; \
	done
