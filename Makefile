# tn-proto root developer commands.
#
# The current Python distribution is one mixed maturin wheel:
#   python/ package sources + crypto/tn-py umbrella native extension
#   exposed as tn._native.core, tn._native.btn, and tn._native.hibe.
#
# These targets are thin wrappers over tools/dev.py so the same commands work
# from PowerShell, Bash, and CI.

PYTHON ?= python
DEV := $(PYTHON) tools/dev.py

.PHONY: help bootstrap native verify-native wheel build \
        rust-hibe python-hibe ts-hibe test-hibe clean

help:
	@$(DEV) --help

bootstrap:
	$(DEV) bootstrap

native:
	$(DEV) native

verify-native:
	$(DEV) verify-native

wheel:
	$(DEV) wheel

build:
	$(DEV) build

rust-hibe:
	$(DEV) rust-hibe

python-hibe:
	$(DEV) python-hibe

ts-hibe:
	$(DEV) ts-hibe

test-hibe:
	$(DEV) test-hibe

clean:
	rm -rf dist python/dist-local target/wheels .venv-test
