# tn-proto build orchestration.
#
# Standard tooling, repeatable across machines:
#
#   - ``maturin``  builds the Rust+PyO3 wheels (tn-core, tn-btn).
#   - ``python -m build``  builds the pure-Python wheel + sdist (tn-proto).
#   - ``twine check``  validates wheel metadata before upload.
#   - ``twine upload``  publishes to TestPyPI / PyPI.
#
# Output goes to ./dist/ (the Python packaging convention; gitignored).
# The legacy bespoke ``./dist-wheelhouse/`` location is no longer used.
#
# Common workflows::
#
#   make                  # build all three wheels into ./dist
#   make build            # same
#   make clean            # rm ./dist and ./target/wheels
#   make check            # twine check on every wheel in ./dist
#   make test-install     # fresh venv, pip install dist/*.whl, smoke import
#   make publish-test     # upload ./dist to TestPyPI
#   make publish          # upload ./dist to PyPI (prompts for confirmation)
#   make help
#
# Override the Python interpreter::
#
#   make build PYTHON=/path/to/python
#
# By default, Make uses the ``python`` on $PATH. The Makefile assumes
# that interpreter has ``maturin``, ``build``, and ``twine`` installed.
# To install them in one shot::
#
#   make tools

PYTHON ?= python
DIST   := dist

# Subdirectories of crypto/ that produce PyO3 wheels via maturin. The
# pattern ``crypto/<crate>-py`` is the convention.
RUST_CRATES := tn-core tn-btn

# Map crate name → maturin build dir.
TN_CORE_DIR := crypto/tn-core-py
TN_BTN_DIR  := crypto/tn-btn-py

# Pure-Python package directory.
PY_DIR := python

.PHONY: help build build-core build-btn build-protocol \
        clean check test-install \
        publish-test publish tools \
        verify-version

# Default target.
all: build

help:
	@echo "tn-proto Makefile — standard build/publish workflow"
	@echo ""
	@echo "Targets:"
	@echo "  build           Build all wheels (tn-core + tn-btn + tn-proto) into ./dist"
	@echo "  build-core      Build only the tn-core wheel"
	@echo "  build-btn       Build only the tn-btn wheel"
	@echo "  build-protocol  Build only the tn-proto wheel + sdist"
	@echo "  clean           Remove ./dist and ./target/wheels"
	@echo "  check           Run 'twine check' over every wheel in ./dist"
	@echo "  test-install    Fresh venv + pip install + import smoke test"
	@echo "  publish-test    Upload ./dist to TestPyPI (prompts for token)"
	@echo "  publish         Upload ./dist to PyPI (prompts twice; require confirmation)"
	@echo "  tools           Install maturin + build + twine into the active interpreter"
	@echo "  verify-version  Check tn-proto version isn't already on TestPyPI"
	@echo ""
	@echo "Override Python: make PYTHON=/path/to/python build"

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------

# Make sure ./dist exists. Used as a prerequisite by every build target.
$(DIST):
	mkdir -p $(DIST)

build: build-core build-btn build-protocol
	@echo ""
	@echo "==> Wheels in $(DIST):"
	@ls -1 $(DIST) | sed 's/^/    /'

build-core: $(DIST)
	@echo "==> Building tn-core (Rust + PyO3 via maturin)"
	cd $(TN_CORE_DIR) && $(PYTHON) -m maturin build --release --out ../../$(DIST)

build-btn: $(DIST)
	@echo "==> Building tn-btn (Rust + PyO3 via maturin)"
	cd $(TN_BTN_DIR) && $(PYTHON) -m maturin build --release --out ../../$(DIST)

build-protocol: $(DIST)
	@echo "==> Building tn-proto (pure Python via build)"
	cd $(PY_DIR) && $(PYTHON) -m build --outdir ../$(DIST)

# ---------------------------------------------------------------------------
# Hygiene + verification
# ---------------------------------------------------------------------------

clean:
	@echo "==> Removing $(DIST)/ and target/wheels/"
	rm -rf $(DIST) target/wheels

check: $(DIST)
	@echo "==> Running twine check over $(DIST)/"
	$(PYTHON) -m twine check $(DIST)/*

# Build a fresh venv, install every wheel from ./dist, and import-test
# the public surface. Catches "wheel built but unusable" cases before
# they reach TestPyPI.
test-install: build
	@echo "==> Spinning up a fresh venv to install + smoke-test the wheels"
	rm -rf .venv-test
	$(PYTHON) -m venv .venv-test
	@echo "==> Installing wheels"
	. .venv-test/bin/activate 2>/dev/null || .venv-test/Scripts/activate; \
	  pip install --upgrade pip --quiet && \
	  pip install --find-links $(DIST) tn-proto --quiet && \
	  python -c "import tn, tn_core, tn_btn; print('smoke OK:', tn.__name__, '+', tn_core.__name__, '+', tn_btn.__name__)"
	@echo "==> Cleaning up"
	rm -rf .venv-test

# ---------------------------------------------------------------------------
# Publish targets
# ---------------------------------------------------------------------------

# Pre-flight for publish: make sure version isn't already on TestPyPI.
# Bumps to existing versions get rejected by PyPI; this catches the
# common "forgot to bump" case before tagging.
verify-version:
	@echo "==> Checking tn-proto version is fresh on TestPyPI"
	@v=$$($(PYTHON) -c "import tomllib, sys; print(tomllib.load(open('python/pyproject.toml','rb'))['project']['version'])"); \
	  echo "    Local version: $$v"; \
	  if curl -sf "https://test.pypi.org/pypi/tn-proto/$$v/json" >/dev/null; then \
	    echo "    !! Version $$v already on TestPyPI. Bump python/pyproject.toml before publishing."; \
	    exit 1; \
	  else \
	    echo "    OK — $$v is unused on TestPyPI"; \
	  fi

publish-test: check verify-version
	@echo "==> Uploading $(DIST)/ to TestPyPI"
	@echo "    (use TWINE_USERNAME=__token__ and TWINE_PASSWORD=<test-pypi-token>)"
	$(PYTHON) -m twine upload --repository testpypi $(DIST)/*

publish: check
	@echo "==> Uploading $(DIST)/ to PyPI (real, not test)"
	@read -p "About to publish to real PyPI. Type 'yes' to continue: " ans; \
	  [ "$$ans" = "yes" ] || (echo "Aborted."; exit 1)
	$(PYTHON) -m twine upload $(DIST)/*

# ---------------------------------------------------------------------------
# Tooling
# ---------------------------------------------------------------------------

tools:
	@echo "==> Installing build/publish tooling into $(PYTHON)"
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install --upgrade maturin build twine
