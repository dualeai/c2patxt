name ?= c2patxt
python_version ?= 3.10 # Lowest compatible version (see pyproject.toml requires-python)
version_full ?= $(shell $(MAKE) --silent version-full)
version_small ?= $(shell $(MAKE) --silent version)

vectors_dir := tests/vectors

version:
	@bash ./cicd/version.sh -g . -c

version-full:
	@bash ./cicd/version.sh -g . -c -m

version-pypi:
	@bash ./cicd/version.sh -g .

install:
	uv venv --python $(python_version) --allow-existing
	$(MAKE) install-deps

install-deps:
	uv sync --extra dev

upgrade:
	uv lock --upgrade --refresh

test:
	$(MAKE) test-static
	$(MAKE) test-func

test-static:
	uv run ruff format --check .
	uv run ruff check .
	uv run pyright .
	uv run -m vulture

# Every test except the benchmarks. Selection is by DIRECTORY, not by marker -- see
# CONTRIBUTING.md for why.
test-func:
	uv run pytest tests/ -v -n auto --ignore=tests/benchmarks

# CodSpeed owns CPU and memory measurements. Run serially without coverage or the
# functional-suite addopts; codspeed.yml also clears PYTEST_ADDOPTS.
test-bench:
	uv run pytest tests/benchmarks/ --codspeed -v --no-cov -p no:xdist -o "addopts=" --disable-socket

# Fix what can be fixed, then run the full static gate: all four steps, because a
# contributor is told this target IS the gate.
lint:
	uv run ruff format .
	uv run ruff check --fix .
	uv run pyright .
	uv run -m vulture

# --- Test vectors -------------------------------------------------------------
# Vectors are COMMITTED, not fetched at test time; the suite runs offline.
# These targets refresh them from upstream. Pattern follows hpke-http.

download-vectors:
	$(MAKE) download-vectors-cose
	$(MAKE) download-vectors-cbor

# COSE_Sign1 examples from the COSE working group. Unlicense (public domain).
# eddsa-* cover Ed25519 and the forbidden Ed448 case. sign1-tests/ covers ES256
# Sig_structure encodings; package-owned tests provide the C2PA x5chain and detached
# payload needed for full signature validation.
# sign1-tests/ adds three passing and six FAILING cases, flattened to sign-pass-* and
# sign-fail-* on disk. See tests/vectors/cose/PROVENANCE.md.
download-vectors-cose:
	@echo "Downloading COSE_Sign1 vectors (cose-wg/Examples, Unlicense)..."
	@mkdir -p $(vectors_dir)/cose
	@for f in eddsa-examples/eddsa-01 eddsa-examples/eddsa-sig-01 eddsa-examples/eddsa-sig-02 \
	          sign1-tests/sign-pass-01 sign1-tests/sign-pass-02 sign1-tests/sign-pass-03 \
	          sign1-tests/sign-fail-01 sign1-tests/sign-fail-02 sign1-tests/sign-fail-03 \
	          sign1-tests/sign-fail-04 sign1-tests/sign-fail-06 sign1-tests/sign-fail-07; do \
	  curl -sSfL "https://raw.githubusercontent.com/cose-wg/Examples/53c9d634333bb4f529d78f5980fffa2667ee2c12/$$f.json" \
	    -o "$(vectors_dir)/cose/$$(basename $$f).json"; \
	done
	@echo "  $$(ls $(vectors_dir)/cose/*.json | wc -l | tr -d ' ') COSE vector file(s)"

# RFC 8949 Appendix A, from the CBOR working group. BSD-2-Clause.
# NOT cbor/test-vectors: unmaintained since 2019 and shipping no licence at all.
download-vectors-cbor:
	@echo "Downloading CBOR vectors (cbor-wg/cbor-test-vectors, BSD-2-Clause)..."
	@mkdir -p $(vectors_dir)/cbor
	@for m in 0 1 2 3 4 5 6 7-float 7-simple; do \
	  curl -sSfL "https://raw.githubusercontent.com/cbor-wg/cbor-test-vectors/001eb6848a4014f8ba81cd16a3d9381138ca7da6/tests/rfc8949-appendixA/mt$$m.cbor" \
	    -o "$(vectors_dir)/cbor/mt$$m.cbor"; \
	  curl -sSfL "https://raw.githubusercontent.com/cbor-wg/cbor-test-vectors/001eb6848a4014f8ba81cd16a3d9381138ca7da6/tests/rfc8949-appendixA/mt$$m.edn" \
	    -o "$(vectors_dir)/cbor/mt$$m.edn"; \
	done
	@for f in rfc8949/bad rfc8949-appendixA/streaming; do \
	  curl -sSfL "https://raw.githubusercontent.com/cbor-wg/cbor-test-vectors/001eb6848a4014f8ba81cd16a3d9381138ca7da6/tests/$$f.cbor" \
	    -o "$(vectors_dir)/cbor/$$(basename $$f).cbor"; \
	  curl -sSfL "https://raw.githubusercontent.com/cbor-wg/cbor-test-vectors/001eb6848a4014f8ba81cd16a3d9381138ca7da6/tests/$$f.edn" \
	    -o "$(vectors_dir)/cbor/$$(basename $$f).edn"; \
	done
	@echo "  $$(ls $(vectors_dir)/cbor/mt*.cbor | wc -l | tr -d ' ') CBOR major-type file(s), plus bad and streaming"
