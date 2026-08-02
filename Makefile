.PHONY: all test unit storm syntax clean

PYTHON ?= python3

all: test

test: syntax unit
	@echo "OK: all tests passed"

syntax:
	$(PYTHON) -c "import ast; ast.parse(open('ptrace-ism').read())"
	@echo "OK: syntax"

unit:
	$(PYTHON) tests/test_matcher.py

storm:
	$(PYTHON) -m pytest tests/test_storm_*.py -n 16 -q

clean:
	rm -rf __pycache__ .pytest_cache
	find . -name '*.pyc' -delete
