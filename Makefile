.PHONY: test clean run

PYTHON := python3

run:
	$(PYTHON) -m recon_engine.cli --target 127.0.0.1 --scope lab-runtime/scope.csv --output run/ --rate 25

test:
	$(PYTHON) -m pytest tests/ -v

clean:
	rm -rf run/ __pycache__ .pytest_cache
