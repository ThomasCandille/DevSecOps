.PHONY: check test clean

check:
	./scan.sh --check

test:
	python3 -m unittest discover -s tests -p 'test_*.py'

clean:
	find scripts tests -type d -name __pycache__ -prune -exec rm -rf {} +
	find scripts tests -type f -name '*.pyc' -delete
