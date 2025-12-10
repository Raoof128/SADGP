PY ?= python
PIP ?= pip

.PHONY: install install-dev lint format test demo mitm dashboard

install:
	$(PIP) install -r requirements.txt

install-dev: install
	$(PIP) install -r dev-requirements.txt

lint:
	ruff check proxy tests
	black --check proxy tests
	isort --check-only proxy tests

format:
	ruff check --fix proxy tests
	black proxy tests
	isort proxy tests

test:
	PYTHONPATH=. pytest tests

demo:
	$(PY) -m proxy.main --demo

mitm:
	$(PY) -m proxy.main --mitm --listen 0.0.0.0:8899

dashboard:
	cd dashboard && npm install && npm run dev

