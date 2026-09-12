# Contributing

Contributions are welcome. Keep changes focused, add tests for parser/classification logic, and document new traffic signatures with evidence.

Development setup:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install -U pip
pip install -e ".[dev]"
pytest -q
```

Do not submit packet captures containing third-party private data or secrets.
