# Contributing Guidelines

Thanks for your interest in improving the Shadow AI Discovery & Governance Proxy. This project is educational and uses only synthetic data. Please follow these guidelines to keep the codebase consistent and safe.

## How to contribute
1. Fork the repo and create a feature branch from `main`.
2. Keep changes focused and small; one feature or fix per PR.
3. Add or update tests (pytest) for any new logic.
4. Run `pytest` and ensure linting/formatting passes.
5. Update documentation when behavior or APIs change.

## Code style
- Python: PEP8, type hints everywhere, docstrings for all public classes/functions.
- JavaScript/React: keep components small, prefer functional components with hooks.
- No secrets or real data; only synthetic examples are allowed.

## Commit messages
- Use clear, descriptive messages. Example: `feat: add masking mode to redactor`.

## Security and safety
- Do not include real credentials, tokens, or production endpoints.
- MITM features must remain opt-in and synthetic-only.

## Reporting issues
- Open an issue with reproduction steps, expected vs actual behavior, and environment details.

## Pull request checklist
- [ ] Tests added/updated
- [ ] Docs updated (README/ARCHITECTURE/API)
- [ ] No real data introduced
- [ ] Lint/format passes


