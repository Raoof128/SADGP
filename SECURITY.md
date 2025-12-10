# Security Policy

## Supported Versions
This project is educational and synthetic. MITM and interception features must only be run in controlled labs. No production use is supported.

## Reporting a Vulnerability
Please open a private issue describing:
- The potential vulnerability
- Steps to reproduce
- Suggested mitigation

Do not include real credentials or sensitive data in reports. Maintainers will review and respond on a best-effort basis.

## Safe Usage Guidelines
- Never use real secrets or customer data.
- Trust the generated root CA only in isolated test clients.
- Keep dependencies patched and run `pip install -r requirements.txt --upgrade` periodically.
- Disable MITM mode outside lab environments.


