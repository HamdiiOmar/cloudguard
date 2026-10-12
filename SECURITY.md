# Security Policy

CloudGuard only performs **read** operations against your cloud account and never
modifies resources. Scan output and saved inventories can contain resource names and IDs,
so treat them as sensitive and do not commit them to a public repository.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's
"Report a vulnerability" button on the Security tab of this repository.

## Recommended permissions

Run scans with the built-in **Reader** role on the target subscription. No write
permissions are needed.
