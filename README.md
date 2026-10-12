# CloudGuard

[![CI](https://github.com/HamdiiOmar/cloudguard/actions/workflows/ci.yml/badge.svg)](https://github.com/HamdiiOmar/cloudguard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A small, testable **multi-cloud security scanner** for **Azure** and **AWS**. CloudGuard
checks cloud configuration against security rules mapped to the **CIS Foundations
Benchmarks** and **MITRE ATT&CK**, and reports findings as console text, JSON or **SARIF**.

It can scan three kinds of input with the same checks:

| Input | Command | Needs a cloud account? |
|-------|---------|------------------------|
| **Terraform code** | `cloudguard scan --iac ./infra` | No |
| **A live AWS account** | `cloudguard scan --provider aws` | Yes (read-only) |
| **A live Azure subscription** | `cloudguard scan --provider azure --subscription-id ...` | Yes (Reader) |

> Status: early alpha (v0.1). 16 checks (6 Azure, 10 AWS). See the [roadmap](#roadmap).

### How it is tested

- Every check has unit tests that run on plain dictionaries, with no cloud account.
- The **Terraform reader** has fixture-based tests, and was also run against the public
  [TerraGoat](https://github.com/bridgecrewio/terragoat) repository (47 `.tf` files). That run
  found two bugs, now fixed and covered by tests.
- The **AWS collector** is tested end to end with real boto3 calls against
  [moto](https://github.com/getmoto/moto), a local simulation of the AWS API.
- The **Azure collector has not been run against a live subscription yet.** Treat live Azure
  scans as unverified. Azure checks are covered by unit tests and by Terraform scanning.

## Why this exists

Commercial CSPM tools are powerful but opaque. CloudGuard is intentionally small so you can
read the whole codebase in an afternoon, and every check is a plain Python function you can
unit test without touching a cloud account.

## Design

```
 Terraform (.tf) ──► IaC reader ─┐
                                 ├──► Inventory (plain dicts, JSON-serialisable)
 Azure SDK / boto3 ─► Collector ─┘            │
                                              ▼
                      Engine ──► registered checks ──► Findings (with file:line for IaC)
                                              │
                                              ▼
                              Reporters: console | json | sarif
```

- **Collection is separated from evaluation.** Checks never call the cloud and never parse
  Terraform; they only read an `Inventory`. That is why one set of checks serves live
  accounts, saved snapshots and Terraform code.
- **Unknown is never guessed.** A Terraform value that is a variable or expression is skipped
  rather than reported, and a cloud setting that cannot be read (AccessDenied) becomes a
  warning, not a false finding.
- **Checks self-register** with a decorator that carries severity, CIS and ATT&CK metadata.
- **One failing check never hides the others.** Errors are collected and reported.

## Quick start

```bash
git clone https://github.com/HamdiiOmar/cloudguard.git
cd cloudguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Everything below works offline, with no cloud account
cloudguard scan --iac examples/terraform                          # Terraform (AWS + Azure)
cloudguard scan --inventory examples/sample_inventory.json        # Azure snapshot
cloudguard scan --inventory examples/sample_inventory_aws.json    # AWS snapshot
```

### Scan Terraform code

```bash
pip install -e ".[iac]"
cloudguard scan --iac ./infra                      # a folder (searched recursively) or one file
cloudguard scan --iac ./infra --format sarif -o results.sarif
cloudguard scan --iac ./infra --fail-on high       # exit 1 so CI can block the pull request
```

Each finding carries the file and line of the `resource` block, for example
`at aws.tf:34`. Supported resources:

| Cloud | Resources read |
|-------|----------------|
| AWS | `aws_s3_bucket` (+ `_public_access_block`, `_acl`, `_versioning`, account-level block), `aws_security_group` (+ `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`), IAM policies (`aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy`; JSON heredoc or `jsonencode()` of literals) |
| Azure | `azurerm_storage_account` (+ `azurerm_storage_account_network_rules`), `azurerm_network_security_group` (+ `azurerm_network_security_rule`) |

Try it on an intentionally vulnerable public project:

```bash
git clone --depth 1 https://github.com/bridgecrewio/terragoat.git
cloudguard scan --iac terragoat/terraform
```

**Terraform limitations.** Modules are not followed (a warning names each one). `dynamic`
blocks, `count` and `for_each` are not expanded, variables are not resolved, and `.tf.json`
files are not read. Line numbers point at the `resource` header, not the exact attribute.

### Try the AWS scanner without an AWS account

[moto](https://github.com/getmoto/moto) simulates the AWS API locally, so you can run the
real collector against a fake account containing deliberate misconfigurations:

```bash
python examples/generate_aws_demo_inventory.py   # builds examples/sample_inventory_aws.json
cloudguard scan --inventory examples/sample_inventory_aws.json
```

### Scan a real AWS account

```bash
pip install -e ".[aws]"
aws configure            # or use SSO / an instance role
cloudguard scan --provider aws --region eu-west-1
cloudguard scan --provider aws --all-regions --profile my-profile
```

Credentials come from the standard boto3 chain. Use read-only permissions (the
`SecurityAudit` managed policy covers every call, including the IAM ones). If a setting cannot be read (AccessDenied), CloudGuard
records a warning and skips that resource instead of reporting a false finding.

### Scan a real Azure subscription

```bash
pip install -e ".[azure]"
az login
cloudguard scan --provider azure --subscription-id <SUBSCRIPTION_ID>
```

Authentication uses `DefaultAzureCredential`. The **Reader** role is sufficient; CloudGuard
only performs read operations.

### Useful options

```bash
cloudguard list-checks [--provider aws]
cloudguard scan --subscription-id <ID> --save-inventory inv.json     # snapshot for replay
cloudguard scan --inventory inv.json --format sarif -o results.sarif
cloudguard scan --inventory inv.json --min-severity high
cloudguard scan --inventory inv.json --skip CG-AZ-STG-003
cloudguard scan --inventory inv.json --fail-on high                  # exit 1 for CI gates
```

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` usage or runtime error.

### Docker

```bash
docker build -t cloudguard .
docker run --rm -v "$PWD/examples:/data" cloudguard scan --iac /data/terraform
```

## Checks

### Azure (CIS Microsoft Azure Foundations v2.0.0)

| ID | Severity | CIS | ATT&CK | What it detects |
|----|----------|-----|--------|-----------------|
| CG-AZ-STG-001 | high | 3.7 | T1530 | Storage account allows public blob access |
| CG-AZ-STG-002 | medium | 3.1 | T1557 | Secure transfer (HTTPS only) not required |
| CG-AZ-STG-003 | medium | 3.15 | T1557 | Minimum TLS version below 1.2 |
| CG-AZ-STG-004 | high | 3.8 | T1530 | Storage firewall default action is Allow |
| CG-AZ-NET-001 | high | 6.1 | T1021.001, T1133 | NSG allows RDP (3389) from the Internet |
| CG-AZ-NET-002 | high | 6.2 | T1021.004, T1133 | NSG allows SSH (22) from the Internet |

### AWS (CIS AWS Foundations v3.0.0)

| ID | Severity | CIS | ATT&CK | What it detects |
|----|----------|-----|--------|-----------------|
| CG-AWS-S3-001 | high | 2.1.4 | T1530 | S3 bucket does not enable all Block Public Access settings |
| CG-AWS-S3-002 | high | - | T1530 | S3 bucket ACL grants access to everyone / any AWS account |
| CG-AWS-S3-003 | low | - | T1485 | S3 bucket versioning is not enabled |
| CG-AWS-EC2-001 | high | 5.2, 5.3 | T1021.004, T1133 | Security group allows SSH (22) from 0.0.0.0/0 or ::/0 |
| CG-AWS-EC2-002 | high | 5.2, 5.3 | T1021.001, T1133 | Security group allows RDP (3389) from 0.0.0.0/0 or ::/0 |
| CG-AWS-EC2-003 | critical | 5.2, 5.3 | T1190, T1133 | Security group allows all traffic from the Internet |
| CG-AWS-IAM-001 | critical | 1.4 | T1078.004 | Root account has active access keys (live only) |
| CG-AWS-IAM-002 | high | 1.10 | T1078.004 | IAM user with console access has no MFA (live only) |
| CG-AWS-IAM-003 | high | 1.16 | T1078.004 | IAM policy allows `Action: *` on `Resource: *` |
| CG-AWS-IAM-004 | medium | 1.14 | T1078.004 | Active access key older than 90 days (live only) |

> The CIS control numbers were written from memory of each benchmark and **must be verified**
> against the exact benchmark version you audit against, since numbering changes between
> releases. A dash means the check has no direct CIS control.

### Known limitations

- Azure NSG evaluation honours rule priority and Deny rules but does not model every service
  tag, application security groups, or subnet-level vs NIC-level NSG layering.
- Azure storage settings left unset are not flagged (to avoid false positives on newer
  accounts where Azure applies secure defaults), except the storage firewall: no firewall
  rules at all means the documented default, which allows all networks.
- AWS S3 checks evaluate bucket-level settings (plus the account-level Block Public Access
  resource in Terraform). Bucket policies are not modelled yet.
- IAM: live scans read customer-managed policies only (inline policies, permission boundaries
  and SCPs are not modelled). Root keys, MFA and key age cannot be seen in Terraform, so those
  three checks run on live accounts and snapshots only. `data.aws_iam_policy_document` is not
  evaluated, and a policy that is not a literal is skipped with a warning.
- AWS security group checks treat only `0.0.0.0/0` and `::/0` as the Internet; other
  security groups and prefix lists are not followed.

## SARIF output and GitHub code scanning

`--format sarif` produces SARIF 2.1.0 with rule metadata, CIS/ATT&CK tags and GitHub's
`security-severity` property.

- **Terraform findings** point at the real file and line, which is what GitHub code scanning
  expects.
- **Live-account findings** have no file, so each result carries a synthetic path derived
  from the resource ID, plus the real resource ID as a logical location.

How GitHub's Security tab displays these results has not been verified with a real upload
yet. A pull-request workflow would look like this (untested):

```yaml
name: CloudGuard
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install "cloudguard-cspm[iac] @ git+https://github.com/HamdiiOmar/cloudguard.git"
      - run: cloudguard scan --iac infra --format sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
```

## Adding a check

```python
from cloudguard.models import Hit, Severity
from cloudguard.registry import check

@check(
    id="CG-AZ-STG-005",
    title="Storage account has no blob soft delete",
    description="...",
    severity=Severity.LOW,
    provider="azure",
    service="storage",
    cis=("3.x",),
    mitre=("T1485",),
    remediation="Enable blob soft delete.",
)
def blob_soft_delete(inventory):
    for account in inventory.get("storage_accounts"):
        if not account.get("blob_soft_delete_enabled"):
            yield Hit(account["id"], account["name"], "Blob soft delete is disabled.")
```

Add the module to `providers/azure/checks/__init__.py`, write a test in `tests/`, and the
check appears in `list-checks` and in every report. If the check needs a new setting, add it
to the collector (live) and to `iac/terraform.py` (Terraform) so both inputs feed it.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

## Roadmap

- [x] AWS provider (S3, security groups), tested against moto
- [x] Terraform scanning with file and line numbers
- [x] AWS IAM checks (root keys, MFA, wildcard policies, key rotation)
- [ ] Verify SARIF upload to GitHub code scanning
- [ ] Validate the Azure collector against a live subscription
- [ ] More checks: CloudTrail, root MFA, Key Vault, SQL, Azure RBAC
- [ ] Terraform modules and variable defaults
- [ ] HTML report
- [ ] Auto-remediation mode (opt-in, dry-run by default)
- [ ] Publish to PyPI

## License

MIT
