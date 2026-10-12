import json

from cloudguard.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main


def test_list_checks(capsys):
    assert main(["list-checks"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "CG-AZ-STG-001" in out
    assert "CG-AZ-NET-002" in out


def test_scan_offline_console(sample_path, capsys):
    assert main(["scan", "--inventory", sample_path]) == EXIT_OK
    assert "Findings: 6" in capsys.readouterr().out


def test_scan_aws_inventory_offline(capsys):
    from conftest import SAMPLE_AWS

    assert main(["scan", "--inventory", str(SAMPLE_AWS), "--fail-on", "critical"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "aws / 123456789012" in out
    assert "CG-AWS-EC2-003" in out


def test_scan_terraform_example(capsys):
    from conftest import EXAMPLES

    code = main(["scan", "--iac", str(EXAMPLES / "terraform"), "--fail-on", "critical"])
    assert code == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "aws+azure" in out
    assert "Findings: 13" in out
    assert "at aws.tf:8" in out


def test_iac_and_inventory_are_mutually_exclusive(sample_path, capsys):
    from conftest import EXAMPLES

    code = main(["scan", "--iac", str(EXAMPLES / "terraform"), "--inventory", sample_path])
    assert code == EXIT_ERROR
    assert "not both" in capsys.readouterr().err


def test_iac_rejects_save_inventory(capsys):
    from conftest import EXAMPLES

    code = main(["scan", "--iac", str(EXAMPLES / "terraform"), "--save-inventory", "x.json"])
    assert code == EXIT_ERROR


def test_iac_on_missing_path_is_a_clean_error(capsys):
    assert main(["scan", "--iac", "/nonexistent/dir"]) == EXIT_ERROR
    assert "path not found" in capsys.readouterr().err


def test_list_checks_can_filter_by_provider(capsys):
    assert main(["list-checks", "--provider", "aws"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "CG-AWS-S3-001" in out
    assert "CG-AZ-" not in out


def test_fail_on_high_returns_findings_code(sample_path):
    assert main(["scan", "--inventory", sample_path, "--fail-on", "high"]) == EXIT_FINDINGS


def test_fail_on_critical_passes_when_nothing_critical(sample_path):
    assert main(["scan", "--inventory", sample_path, "--fail-on", "critical"]) == EXIT_OK


def test_sarif_to_file(sample_path, tmp_path):
    out = tmp_path / "results.sarif"
    code = main(["scan", "--inventory", sample_path, "--format", "sarif", "-o", str(out)])
    assert code == EXIT_OK
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_missing_subscription_is_a_clean_error(monkeypatch, capsys):
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    assert main(["scan"]) == EXIT_ERROR
    assert "subscription" in capsys.readouterr().err.lower()


def test_bad_severity_is_a_clean_error(sample_path, capsys):
    assert main(["scan", "--inventory", sample_path, "--fail-on", "urgent"]) == EXIT_ERROR
    assert "unknown severity" in capsys.readouterr().err


def test_missing_inventory_file_is_a_clean_error(capsys):
    assert main(["scan", "--inventory", "/nonexistent/inv.json"]) == EXIT_ERROR
    assert "error:" in capsys.readouterr().err
