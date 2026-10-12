import json
import textwrap

import pytest

from cloudguard.engine import merge_results, run_scan
from cloudguard.iac.terraform import load_inventories

BPA_ALL = """
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
"""


def write(tmp_path, text, name="main.tf"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))
    return tmp_path


def scan(path):
    return merge_results([run_scan(inv) for inv in load_inventories(path)])


def flagged(result) -> set[tuple[str, str]]:
    return {(f.check_id, f.resource_name) for f in result.findings}


# ------------------------------------------------------------------ S3


def test_bucket_with_full_public_access_block_resource_is_clean(tmp_path):
    write(
        tmp_path,
        f"""
        resource "aws_s3_bucket" "data" {{
          bucket = "data"
        }}
        resource "aws_s3_bucket_public_access_block" "data" {{
          bucket = aws_s3_bucket.data.id
          {BPA_ALL}
        }}
        resource "aws_s3_bucket_versioning" "data" {{
          bucket = aws_s3_bucket.data.id
          versioning_configuration {{
            status = "Enabled"
          }}
        }}
        """,
    )
    assert flagged(scan(tmp_path)) == set()


def test_bucket_without_block_is_flagged(tmp_path):
    write(tmp_path, 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n')
    assert ("CG-AWS-S3-001", "aws_s3_bucket.data") in flagged(scan(tmp_path))


def test_partial_block_is_flagged(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_s3_bucket" "data" {}
        resource "aws_s3_bucket_public_access_block" "data" {
          bucket             = aws_s3_bucket.data.id
          block_public_acls  = true
        }
        """,
    )
    result = scan(tmp_path)
    finding = next(f for f in result.findings if f.check_id == "CG-AWS-S3-001")
    assert "block_public_policy" in finding.message
    assert "block_public_acls" not in finding.message


def test_block_matched_by_literal_bucket_name(tmp_path):
    write(
        tmp_path,
        f"""
        resource "aws_s3_bucket" "data" {{
          bucket = "my-data"
        }}
        resource "aws_s3_bucket_public_access_block" "other_label" {{
          bucket = "my-data"
          {BPA_ALL}
        }}
        """,
    )
    assert ("CG-AWS-S3-001", "aws_s3_bucket.data") not in flagged(scan(tmp_path))


def test_account_level_block_protects_buckets(tmp_path):
    write(
        tmp_path,
        f"""
        resource "aws_s3_bucket" "data" {{}}
        resource "aws_s3_account_public_access_block" "acct" {{
          {BPA_ALL}
        }}
        """,
    )
    assert ("CG-AWS-S3-001", "aws_s3_bucket.data") not in flagged(scan(tmp_path))


def test_expression_in_block_setting_is_not_a_finding(tmp_path):
    write(
        tmp_path,
        f"""
        resource "aws_s3_bucket" "data" {{}}
        resource "aws_s3_bucket_public_access_block" "data" {{
          bucket             = aws_s3_bucket.data.id
          block_public_acls  = var.strict
          {BPA_ALL.replace("block_public_acls       = true", "")}
        }}
        """,
    )
    assert ("CG-AWS-S3-001", "aws_s3_bucket.data") not in flagged(scan(tmp_path))


@pytest.mark.parametrize("acl", ["public-read", "public-read-write", "authenticated-read"])
def test_inline_public_acl_flagged(tmp_path, acl):
    write(tmp_path, f'resource "aws_s3_bucket" "b" {{\n  acl = "{acl}"\n}}\n')
    assert ("CG-AWS-S3-002", "aws_s3_bucket.b") in flagged(scan(tmp_path))


def test_private_acl_not_flagged(tmp_path):
    write(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n')
    assert ("CG-AWS-S3-002", "aws_s3_bucket.b") not in flagged(scan(tmp_path))


def test_acl_resource_flagged(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_s3_bucket" "b" {}
        resource "aws_s3_bucket_acl" "b" {
          bucket = aws_s3_bucket.b.id
          acl    = "public-read"
        }
        """,
    )
    assert ("CG-AWS-S3-002", "aws_s3_bucket.b") in flagged(scan(tmp_path))


def test_unknown_acl_expression_is_skipped(tmp_path):
    write(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = var.acl\n}\n')
    assert ("CG-AWS-S3-002", "aws_s3_bucket.b") not in flagged(scan(tmp_path))


def test_legacy_inline_versioning(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_s3_bucket" "on" {
          versioning {
            enabled = true
          }
        }
        resource "aws_s3_bucket" "off" {
          versioning {
            enabled = false
          }
        }
        resource "aws_s3_bucket" "unset" {}
        resource "aws_s3_bucket" "unknown" {
          versioning {
            enabled = var.versioned
          }
        }
        """,
    )
    versioning = {n for c, n in flagged(scan(tmp_path)) if c == "CG-AWS-S3-003"}
    assert versioning == {"aws_s3_bucket.off", "aws_s3_bucket.unset"}


def test_versioning_resource_suspended_is_flagged(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_s3_bucket" "b" {}
        resource "aws_s3_bucket_versioning" "b" {
          bucket = aws_s3_bucket.b.id
          versioning_configuration {
            status = "Suspended"
          }
        }
        """,
    )
    assert ("CG-AWS-S3-003", "aws_s3_bucket.b") in flagged(scan(tmp_path))


# ------------------------------------------------------ AWS security groups


def test_inline_ingress_rules(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group" "g" {
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
          }
          ingress {
            from_port        = 3389
            to_port          = 3389
            protocol         = "tcp"
            ipv6_cidr_blocks = ["::/0"]
          }
        }
        """,
    )
    assert flagged(scan(tmp_path)) == {
        ("CG-AWS-EC2-001", "aws_security_group.g"),
        ("CG-AWS-EC2-002", "aws_security_group.g"),
    }


def test_variable_cidr_is_skipped_but_literal_in_same_list_still_counts(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group" "only_var" {
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = [var.admin_cidr]
          }
        }
        resource "aws_security_group" "mixed" {
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = [var.admin_cidr, "0.0.0.0/0"]
          }
        }
        """,
    )
    assert flagged(scan(tmp_path)) == {("CG-AWS-EC2-001", "aws_security_group.mixed")}


def test_unknown_port_is_skipped(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group" "g" {
          ingress {
            from_port   = var.port
            to_port     = var.port
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        """,
    )
    assert flagged(scan(tmp_path)) == set()


def test_protocol_number_six_is_tcp(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group" "g" {
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "6"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        """,
    )
    assert ("CG-AWS-EC2-001", "aws_security_group.g") in flagged(scan(tmp_path))


def test_all_traffic_rule_is_critical(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group" "g" {
          ingress {
            from_port   = 0
            to_port     = 0
            protocol    = "-1"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        """,
    )
    result = scan(tmp_path)
    assert flagged(result) == {("CG-AWS-EC2-003", "aws_security_group.g")}
    assert str(result.findings[0].severity) == "critical"


def test_separate_rule_resource_attaches_to_group(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group" "g" {}
        resource "aws_security_group_rule" "ssh" {
          type              = "ingress"
          security_group_id = aws_security_group.g.id
          from_port         = 22
          to_port           = 22
          protocol          = "tcp"
          cidr_blocks       = ["0.0.0.0/0"]
        }
        resource "aws_security_group_rule" "egress_ignored" {
          type              = "egress"
          security_group_id = aws_security_group.g.id
          from_port         = 22
          to_port           = 22
          protocol          = "tcp"
          cidr_blocks       = ["0.0.0.0/0"]
        }
        """,
    )
    assert flagged(scan(tmp_path)) == {("CG-AWS-EC2-001", "aws_security_group.g")}


def test_rule_for_unknown_group_is_reported_at_the_rule(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group_rule" "ssh" {
          type              = "ingress"
          security_group_id = var.sg_id
          from_port         = 22
          to_port           = 22
          protocol          = "tcp"
          cidr_blocks       = ["0.0.0.0/0"]
        }
        """,
    )
    assert flagged(scan(tmp_path)) == {("CG-AWS-EC2-001", "aws_security_group_rule.ssh")}


def test_vpc_ingress_rule_resource(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group" "g" {}
        resource "aws_vpc_security_group_ingress_rule" "rdp" {
          security_group_id = aws_security_group.g.id
          ip_protocol       = "tcp"
          from_port         = 3389
          to_port           = 3389
          cidr_ipv4         = "0.0.0.0/0"
        }
        """,
    )
    assert flagged(scan(tmp_path)) == {("CG-AWS-EC2-002", "aws_security_group.g")}


# ------------------------------------------------------------------ Azure


def test_storage_account_explicit_insecure_values(tmp_path):
    write(
        tmp_path,
        """
        resource "azurerm_storage_account" "sa" {
          allow_nested_items_to_be_public = true
          https_traffic_only_enabled      = false
          min_tls_version                 = "TLS1_0"
          network_rules {
            default_action = "Allow"
          }
        }
        """,
    )
    assert {c for c, _ in flagged(scan(tmp_path))} == {
        "CG-AZ-STG-001",
        "CG-AZ-STG-002",
        "CG-AZ-STG-003",
        "CG-AZ-STG-004",
    }


def test_storage_account_hardened_is_clean(tmp_path):
    write(
        tmp_path,
        """
        resource "azurerm_storage_account" "sa" {
          allow_nested_items_to_be_public = false
          https_traffic_only_enabled      = true
          min_tls_version                 = "TLS1_2"
          network_rules {
            default_action = "Deny"
          }
        }
        """,
    )
    assert flagged(scan(tmp_path)) == set()


def test_storage_account_unset_values_are_not_guessed_except_network_default(tmp_path):
    write(tmp_path, 'resource "azurerm_storage_account" "sa" {}\n')
    assert flagged(scan(tmp_path)) == {("CG-AZ-STG-004", "azurerm_storage_account.sa")}


def test_storage_account_legacy_attribute_names(tmp_path):
    write(
        tmp_path,
        """
        resource "azurerm_storage_account" "sa" {
          allow_blob_public_access  = true
          enable_https_traffic_only = false
          network_rules {
            default_action = "Deny"
          }
        }
        """,
    )
    assert {c for c, _ in flagged(scan(tmp_path))} == {"CG-AZ-STG-001", "CG-AZ-STG-002"}


def test_storage_account_expressions_are_skipped(tmp_path):
    write(
        tmp_path,
        """
        resource "azurerm_storage_account" "sa" {
          allow_nested_items_to_be_public = var.public
          min_tls_version                 = var.tls
          network_rules {
            default_action = var.action
          }
        }
        """,
    )
    assert flagged(scan(tmp_path)) == set()


@pytest.mark.parametrize(
    "reference",
    ["storage_account_id = azurerm_storage_account.sa.id",
     "storage_account_name = azurerm_storage_account.sa.name"],
)
def test_separate_network_rules_resource_overrides_the_default(tmp_path, reference):
    # Found by running against TerraGoat: a firewall defined in its own resource used to be
    # missed, producing a false "default action is Allow" finding.
    write(
        tmp_path,
        f"""
        resource "azurerm_storage_account" "sa" {{}}
        resource "azurerm_storage_account_network_rules" "sa" {{
          {reference}
          default_action = "Deny"
        }}
        """,
    )
    assert flagged(scan(tmp_path)) == set()


def test_separate_network_rules_resource_with_allow_is_flagged(tmp_path):
    write(
        tmp_path,
        """
        resource "azurerm_storage_account" "sa" {}
        resource "azurerm_storage_account_network_rules" "sa" {
          storage_account_id = azurerm_storage_account.sa.id
          default_action     = "Allow"
        }
        """,
    )
    assert flagged(scan(tmp_path)) == {("CG-AZ-STG-004", "azurerm_storage_account.sa")}


def test_nsg_inline_and_separate_rules(tmp_path):
    write(
        tmp_path,
        """
        resource "azurerm_network_security_group" "web" {
          security_rule {
            name                   = "rdp"
            priority               = 100
            direction              = "Inbound"
            access                 = "Allow"
            protocol               = "Tcp"
            destination_port_range = "3389"
            source_address_prefix  = "*"
          }
        }
        resource "azurerm_network_security_rule" "ssh" {
          name                        = "ssh"
          priority                    = 110
          direction                   = "Inbound"
          access                      = "Allow"
          protocol                    = "Tcp"
          destination_port_ranges     = ["22", "8080"]
          source_address_prefixes     = ["Internet"]
          network_security_group_name = azurerm_network_security_group.web.name
        }
        """,
    )
    assert flagged(scan(tmp_path)) == {
        ("CG-AZ-NET-001", "azurerm_network_security_group.web"),
        ("CG-AZ-NET-002", "azurerm_network_security_group.web"),
    }


def test_nsg_deny_with_lower_priority_number_shadows_allow(tmp_path):
    write(
        tmp_path,
        """
        resource "azurerm_network_security_group" "web" {
          security_rule {
            name                   = "deny"
            priority               = 100
            direction              = "Inbound"
            access                 = "Deny"
            protocol               = "Tcp"
            destination_port_range = "3389"
            source_address_prefix  = "*"
          }
          security_rule {
            name                   = "allow"
            priority               = 200
            direction              = "Inbound"
            access                 = "Allow"
            protocol               = "Tcp"
            destination_port_range = "3389"
            source_address_prefix  = "*"
          }
        }
        """,
    )
    assert flagged(scan(tmp_path)) == set()


def test_nsg_rule_with_variable_source_is_skipped(tmp_path):
    write(
        tmp_path,
        """
        resource "azurerm_network_security_group" "web" {
          security_rule {
            name                   = "rdp"
            priority               = 100
            direction              = "Inbound"
            access                 = "Allow"
            protocol               = "Tcp"
            destination_port_range = "3389"
            source_address_prefix  = var.admin_ip
          }
        }
        """,
    )
    assert flagged(scan(tmp_path)) == set()


# ------------------------------------------------ locations, warnings, errors


def test_findings_carry_file_and_resource_line(tmp_path):
    write(
        tmp_path,
        """
        # a comment

        resource "aws_s3_bucket" "first" {
          acl = "private"
        }

        resource "aws_s3_bucket" "second" {
          acl = "public-read"
        }
        """,
    )
    finding = next(f for f in scan(tmp_path).findings if f.check_id == "CG-AWS-S3-002")
    assert finding.resource_name == "aws_s3_bucket.second"
    assert finding.file == "main.tf"
    assert finding.line == 8


def test_unquoted_resource_header_still_gets_its_line_number(tmp_path):
    # Terraform accepts `resource aws_s3_bucket "x"`; TerraGoat uses it.
    write(
        tmp_path,
        """
        # line 1 is blank, line 2 is this comment
        resource aws_s3_bucket "x" {
          acl = "public-read"
        }
        """,
    )
    finding = next(f for f in scan(tmp_path).findings if f.check_id == "CG-AWS-S3-002")
    assert finding.line == 3


def test_subdirectories_are_scoped_and_prefixed(tmp_path):
    bad = 'resource "aws_s3_bucket" "logs" {\n  acl = "public-read"\n}\n'
    good = 'resource "aws_s3_bucket" "logs" {\n  acl = "private"\n}\n'
    write(tmp_path, bad, "envs/prod/main.tf")
    write(tmp_path, good, "envs/dev/main.tf")
    result = scan(tmp_path)
    public = {(f.resource_name, f.file) for f in result.findings if f.check_id == "CG-AWS-S3-002"}
    assert public == {("envs/prod/aws_s3_bucket.logs", "envs/prod/main.tf")}


def test_same_names_in_different_folders_do_not_cross_reference(tmp_path):
    protected = f"""
        resource "aws_s3_bucket" "logs" {{}}
        resource "aws_s3_bucket_public_access_block" "logs" {{
          bucket = aws_s3_bucket.logs.id
          {BPA_ALL}
        }}
    """
    write(tmp_path, protected, "a/main.tf")
    write(tmp_path, 'resource "aws_s3_bucket" "logs" {}\n', "b/main.tf")
    result = scan(tmp_path)
    names = {f.resource_name for f in result.findings if f.check_id == "CG-AWS-S3-001"}
    assert names == {"b/aws_s3_bucket.logs"}


def test_terraform_cache_directory_is_ignored(tmp_path):
    write(tmp_path, 'resource "aws_s3_bucket" "x" {\n  acl = "public-read"\n}\n', ".terraform/m.tf")
    write(tmp_path, 'resource "aws_s3_bucket" "y" {}\n', "main.tf")
    names = {f.resource_name for f in scan(tmp_path).findings}
    assert not any("aws_s3_bucket.x" in n for n in names)


def test_module_is_reported_not_followed(tmp_path):
    write(
        tmp_path,
        """
        module "network" {
          source = "./modules/network"
        }
        resource "aws_s3_bucket" "b" {}
        """,
    )
    result = scan(tmp_path)
    assert any("module 'network' is not followed" in w for w in result.warnings)


def test_unparsable_file_is_skipped_with_warning(tmp_path):
    write(tmp_path, 'resource "aws_s3_bucket" "ok" {}\n', "good.tf")
    write(tmp_path, 'resource "aws_s3_bucket" "broken" {{{ not hcl\n', "bad.tf")
    result = scan(tmp_path)
    assert any("bad.tf" in w and "could not be parsed" in w for w in result.warnings)
    assert ("CG-AWS-S3-001", "aws_s3_bucket.ok") in flagged(result)


def test_dynamic_blocks_produce_a_warning(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_security_group" "g" {
          dynamic "ingress" {
            for_each = var.ports
            content {
              from_port = ingress.value
            }
          }
        }
        """,
    )
    assert any("dynamic blocks are not evaluated" in w for w in scan(tmp_path).warnings)


def test_single_file_path_works(tmp_path):
    write(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n', "one.tf")
    result = scan(tmp_path / "one.tf")
    assert result.findings[0].file == "one.tf"


def test_errors(tmp_path):
    with pytest.raises(ValueError, match="path not found"):
        load_inventories(tmp_path / "nope")
    with pytest.raises(ValueError, match="no .tf files"):
        load_inventories(tmp_path)
    write(tmp_path, 'resource "google_compute_instance" "vm" {}\n')
    with pytest.raises(ValueError, match="no supported resources"):
        load_inventories(tmp_path)


def test_mixed_providers_are_merged(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_s3_bucket" "b" {
          acl = "public-read"
        }
        resource "azurerm_storage_account" "sa" {
          https_traffic_only_enabled = false
        }
        """,
    )
    result = scan(tmp_path)
    assert result.provider == "aws+azure"
    assert {c for c, _ in flagged(result)} >= {"CG-AWS-S3-002", "CG-AZ-STG-002"}
    assert result.checks_run == 16


def test_sarif_points_at_real_files(tmp_path):
    from cloudguard.reporters import REPORTERS

    write(
        tmp_path,
        """
        resource "aws_s3_bucket" "b" {
          acl = "public-read"
        }
        resource "azurerm_storage_account" "sa" {
          https_traffic_only_enabled = false
        }
        """,
    )
    sarif = json.loads(REPORTERS["sarif"](scan(tmp_path)))
    run = sarif["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {"CG-AWS-S3-001", "CG-AZ-NET-001"}
    result = next(r for r in run["results"] if r["ruleId"] == "CG-AWS-S3-002")
    location = result["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "main.tf"
    assert location["physicalLocation"]["region"]["startLine"] == 2  # after the leading blank line
    assert location["logicalLocations"][0]["fullyQualifiedName"] == "aws_s3_bucket.b"


def test_json_report_includes_file_and_line_only_for_iac(tmp_path, sample_inventory):
    from cloudguard.reporters import REPORTERS

    write(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
    iac = json.loads(REPORTERS["json"](scan(tmp_path)))
    assert iac["findings"][0]["file"] == "main.tf"
    assert iac["findings"][0]["line"] == 1

    live = json.loads(REPORTERS["json"](run_scan(sample_inventory)))
    assert "file" not in live["findings"][0]


# ------------------------------------------------------------------------ IAM policies


def _names(result, check_id) -> set[str]:
    return {name for cid, name in flagged(result) if cid == check_id}



def test_iam_policy_jsonencode_and_heredoc(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_iam_policy" "admin" {
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
          })
        }

        resource "aws_iam_role_policy" "admin_heredoc" {
          role   = "r"
          policy = <<POLICY
        {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*"}]}
        POLICY
        }

        resource "aws_iam_user_policy" "scoped" {
          user   = "u"
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "*" }]
          })
        }
        """,
    )
    result = scan(tmp_path)
    assert _names(result, "CG-AWS-IAM-003") == {
        "aws_iam_policy.admin",
        "aws_iam_role_policy.admin_heredoc",
    }


def test_iam_policy_with_references_keeps_literal_parts(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_iam_policy" "p" {
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [{ Effect = "Allow", Action = "*", Resource = aws_s3_bucket.b.arn }]
          })
        }
        """,
    )
    # The resource is a reference (unknown), so the wildcard-resource check must not fire.
    assert _names(scan(tmp_path), "CG-AWS-IAM-003") == set()


def test_unreadable_iam_policy_is_skipped_with_a_warning(tmp_path):
    write(
        tmp_path,
        """
        resource "aws_iam_policy" "dyn" {
          policy = data.aws_iam_policy_document.doc.json
        }
        resource "aws_s3_bucket" "b" {
          bucket = "x"
        }
        """,
    )
    result = scan(tmp_path)
    assert _names(result, "CG-AWS-IAM-003") == set()
    assert any("aws_iam_policy.dyn" in w for w in result.warnings)
