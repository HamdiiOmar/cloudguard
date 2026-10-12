"""Read Terraform (.tf) files into CloudGuard inventories.

Instead of asking a live cloud account what is configured, this reads what the code *declares*
and converts it to the same inventory shape the collectors produce, so every existing check
runs unchanged. Findings point at the resource's file and line.

Design rules:

* **Unknown is never guessed.** A value that is a variable, a function call or any other
  expression is treated as unknown and left out, so checks skip it rather than report a
  false finding. Only literal values count as evidence.
* **Absent means the documented default** only where that default is stable across provider
  versions (for example an S3 bucket with no versioning configuration is unversioned, and an
  Azure storage account with no ``network_rules`` block allows all networks).

Supported resources:
  AWS    aws_s3_bucket (+ _public_access_block, _acl, _versioning, account-level block),
         aws_security_group (+ aws_security_group_rule, aws_vpc_security_group_ingress_rule),
         aws_iam_policy, aws_iam_role_policy, aws_iam_user_policy, aws_iam_group_policy
         (policy as a JSON heredoc, or jsonencode() of literal values)
  Azure  azurerm_storage_account (+ azurerm_storage_account_network_rules),
         azurerm_network_security_group (+ azurerm_network_security_rule)

Known limitations: ``data.aws_iam_policy_document`` is not evaluated, modules are not
followed (a warning names each one), ``dynamic`` blocks,
``count`` and ``for_each`` are not expanded, variables are not resolved, and ``.tf.json``
files are not read. Line numbers point at the ``resource`` block header.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cloudguard.models import Inventory

SUPPORTED_TYPES = (
    "aws_s3_bucket",
    "aws_security_group",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
    "azurerm_storage_account",
    "azurerm_network_security_group",
)

_MISSING = object()
_UNKNOWN = object()
_SKIP_DIRS = {".terraform", ".git", "node_modules"}
# Matches `resource "type" "name"` and also the unquoted forms Terraform accepts.
_HEADER = re.compile(r'^[ \t]*resource[ \t]+"?([^\s"]+)"?[ \t]+"?([^\s"{]+)"?', re.MULTILINE)

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_CANNED_ACLS = {
    "public-read": [(_ALL_USERS, "READ")],
    "public-read-write": [(_ALL_USERS, "READ"), (_ALL_USERS, "WRITE")],
    "authenticated-read": [(_AUTH_USERS, "READ")],
}
_BPA_KEYS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)
_PROTOCOL_NUMBERS = {"6": "tcp", "17": "udp", "1": "icmp"}
_DEFAULT_NSG_PRIORITY = 65000


@dataclass
class _Resource:
    type: str
    name: str
    body: dict[str, Any]
    file: str  # POSIX path relative to the scan root
    line: int
    directory: str  # POSIX directory relative to the scan root; "" for the root

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"

    @property
    def ident(self) -> str:
        return f"{self.directory}/{self.address}" if self.directory else self.address

    @property
    def source(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line}


# ---------------------------------------------------------------- value helpers


def _is_expr(value: Any) -> bool:
    return isinstance(value, str) and "${" in value


def _as_bool(value: Any) -> bool | None:
    """True/False for a literal boolean (or "true"/"false"), None for anything else."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


def _literal_str(value: Any) -> str | None:
    """A literal string (or number written as one), or None if absent or an expression."""
    if isinstance(value, bool) or value is None or _is_expr(value):
        return None
    if isinstance(value, (str, int)):
        return str(value)
    return None


def _str_list(value: Any) -> list[str]:
    """Literal string elements of a list (or a single string). Expressions are dropped."""
    items = value if isinstance(value, list) else [value]
    return [s for s in (_literal_str(v) for v in items) if s is not None]


def _blocks(body: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = body.get(name)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [b for b in value if isinstance(b, dict)]
    return []


def _refers_to(value: Any, target: _Resource, literal_name: str | None = None) -> bool:
    """Does an attribute value point at ``target``? Matches ``type.name`` inside an
    expression, or (for S3) the bucket's literal name."""
    if not isinstance(value, str):
        return False
    if re.search(rf"\b{re.escape(target.type)}\.{re.escape(target.name)}\b", value):
        return True
    return literal_name is not None and not _is_expr(value) and value == literal_name


# ----------------------------------------------------------------------- AWS


def _bpa_setting(body: dict[str, Any], key: str) -> bool:
    """Absent means off. An expression is assumed on, so unknown never causes a finding."""
    if key not in body:
        return False
    parsed = _as_bool(body[key])
    return True if parsed is None else parsed


def _acl_grants(bucket: _Resource, acl_resources: list[_Resource]) -> Any:
    values = [bucket.body.get("acl", _MISSING)]
    values += [r.body.get("acl", _MISSING) for r in acl_resources]
    grants: list[tuple[str, str]] = []
    for value in values:
        if value is _MISSING:
            continue
        if _literal_str(value) is None:
            return _UNKNOWN
        grants.extend(_CANNED_ACLS.get(value, []))
    return [{"grantee_uri": uri, "permission": perm} for uri, perm in dict.fromkeys(grants)]


def _versioning(bucket: _Resource, versioning_resources: list[_Resource]) -> Any:
    for res in versioning_resources:
        configs = _blocks(res.body, "versioning_configuration")
        status = _literal_str(configs[0].get("status")) if configs else None
        return status.capitalize() if status else _UNKNOWN
    inline = _blocks(bucket.body, "versioning")
    if inline:
        enabled = _as_bool(inline[0].get("enabled", False))
        if enabled is None:
            return _UNKNOWN
        return "Enabled" if enabled else "Disabled"
    return "Disabled"


def _s3_buckets(resources: list[_Resource], account_bpa: dict[str, bool] | None) -> list[dict]:
    items = []
    for bucket in (r for r in resources if r.type == "aws_s3_bucket"):
        literal = _literal_str(bucket.body.get("bucket"))

        def related(rtype: str, bucket=bucket, literal=literal) -> list[_Resource]:
            return [
                r
                for r in resources
                if r.type == rtype and _refers_to(r.body.get("bucket"), bucket, literal)
            ]

        item: dict[str, Any] = {"id": bucket.ident, "name": bucket.ident, "_source": bucket.source}

        block = related("aws_s3_bucket_public_access_block")
        if block:
            item["public_access_block"] = {k: _bpa_setting(block[0].body, k) for k in _BPA_KEYS}
        else:
            item["public_access_block"] = account_bpa

        grants = _acl_grants(bucket, related("aws_s3_bucket_acl"))
        if grants is not _UNKNOWN:
            item["acl_grants"] = grants

        status = _versioning(bucket, related("aws_s3_bucket_versioning"))
        if status is not _UNKNOWN:
            item["versioning"] = status

        items.append(item)
    return items


def _ingress_rule(
    body: dict[str, Any], *, protocol_key: str, v4_key: str, v6_key: str
) -> dict[str, Any] | None:
    protocol = _literal_str(body.get(protocol_key))
    if protocol is None:
        return None
    return {
        "protocol": _PROTOCOL_NUMBERS.get(protocol.lower(), protocol.lower()),
        "from_port": _as_int(body.get("from_port")),
        "to_port": _as_int(body.get("to_port")),
        "ipv4_ranges": _str_list(body.get(v4_key)),
        "ipv6_ranges": _str_list(body.get(v6_key)),
    }


def _security_groups(resources: list[_Resource]) -> list[dict]:
    sgs = [r for r in resources if r.type == "aws_security_group"]
    groups: dict[str, dict[str, Any]] = {}
    for sg in sgs:
        ingress = [
            rule
            for block in _blocks(sg.body, "ingress")
            if (
                rule := _ingress_rule(
                    block, protocol_key="protocol", v4_key="cidr_blocks", v6_key="ipv6_cidr_blocks"
                )
            )
        ]
        groups[sg.address] = _group_item(sg, ingress)

    for res in resources:
        if res.type == "aws_security_group_rule":
            if _literal_str(res.body.get("type")) != "ingress":
                continue
            rule = _ingress_rule(
                res.body, protocol_key="protocol", v4_key="cidr_blocks", v6_key="ipv6_cidr_blocks"
            )
        elif res.type == "aws_vpc_security_group_ingress_rule":
            rule = _ingress_rule(
                res.body, protocol_key="ip_protocol", v4_key="cidr_ipv4", v6_key="cidr_ipv6"
            )
        else:
            continue
        if rule is None:
            continue
        owner = next((s for s in sgs if _refers_to(res.body.get("security_group_id"), s)), None)
        if owner is not None:
            groups[owner.address]["ingress"].append(rule)
        else:  # the group lives elsewhere (module, data source): report at the rule itself
            groups[res.address] = _group_item(res, [rule])
    return list(groups.values())


def _group_item(res: _Resource, ingress: list[dict]) -> dict[str, Any]:
    return {
        "id": res.ident,
        "group_id": res.ident,
        "name": res.ident,
        "region": None,
        "vpc_id": None,
        "ingress": ingress,
        "_source": res.source,
    }


_IAM_POLICY_TYPES = (
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
)
_HEREDOC = re.compile(r"^<<-?\s*(\w+)\n(.*)\n\s*\1\s*$", re.DOTALL)
_JSONENCODE = re.compile(r"^\$\{\s*jsonencode\((.*)\)\s*\}$", re.DOTALL)
_BARE = re.compile(r"[A-Za-z_][\w.\-\[\]*]*")


def _hcl_object_to_json(text: str) -> str:
    """Convert the literal part of an HCL object expression to JSON text.

    ``key = value`` becomes ``"key": value`` (outside strings only) and a bare reference such
    as ``aws_s3_bucket.x.arn`` becomes the string "<unknown>". Anything more exotic (function
    calls, conditionals, interpolation) makes ``json.loads`` fail, which the caller treats as
    unknown.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif ch == "=" and text[i : i + 2] != "==":
            out.append(":")
            i += 1
        elif ch.isalpha() or ch == "_":
            m = _BARE.match(text, i)
            word = m.group(0)
            i = m.end()
            rest = text[i:].lstrip()
            if rest.startswith("=") and not rest.startswith("=="):
                out.append(json.dumps(word))  # object key
            elif word in ("true", "false", "null"):
                out.append(word)
            else:
                out.append('"<unknown>"')
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _policy_document(value: Any) -> Any:
    """The parsed policy JSON, or _UNKNOWN when it is not a readable literal."""
    if not isinstance(value, str):
        return _UNKNOWN
    text = value.strip()
    try:
        heredoc = _HEREDOC.match(text)
        if heredoc:
            return json.loads(heredoc.group(2))
        encoded = _JSONENCODE.match(text)
        if encoded:
            return json.loads(_hcl_object_to_json(encoded.group(1)))
        if not _is_expr(text):
            return json.loads(text)
    except ValueError:
        pass
    return _UNKNOWN


def _iam_policies(resources: list[_Resource], warnings: list[str]) -> list[dict]:
    items = []
    for res in (r for r in resources if r.type in _IAM_POLICY_TYPES):
        document = _policy_document(res.body.get("policy"))
        if document is _UNKNOWN:
            warnings.append(f"{res.ident}: policy is not a literal JSON document; skipped")
            continue
        items.append(
            {"id": res.ident, "name": res.ident, "document": document, "_source": res.source}
        )
    return items


# --------------------------------------------------------------------- Azure


def _first_known_bool(body: dict[str, Any], *keys: str) -> bool | None:
    for key in keys:
        if key in body:
            parsed = _as_bool(body[key])
            if parsed is not None:
                return parsed
    return None


def _storage_accounts(resources: list[_Resource]) -> list[dict]:
    items = []
    for sa in (r for r in resources if r.type == "azurerm_storage_account"):
        item: dict[str, Any] = {"id": sa.ident, "name": sa.ident, "_source": sa.source}

        public = _first_known_bool(
            sa.body, "allow_nested_items_to_be_public", "allow_blob_public_access"
        )
        if public is not None:
            item["allow_blob_public_access"] = public

        https_only = _first_known_bool(
            sa.body, "https_traffic_only_enabled", "enable_https_traffic_only"
        )
        if https_only is not None:
            item["enable_https_traffic_only"] = https_only

        tls = _literal_str(sa.body.get("min_tls_version"))
        if tls:
            item["minimum_tls_version"] = tls

        # Firewall rules can be an inline block or a separate azurerm_storage_account_network_rules
        # resource that points back at the account.
        separate = [
            r
            for r in resources
            if r.type == "azurerm_storage_account_network_rules"
            and (
                _refers_to(r.body.get("storage_account_id"), sa)
                or _refers_to(r.body.get("storage_account_name"), sa)
            )
        ]
        inline = _blocks(sa.body, "network_rules")
        if separate or inline:
            rules = separate[0].body if separate else inline[0]
            action = _literal_str(rules.get("default_action"))
            if action:
                item["network_rule_set"] = {"default_action": action}
        else:
            item["network_rule_set"] = {"default_action": "Allow"}  # the documented default

        items.append(item)
    return items


def _nsg_rule(body: dict[str, Any]) -> dict[str, Any] | None:
    name = _literal_str(body.get("name"))
    direction = _literal_str(body.get("direction"))
    access = _literal_str(body.get("access"))
    protocol = _literal_str(body.get("protocol"))
    if None in (direction, access, protocol):
        return None
    rule: dict[str, Any] = {
        "name": name or "?",
        "priority": _as_int(body.get("priority")) or _DEFAULT_NSG_PRIORITY,
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "source_address_prefixes": _str_list(body.get("source_address_prefixes")),
        "destination_port_ranges": _str_list(body.get("destination_port_ranges")),
    }
    source = _literal_str(body.get("source_address_prefix"))
    if source:
        rule["source_address_prefix"] = source
    port = _literal_str(body.get("destination_port_range"))
    if port:
        rule["destination_port_range"] = port
    return rule


def _network_security_groups(resources: list[_Resource]) -> list[dict]:
    nsgs = [r for r in resources if r.type == "azurerm_network_security_group"]
    groups: dict[str, dict[str, Any]] = {}
    for nsg in nsgs:
        rules = [r for b in _blocks(nsg.body, "security_rule") if (r := _nsg_rule(b))]
        groups[nsg.address] = _nsg_item(nsg, rules)

    for res in (r for r in resources if r.type == "azurerm_network_security_rule"):
        rule = _nsg_rule(res.body)
        if rule is None:
            continue
        owner = next(
            (n for n in nsgs if _refers_to(res.body.get("network_security_group_name"), n)), None
        )
        if owner is not None:
            groups[owner.address]["security_rules"].append(rule)
        else:
            groups[res.address] = _nsg_item(res, [rule])
    return list(groups.values())


def _nsg_item(res: _Resource, rules: list[dict]) -> dict[str, Any]:
    return {"id": res.ident, "name": res.ident, "security_rules": rules, "_source": res.source}


# ------------------------------------------------------------------- loading


def _load_hcl():
    try:
        import hcl2
        from hcl2 import SerializationOptions
    except ImportError as exc:
        raise RuntimeError(
            'python-hcl2 is not installed. Run: pip install "cloudguard-cspm[iac]"'
        ) from exc
    options = SerializationOptions(strip_string_quotes=True)
    return lambda text: hcl2.loads(text, serialization_options=options)


def _find_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(
        p
        for p in root.rglob("*.tf")
        if not set(p.relative_to(root).parts[:-1]) & _SKIP_DIRS
    )


def _read_file(
    path: Path, base: Path, parse: Any, warnings: list[str]
) -> tuple[list[_Resource], list[str]]:
    rel = path.relative_to(base).as_posix()
    directory = Path(rel).parent.as_posix()
    directory = "" if directory == "." else directory
    try:
        text = path.read_text(encoding="utf-8")
        document = parse(text)
    except Exception as exc:  # the parser raises assorted lark errors
        warnings.append(f"{rel}: could not be parsed ({type(exc).__name__}); file skipped")
        return [], []

    lines: dict[tuple[str, str], int] = {}
    for match in _HEADER.finditer(text):
        lines.setdefault(
            (match.group(1), match.group(2)), text.count("\n", 0, match.start()) + 1
        )

    resources: list[_Resource] = []
    for block in document.get("resource", []):
        for rtype, instances in block.items():
            if rtype.startswith("__") or not isinstance(instances, dict):
                continue
            for rname, body in instances.items():
                if rname.startswith("__") or not isinstance(body, dict):
                    continue
                resources.append(
                    _Resource(rtype, rname, body, rel, lines.get((rtype, rname), 1), directory)
                )

    modules = []
    for block in document.get("module", []):
        for mname, mbody in block.items():
            if not mname.startswith("__") and isinstance(mbody, dict):
                modules.append(
                    f"{rel}: module '{mname}' is not followed; "
                    "resources inside it were not scanned"
                )
    return resources, modules


def load_inventories(path: str | Path) -> list[Inventory]:
    """Read a .tf file or a directory tree and return one Inventory per cloud provider found."""
    root = Path(path)
    if not root.exists():
        raise ValueError(f"path not found: {path}")
    files = _find_files(root)
    if not files:
        raise ValueError(f"no .tf files found in {path}")

    parse = _load_hcl()
    base = root.parent if root.is_file() else root
    warnings: list[str] = []
    all_resources: list[_Resource] = []
    for file in files:
        resources, module_warnings = _read_file(file, base, parse, warnings)
        all_resources.extend(resources)
        warnings.extend(module_warnings)

    for res in all_resources:
        if res.type in SUPPORTED_TYPES and "dynamic" in res.body:
            warnings.append(f"{res.ident}: dynamic blocks are not evaluated")

    account_blocks = [r for r in all_resources if r.type == "aws_s3_account_public_access_block"]
    account_bpa = (
        {k: _bpa_setting(account_blocks[0].body, k) for k in _BPA_KEYS} if account_blocks else None
    )

    by_directory: dict[str, list[_Resource]] = defaultdict(list)
    for res in all_resources:
        by_directory[res.directory].append(res)

    aws: dict[str, list] = {"s3_buckets": [], "security_groups": [], "iam_policies": []}
    azure: dict[str, list] = {"storage_accounts": [], "network_security_groups": []}
    for directory in sorted(by_directory):
        group = by_directory[directory]
        aws["s3_buckets"] += _s3_buckets(group, account_bpa)
        aws["security_groups"] += _security_groups(group)
        aws["iam_policies"] += _iam_policies(group, warnings)
        azure["storage_accounts"] += _storage_accounts(group)
        azure["network_security_groups"] += _network_security_groups(group)

    scope = str(path)
    inventories = [
        Inventory(provider=provider, scope=scope, resources=resources)
        for provider, resources in (("aws", aws), ("azure", azure))
        if any(resources.values())
    ]
    if not inventories:
        detail = f" ({'; '.join(warnings)})" if warnings else ""
        raise ValueError(
            f"no supported resources found in {path}{detail}. Supported: "
            + ", ".join(SUPPORTED_TYPES)
        )
    inventories[0].warnings.extend(warnings)
    return inventories
