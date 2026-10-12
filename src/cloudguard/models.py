"""Core data model shared by checks, the engine and the reporters."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from None

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class CheckMeta:
    """Static description of a check: what it looks for and how it maps to frameworks."""

    id: str
    title: str
    description: str
    severity: Severity
    provider: str
    service: str
    cis: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    remediation: str = ""


@dataclass(frozen=True)
class Hit:
    """What a check function yields for each offending resource."""

    resource_id: str
    resource_name: str
    message: str


@dataclass(frozen=True)
class Finding:
    """A Hit enriched with its check's metadata. This is what reporters consume."""

    check_id: str
    title: str
    severity: Severity
    provider: str
    service: str
    resource_id: str
    resource_name: str
    message: str
    cis: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    remediation: str = ""
    # Set when the resource comes from source code (Terraform) rather than a live account.
    file: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = str(self.severity)
        data["cis"] = list(self.cis)
        data["mitre"] = list(self.mitre)
        if self.file is None:
            data.pop("file")
            data.pop("line")
        return data


@dataclass
class Inventory:
    """A snapshot of cloud resources, as plain dicts, keyed by resource kind.

    Checks only ever read an Inventory, never call a cloud API. That keeps them
    unit-testable offline and lets a scan be replayed from a saved snapshot.

    A resource dict may carry a reserved ``_source`` key, ``{"file": ..., "line": ...}``,
    set when the resource was read from Terraform. The engine copies it onto findings.
    """

    provider: str
    scope: str
    resources: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def get(self, kind: str) -> list[dict[str, Any]]:
        return self.resources.get(kind) or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "scope": self.scope,
            "warnings": self.warnings,
            "resources": self.resources,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Inventory:
        try:
            return cls(
                provider=data["provider"],
                scope=data.get("scope", ""),
                resources=data.get("resources", {}),
                warnings=list(data.get("warnings", [])),
            )
        except KeyError as exc:
            raise ValueError(f"inventory is missing required key {exc}") from None

    @classmethod
    def load(cls, path: str | Path) -> Inventory:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def save(self, path: str | Path) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, default=str)
