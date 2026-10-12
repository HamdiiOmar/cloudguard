"""Check registry: checks self-register with the @check decorator."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .models import CheckMeta, Hit, Inventory, Severity

CheckFn = Callable[[Inventory], Iterable[Hit]]


@dataclass(frozen=True)
class RegisteredCheck:
    meta: CheckMeta
    fn: CheckFn


_REGISTRY: dict[str, RegisteredCheck] = {}


def check(
    *,
    id: str,
    title: str,
    description: str,
    severity: Severity,
    provider: str,
    service: str,
    cis: tuple[str, ...] = (),
    mitre: tuple[str, ...] = (),
    remediation: str = "",
) -> Callable[[CheckFn], CheckFn]:
    """Register a function as a check. The function takes an Inventory and yields Hits."""

    def decorator(fn: CheckFn) -> CheckFn:
        if id in _REGISTRY:
            raise ValueError(f"duplicate check id: {id}")
        meta = CheckMeta(
            id=id,
            title=title,
            description=description,
            severity=severity,
            provider=provider,
            service=service,
            cis=cis,
            mitre=mitre,
            remediation=remediation,
        )
        _REGISTRY[id] = RegisteredCheck(meta=meta, fn=fn)
        return fn

    return decorator


def load_provider(provider: str) -> None:
    """Import a provider's checks package so its checks register themselves."""
    try:
        importlib.import_module(f"cloudguard.providers.{provider}.checks")
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("cloudguard.providers"):
            raise ValueError(f"unsupported provider: {provider}") from None
        raise


def all_checks(provider: str | None = None) -> list[RegisteredCheck]:
    checks = [c for c in _REGISTRY.values() if provider is None or c.meta.provider == provider]
    return sorted(checks, key=lambda c: c.meta.id)
