from __future__ import annotations
from typing import Callable, Optional
from ..models import VulnRecord, Patch
from . import cwe_457, cwe_476, cwe_563, cwe_401, cwe_190

FixerFn = Callable[[VulnRecord, str], Optional[Patch]]

REGISTRY: dict[str, FixerFn] = {
    "CWE-457": cwe_457.fix,
    "CWE-476": cwe_476.fix,
    "CWE-563": cwe_563.fix,
    "CWE-401": cwe_401.fix,
    "CWE-190": cwe_190.fix,
}


def get_fixer(cwe: str) -> Optional[FixerFn]:
    return REGISTRY.get(cwe)


def supports(cwe: str) -> bool:
    return cwe in REGISTRY
