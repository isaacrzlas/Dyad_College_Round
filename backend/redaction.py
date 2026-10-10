"""Reusable persistence and export redaction for application evidence."""
from __future__ import annotations

import re
from typing import Any, Iterable

REDACTED = "[REDACTED]"
_CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"(?i)\b(api[_-]?key|token|refresh[_-]?token|access[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|password|passwd|credential|secret)\s*[:=]\s*([\"']?)[^\s,;\"']+\2"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
]
_SENSITIVE_KEY_NAMES = {"authorization", "proxy_authorization", "api_key", "apikey", "token", "access_token", "refresh_token", "client_secret", "secret_key", "private_key", "password", "passwd", "credential", "secret", "cookie", "set_cookie"}
_SENSITIVE_KEY_SUFFIXES = ("_api_key", "_apikey", "_token", "_client_secret", "_secret_key", "_private_key", "_password", "_passwd", "_credential", "_secret", "_cookie")


def sensitive_values_from_manifest(manifest: dict[str, Any] | None) -> tuple[list[str], set[str]]:
    manifest = manifest or {}
    settings = manifest.get("redaction", {}) if isinstance(manifest.get("redaction", {}), dict) else {}
    values = list(settings.get("sensitive_values", [])) + list(manifest.get("sensitive_values", []))
    fields = list(settings.get("sensitive_fields", [])) + list(manifest.get("sensitive_fields", []))
    clean_values = sorted({str(value) for value in values if isinstance(value, (str, int, float)) and str(value) and str(value) != REDACTED}, key=len, reverse=True)
    clean_fields = {str(value).casefold() for value in fields if isinstance(value, str)}
    return clean_values, clean_fields


def redact_data(value: Any, *, sensitive_values: Iterable[str] = (), sensitive_fields: Iterable[str] = ()) -> tuple[Any, list[str]]:
    """Redact common credentials, configured literal secrets, and marked fields."""
    values = sorted({str(item) for item in sensitive_values if str(item)}, key=len, reverse=True)
    fields = {str(item).casefold() for item in sensitive_fields}
    locations: list[str] = []

    def redact_string(text: str, path: str) -> str:
        original = text
        for secret in values:
            text = text.replace(secret, REDACTED)
        for pattern in _CREDENTIAL_PATTERNS:
            text = pattern.sub(lambda match: (match.group(1) + "=" + REDACTED) if pattern is _CREDENTIAL_PATTERNS[7] else REDACTED, text)
        if text != original:
            locations.append(path or "$string")
        return text

    def visit(item: Any, path: str) -> Any:
        if isinstance(item, dict):
            clean = {}
            for key, child in item.items():
                key_text = str(key)
                child_path = f"{path}.{key_text}" if path else key_text
                lowered = key_text.casefold().replace("-", "_")
                if lowered in _SENSITIVE_KEY_NAMES or lowered.endswith(_SENSITIVE_KEY_SUFFIXES) or lowered in fields:
                    clean[key] = REDACTED
                    if child not in (None, "", REDACTED):
                        locations.append(child_path)
                else:
                    clean[key] = visit(child, child_path)
            return clean
        if isinstance(item, list):
            return [visit(child, f"{path}[{index}]") for index, child in enumerate(item)]
        if isinstance(item, tuple):
            return [visit(child, f"{path}[{index}]") for index, child in enumerate(item)]
        if isinstance(item, str):
            return redact_string(item, path)
        return item

    return visit(value, ""), locations


def redact_manifest(manifest: dict[str, Any], *, sensitive_values: Iterable[str] = (), sensitive_fields: Iterable[str] = ()) -> tuple[dict[str, Any], list[str]]:
    clean, paths = redact_data(manifest, sensitive_values=sensitive_values, sensitive_fields=sensitive_fields)
    redaction = clean.get("redaction") if isinstance(clean, dict) else None
    if isinstance(redaction, dict) and isinstance(redaction.get("sensitive_values"), list):
        redaction["sensitive_values"] = [REDACTED for _ in redaction["sensitive_values"]]
    if isinstance(clean, dict) and isinstance(clean.get("sensitive_values"), list):
        clean["sensitive_values"] = [REDACTED for _ in clean["sensitive_values"]]
    return clean, paths
