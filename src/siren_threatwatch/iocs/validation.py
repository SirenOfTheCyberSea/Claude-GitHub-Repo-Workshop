"""Indicator of Compromise (IOC) parsing, re-fanging, validation and safe display.

All functions here are pure string processing. **Nothing in this module ever resolves, connects to
or visits an indicator.**
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit


class IocType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"


HASH_LENGTHS: dict[IocType, int] = {
    IocType.MD5: 32,
    IocType.SHA1: 40,
    IocType.SHA256: 64,
    IocType.SHA512: 128,
}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_URL_SCHEMES = {"http", "https", "ftp", "ftps", "hxxp", "hxxps", "fxp"}
MAX_IOC_LENGTH = 2048


class IocValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ValidatedIndicator:
    ioc_type: IocType
    value: str  # canonical form used for de-duplication
    original: str  # exactly as supplied by the source (evidence preservation)
    is_routable: bool | None = None  # IPs only: False for private/reserved/documentation ranges

    @property
    def entity_key(self) -> str:
        return f"{self.ioc_type.value}:{self.value}"


_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"^fxp", re.I), "ftp"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[\s*@\s*\]|\[at\]", re.I), "@"),
    (re.compile(r"\[://\]"), "://"),
]


def refang(value: str) -> str:
    """Convert common defanged notations (``hxxp://evil[.]com``) back to canonical form."""
    out = value.strip()
    for pattern, repl in _REFANG_RULES:
        out = pattern.sub(repl, out)
    return out


def defang(value: str, ioc_type: IocType | str | None = None) -> str:
    """Make an indicator non-clickable for display/reporting (``hxxp://evil[.]com``)."""
    kind = IocType(ioc_type) if ioc_type else None
    if kind in HASH_LENGTHS:
        return value
    if kind == IocType.IPV6:
        return value.replace(":", "[:]")
    out = re.sub(r"^http", "hxxp", value, flags=re.I)
    out = re.sub(r"^ftp", "fxp", out, flags=re.I)
    if kind in (IocType.URL, None) and "://" in out:
        scheme, rest = out.split("://", 1)
        host, sep, tail = rest.partition("/")
        return f"{scheme}[://]{host.replace('.', '[.]')}{sep}{tail}"
    return out.replace(".", "[.]")


def normalize_domain(value: str) -> str:
    domain = refang(value).strip().rstrip(".").lower()
    if not domain or len(domain) > 253:
        raise IocValidationError("domain is empty or longer than 253 characters")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IocValidationError(f"invalid internationalised domain: {exc}") from exc
    labels = domain.split(".")
    if len(labels) < 2:
        raise IocValidationError("domain must contain at least one dot")
    if not all(_LABEL.match(label) for label in labels):
        raise IocValidationError("domain contains an invalid label")
    if not _TLD.match(labels[-1]):
        raise IocValidationError("domain has an invalid top-level label")
    return domain


def _validate_ip(value: str) -> ValidatedIndicator:
    ip = ipaddress.ip_address(value)
    kind = IocType.IPV4 if ip.version == 4 else IocType.IPV6
    return ValidatedIndicator(kind, ip.compressed, value, is_routable=ip.is_global)


def normalize_url(value: str) -> str:
    candidate = refang(value)
    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in _URL_SCHEMES:
        raise IocValidationError("unsupported or missing URL scheme")
    if not parts.hostname:
        raise IocValidationError("URL has no host")
    host = parts.hostname
    try:
        host = ipaddress.ip_address(host.strip("[]")).compressed
        host_out = f"[{host}]" if ":" in host else host
    except ValueError:
        host_out = normalize_domain(host)
    netloc = host_out
    if parts.port:
        netloc += f":{parts.port}"
    if parts.username:  # preserve userinfo as evidence (common in phishing URLs)
        netloc = f"{parts.username}{':' + parts.password if parts.password else ''}@{netloc}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def detect_type(value: str) -> IocType:
    """Best-effort type detection for an (optionally defanged) indicator."""
    candidate = refang(value)
    if _HEX.match(candidate):
        for kind, length in HASH_LENGTHS.items():
            if len(candidate) == length:
                return kind
    try:
        ip = ipaddress.ip_address(candidate)
        return IocType.IPV4 if ip.version == 4 else IocType.IPV6
    except ValueError:
        pass
    if "://" in candidate:
        return IocType.URL
    normalize_domain(candidate)
    return IocType.DOMAIN


def validate_indicator(value: str, ioc_type: IocType | str | None = None) -> ValidatedIndicator:
    """Validate and canonicalise an indicator. Raises :class:`IocValidationError` if invalid."""
    if not isinstance(value, str) or not value.strip():
        raise IocValidationError("indicator value is empty")
    original = value
    if len(value) > MAX_IOC_LENGTH:
        raise IocValidationError("indicator is too long")
    if any(ord(c) < 32 for c in value):
        raise IocValidationError("indicator contains control characters")
    try:
        kind = IocType(ioc_type.lower()) if isinstance(ioc_type, str) else ioc_type
    except ValueError as exc:
        raise IocValidationError(f"unsupported indicator type: {ioc_type!r}") from exc
    if kind is None:
        try:
            kind = detect_type(value)
        except IocValidationError as exc:
            raise IocValidationError(f"could not determine indicator type: {exc}") from exc

    candidate = refang(value)
    if kind in HASH_LENGTHS:
        if len(candidate) != HASH_LENGTHS[kind] or not _HEX.match(candidate):
            raise IocValidationError(f"not a valid {kind.value} hash")
        return ValidatedIndicator(kind, candidate.lower(), original)
    if kind in (IocType.IPV4, IocType.IPV6):
        try:
            result = _validate_ip(candidate)
        except ValueError as exc:
            raise IocValidationError(f"not a valid IP address: {candidate!r}") from exc
        if result.ioc_type != kind:
            raise IocValidationError(f"IP address is not {kind.value}")
        return ValidatedIndicator(kind, result.value, original, result.is_routable)
    if kind == IocType.DOMAIN:
        return ValidatedIndicator(kind, normalize_domain(candidate), original)
    if kind == IocType.URL:
        return ValidatedIndicator(kind, normalize_url(candidate), original)
    raise IocValidationError(f"unsupported indicator type: {kind}")  # pragma: no cover
