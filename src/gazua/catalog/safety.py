"""Format checks on network destinations and opaque content in attack molds.

These checks reject what a mold declares or writes. They do not prove that a model never
contacts another host: a payload in natural language can still ask for one, so containment
at run time is a separate control.
"""

from __future__ import annotations

import re

from gazua.integration.destinations import (
    DEFAULT_EXFILTRATION_URL,
    DOMAIN_MESSAGE,
    RESERVED_SUFFIX,
    exfiltration_url_problem,
    is_reserved_host,
)

__all__ = [
    "DEFAULT_EXFILTRATION_URL",
    "DOMAIN_MESSAGE",
    "OPAQUE_MESSAGE",
    "RESERVED_SUFFIX",
    "exfiltration_url_problem",
    "is_reserved_host",
    "text_problem",
]

OPAQUE_MESSAGE = (
    "Encoded or opaque payloads are not accepted; write the plain text and set encoding: base64."
)

_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>`]*")
_PROTOCOL_RELATIVE = re.compile(r"(?<![:\w/])//[^\s/\"'<>`]+")
_EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
_IPV6 = re.compile(r"\[[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*\]")
_OBFUSCATED = re.compile(
    r"(?i)hxxps?|\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|[\[({]\s*dot\s*[\])}]"
    r"|\bdot\s+(?:com|net|org|io|test)\b"
)
_HOSTNAME = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,24}))\b")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_BLOB = re.compile(r"\b[0-9A-Fa-f]{48,}\b")
_TOKEN = re.compile(r"\$\{[^{}]*\}")
_TRAILING = ".,;:!?)]}'\""

# Bare names are only treated as hosts when they end in a common public or local suffix, so
# that words such as file names in a payload do not count as destinations.
_HOST_SUFFIXES = frozenset(
    {
        "ai", "app", "biz", "br", "cc", "cloud", "cn", "co", "com", "de", "dev", "eu", "fr",
        "gov", "info", "io", "me", "net", "online", "org", "ru", "site", "sh", "top", "tk",
        "uk", "us", "xyz", "test", "local", "localhost", "internal", "onion", "example",
    }
)  # fmt: skip


def _host_is_foreign(host: str) -> bool:
    return not is_reserved_host(host.lower())


def text_problem(text: str) -> tuple[str, str] | None:
    """The first network destination or opaque payload in a text, as ``(kind, message)``.

    ``kind`` is ``"domain"`` or ``"opaque"``. Allowlisted ``${...}`` tokens are ignored here,
    because their values are checked again after binding.
    """
    plain = _TOKEN.sub(" ", text)
    for match in _URL.finditer(plain):
        if exfiltration_url_problem(match.group().rstrip(_TRAILING)):
            return "domain", DOMAIN_MESSAGE
    without_urls = _URL.sub(" ", plain)
    if _PROTOCOL_RELATIVE.search(without_urls):
        return "domain", DOMAIN_MESSAGE
    if _OBFUSCATED.search(without_urls) or _IPV4.search(without_urls):
        return "domain", DOMAIN_MESSAGE
    if _IPV6.search(without_urls):
        return "domain", DOMAIN_MESSAGE
    for match in _EMAIL.finditer(without_urls):
        if _host_is_foreign(match.group(1)):
            return "domain", DOMAIN_MESSAGE
    without_emails = _EMAIL.sub(" ", without_urls)
    for match in _HOSTNAME.finditer(without_emails):
        host, suffix = match.group(1).lower(), match.group(2).lower()
        if is_reserved_host(host):
            continue
        if suffix in _HOST_SUFFIXES or host.startswith("www.") or "gazua" in host:
            return "domain", DOMAIN_MESSAGE
    if _BASE64_BLOB.search(without_emails) or _HEX_BLOB.search(without_emails):
        return "opaque", OPAQUE_MESSAGE
    return None
