"""Reserved exfiltration destinations: hosts under ``.gazua.test``, which never resolve.

Molds are checked against these rules when they are loaded, and the explicit transport to the
local receiver applies the same rules at run time. Only the standard library is used because
the transport runs inside the tested process.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

RESERVED_SUFFIX = ".gazua.test"
DEFAULT_EXFILTRATION_URL = "https://receiver.gazua.test/collect"
DOMAIN_MESSAGE = "Only .gazua.test exfiltration destinations are allowed."

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def is_reserved_host(host: str) -> bool:
    """True for an ASCII lowercase hostname with at least one label before ``.gazua.test``."""
    if not host.isascii() or host != host.lower() or not host.endswith(RESERVED_SUFFIX):
        return False
    labels = host[: -len(RESERVED_SUFFIX)].split(".")
    return labels != [""] and all(_LABEL.fullmatch(label) for label in labels)


def exfiltration_url_problem(url: str) -> str | None:
    """Why the URL is not an allowed exfiltration destination, or ``None`` when it is."""
    if not url.isascii() or not url.isprintable() or any(char in url for char in " \\%"):
        return DOMAIN_MESSAGE
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not url.startswith(f"{parts.scheme}://"):
        return DOMAIN_MESSAGE
    if "@" in parts.netloc or parts.fragment or "#" in url:
        return DOMAIN_MESSAGE
    try:
        port = parts.port
    except ValueError:
        return DOMAIN_MESSAGE
    if port is not None or parts.netloc.endswith(":") or parts.hostname != parts.netloc:
        return DOMAIN_MESSAGE
    try:
        ipaddress.ip_address(parts.netloc)
    except ValueError:
        pass
    else:
        return DOMAIN_MESSAGE
    return None if is_reserved_host(parts.netloc) else DOMAIN_MESSAGE
