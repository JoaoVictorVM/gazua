"""What the demo says and shows: the simulation notice, the local index and its opening.

The index is a static page with relative links to the two runs' archived reports. It holds no
payload, conversation or evidence, loads nothing remote and runs no script. Opening it hands a
``file://`` URI to the system browser; no server is started.
"""

from __future__ import annotations

import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Final, Literal

from jinja2 import Environment, select_autoescape
from markupsafe import Markup

from gazua.demo.models import BrowserOutcome, ModeOutcome

Language = Literal["en", "pt"]

SIMULATION_NOTICE: Final[dict[Language, str]] = {
    "en": (
        "This demo uses a simulated model that follows a fixed script. It shows that Gazua and "
        "the controls it exercises work; it does not measure how a real model resists attacks."
    ),
    "pt": (
        "Esta demo usa um modelo simulado que segue um roteiro fixo. Ela mostra que o Gazua e os "
        "controles exercitados funcionam; não mede a resistência de um modelo real a ataques."
    ),
}

_TEXT: Final[dict[Language, dict[str, str]]] = {
    "en": {
        "title": "Gazua demo",
        "intro": "Tools mode ran first, then agent mode. Each one has its own reports.",
        "tools": "Tools mode",
        "agent": "Agent mode",
        "exit_code": "Exit code",
        "findings": "Findings",
        "no_reports": "The reports of this mode were not saved.",
        "not_started": "Not started",
        "reproduce": (
            "Reproduction commands in the reports run from this folder, with its gazua.yaml."
        ),
        "clean": (
            "gazua clean in this folder removes the reports these links point to; the next "
            "gazua demo rebuilds them."
        ),
        "html": "Report (HTML)",
        "markdown": "Report (Markdown)",
        "json": "Run data (JSON)",
    },
    "pt": {
        "title": "Demo do Gazua",
        "intro": "O modo tools rodou primeiro, depois o modo agent. Cada um tem seus relatórios.",
        "tools": "Modo tools",
        "agent": "Modo agent",
        "exit_code": "Código de saída",
        "findings": "Achados",
        "no_reports": "Os relatórios deste modo não foram salvos.",
        "not_started": "Não iniciado",
        "reproduce": (
            "Os comandos de reprodução dos relatórios rodam nesta pasta, com o gazua.yaml dela."
        ),
        "clean": (
            "gazua clean nesta pasta remove os relatórios destes links; a próxima execução de "
            "gazua demo os recria."
        ),
        "html": "Relatório (HTML)",
        "markdown": "Relatório (Markdown)",
        "json": "Dados da execução (JSON)",
    },
}

_STYLE: Final = (
    "body{font-family:system-ui,sans-serif;margin:0;background:#fff;color:#1a1a1a}"
    "main{max-width:44rem;margin:0 auto;padding:1.5rem 1rem}"
    ".notice{border-left:4px solid #b26b00;background:#fff6e5;padding:.75rem 1rem}"
    ".small{font-size:.9rem;color:#555}a{color:#0b57d0}"
    "@media (prefers-color-scheme: dark){body{background:#121212;color:#eee}"
    ".notice{background:#2b2210}.small{color:#aaa}a{color:#8ab4f8}}"
)

Opener = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class IndexPart:
    mode: str
    heading: str
    started: bool
    exit_code: int | None
    findings: int
    links: tuple[tuple[str, str], ...]
    reason: str


def notice(language: Language) -> str:
    return SIMULATION_NOTICE[language]


def _relative_link(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _part(root: Path, outcome: ModeOutcome, language: Language) -> IndexPart:
    text = _TEXT[language]
    links = tuple(
        (text[kind], _relative_link(root, outcome.reports[kind]))
        for kind in ("html", "markdown", "json")
        if kind in outcome.reports
    )
    return IndexPart(
        mode=outcome.mode,
        heading=text[outcome.mode],
        started=outcome.started,
        exit_code=outcome.exit_code,
        findings=outcome.findings,
        links=links,
        reason=(outcome.reason or "not_started").replace("_", " "),
    )


def render_index(root: Path, tools: ModeOutcome, agent: ModeOutcome, language: Language) -> str:
    from gazua.reports.rendering import csp_hash

    source = files("gazua.demo").joinpath("resources", "index.html.j2").read_text("utf-8")
    environment = Environment(
        autoescape=select_autoescape(default=True), keep_trailing_newline=True
    )
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; "
        f"img-src 'none'; style-src {csp_hash(_STYLE)}"
    )
    return environment.from_string(source).render(
        lang=language,
        csp=csp,
        # Constant text whose hash is in the policy; escaping it would break the match.
        style=Markup(_STYLE),  # noqa: S704
        text=_TEXT[language],
        notice=notice(language),
        parts=[_part(root, tools, language), _part(root, agent, language)],
    )


def write_index(root: Path, tools: ModeOutcome, agent: ModeOutcome, language: Language) -> Path:
    """Publishes ``index.html`` atomically; an ``OSError`` keeps the previous one."""
    from gazua.runtime.evidence import write_atomic

    path = root / "index.html"
    write_atomic(path, render_index(root, tools, agent, language))
    return path


def _system_open(uri: str) -> bool:
    return webbrowser.open(uri)


def open_index(path: Path, opener: Opener | None = None) -> BrowserOutcome:
    """Asks the browser to open the local page. A failure is a warning, never an error."""
    chosen = opener if opener is not None else _system_open
    try:
        return "opened" if chosen(path.resolve().as_uri()) else "failed"
    # The browser is the user's program; whatever it raises only means it did not open.
    except Exception:  # noqa: BLE001
        return "failed"


__all__ = [
    "SIMULATION_NOTICE",
    "notice",
    "open_index",
    "render_index",
    "write_index",
]
