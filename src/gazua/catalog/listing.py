"""Text rendering of the catalog for ``gazua run --list``. It never prints attack text."""

from __future__ import annotations

from collections.abc import Iterator

from gazua.catalog.loader import CatalogEntry, CatalogLoadResult
from gazua.catalog.models import DAMAGES, MODES, Damage, Language, Mode
from gazua.catalog.selection import adapter_pending, inspect_requirements, select_molds
from gazua.config.models import GazuaConfig
from gazua.diagnostics import sanitize

NO_CONFIG_NOTE = "No configuration loaded; runtime readiness not checked."

_DAMAGE_LABELS: dict[Language, dict[Damage, str]] = {
    "en": {
        "prompt_only_permission": "Prompt-only permission",
        "secret_in_context": "Secret in context",
        "idor_via_agent": "IDOR via agent",
        "unhandled_output": "Unhandled output",
        "unlocked_memory": "Unlocked memory",
        "unchecked_spending": "Unchecked spending",
    },
    "pt": {
        "prompt_only_permission": "Permissão só no prompt",
        "secret_in_context": "Segredo no contexto",
        "idor_via_agent": "IDOR via agente",
        "unhandled_output": "Saída sem tratamento",
        "unlocked_memory": "Memória destravada",
        "unchecked_spending": "Gasto sem controle",
    },
}
_TEXT: dict[Language, dict[str, str]] = {
    "en": {
        "title": "Attack catalog {release}: {count} molds",
        "mode": "mode",
        "missing": "missing",
        "conditional": "without output_sink: conditional risk only",
        "adapter": "entry adapter not verified",
        "footer": (
            "Statuses describe declarations only. Every mold still needs run-time checks, "
            "and no status is an attack result."
        ),
    },
    "pt": {
        "title": "Catálogo de ataques {release}: {count} moldes",
        "mode": "modo",
        "missing": "faltando",
        "conditional": "sem output_sink: apenas risco condicional",
        "adapter": "adaptador da entrada não verificado",
        "footer": (
            "As situações descrevem apenas declarações. Todo molde ainda depende de "
            "verificações em execução, e nenhuma situação é resultado de ataque."
        ),
    },
}


def _line(entry: CatalogEntry, config: GazuaConfig | None, language: Language) -> str:
    mold = entry.mold
    report = inspect_requirements(mold, config)
    text = _TEXT[language]
    origin = entry.origin if entry.origin == "builtin" else f"{entry.origin}:{entry.source}"
    parts = [
        f"{mold.id:<16}",
        f"{mold.entry}/{mold.technique:<16}",
        f"{mold.effective_severity:<8}",
        f"{sanitize(origin):<10}",
        report.status,
    ]
    notes: list[str] = []
    if report.missing:
        notes.append(f"{text['missing']}: {', '.join(report.missing)}")
    if report.conditional:
        notes.append(text["conditional"])
    if adapter_pending(mold):
        notes.append(text["adapter"])
    line = "    " + " ".join(parts)
    return f"{line} ({'; '.join(notes)})" if notes else line


def render_listing(
    result: CatalogLoadResult,
    config: GazuaConfig | None,
    *,
    mode: Mode | None = None,
    language: Language = "en",
) -> Iterator[str]:
    """Lines grouped by damage and mode, in a stable order, without payloads."""
    entries = select_molds(result.entries, mode)
    text = _TEXT[language]
    yield text["title"].format(release=result.release, count=len(entries))
    for damage in DAMAGES:
        of_damage = [entry for entry in entries if entry.mold.damage == damage]
        if not of_damage:
            continue
        yield ""
        yield _DAMAGE_LABELS[language][damage]
        for each_mode in MODES:
            if mode is not None and each_mode != mode:
                continue
            of_mode = [entry for entry in of_damage if each_mode in entry.mold.supported_modes]
            if not of_mode:
                continue
            yield f"  {text['mode']}: {each_mode}"
            yield from (_line(entry, config, language) for entry in of_mode)
    yield ""
    yield text["footer"]
