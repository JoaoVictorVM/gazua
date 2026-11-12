"""Short, fixed guidance per damage, with a stable local reference.

The reference is the damage itself and the report anchors it as ``fix-<damage>``. It is not a
link to a guide: the full guide is a later deliverable that can enrich the same reference. The
texts make no claim of measured effectiveness.
"""

from __future__ import annotations

from typing import Final

from gazua.catalog.models import DAMAGES, Damage, Language

FIXES: Final[dict[Language, dict[Damage, str]]] = {
    "en": {
        "prompt_only_permission": (
            "Enforce authorization and validation in code before the tool runs."
        ),
        "secret_in_context": (
            "Remove secrets from the context and restrict access and output destinations."
        ),
        "idor_via_agent": (
            "Validate identity and record ownership in the backend on every access."
        ),
        "unhandled_output": (
            "Treat output as untrusted data and escape or validate it at the sink."
        ),
        "unlocked_memory": ("Authorize, validate and separate memory writes and reads per user."),
        "unchecked_spending": ("Enforce budget, quantity and operation limits in code."),
    },
    "pt": {
        "prompt_only_permission": (
            "Aplicar autorização e validação em código antes da ferramenta executar."
        ),
        "secret_in_context": (
            "Remover segredos do contexto e restringir acesso e destinos de saída."
        ),
        "idor_via_agent": (
            "Validar identidade e propriedade do registro no backend em cada acesso."
        ),
        "unhandled_output": ("Tratar saída como dado não confiável e escapar ou validar no sink."),
        "unlocked_memory": (
            "Autorizar, validar e separar escrita e leitura da memória por usuário."
        ),
        "unchecked_spending": ("Impor orçamento, quantidade e limites de operação em código."),
    },
}


def fix_ref(damage: Damage) -> str:
    return damage


def fix_anchor(damage: Damage) -> str:
    return f"fix-{damage}"


def fix_text(damage: Damage, language: Language = "en") -> str:
    return FIXES[language][damage]


def fixes_for(language: Language = "en") -> dict[Damage, str]:
    """Every damage with its fixed guidance, in catalog order."""
    return {damage: FIXES[language][damage] for damage in DAMAGES}
