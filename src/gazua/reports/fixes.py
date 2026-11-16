"""Fixed guidance per damage, with a stable local reference.

The reference is the damage itself and the report anchors it as ``fix-<damage>``. Each damage
has a short fix, kept on findings as it always was, and a guide entry that separates what fixes
the cause, what only reduces the risk and what does not solve it. The texts are editorial: no
model writes them and they make no claim of measured effectiveness.
"""

from __future__ import annotations

from typing import Final

from gazua.catalog.models import DAMAGES, Damage, Language
from gazua.reports.guide_models import FixGuide, GuideEntry, GuideOrigin

GUIDE_REVISION: Final = 1

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

_EVERY_PATH: Final[dict[Language, str]] = {
    "en": (
        "Apply the control on every path that reaches the same effect, not only on the one the "
        "attack used."
    ),
    "pt": (
        "Aplicar o controle em todos os caminhos que chegam ao mesmo efeito, não só no caminho "
        "usado pelo ataque."
    ),
}

_CONFIRMATION: Final[dict[Language, str]] = {
    "en": (
        "Verify the finding with gazua verify, by its full id and mode, after the fix. The "
        "command uses the project's current configuration and baseline: if the finding is not "
        "in the baseline yet, review the run and accept it with gazua baseline first, knowing "
        "that accepting findings changes which known findings stop failing the build. Only 0 "
        "successes in 20 conclusive repetitions of every scenario closes the finding; a normal "
        "run never closes it."
    ),
    "pt": (
        "Verificar o finding com gazua verify, pelo ID completo e pelo modo, depois da "
        "correção. O comando usa a configuração e a baseline atuais do projeto: se o finding "
        "ainda não está na baseline, revisar a execução e aceitá-la com gazua baseline antes, "
        "sabendo que aceitar findings muda quais findings conhecidos deixam de falhar o build. "
        "Só 0 sucessos em 20 repetições conclusivas de cada cenário fecham o finding; uma "
        "execução normal nunca o fecha."
    ),
}

_VERIFIED: Final[dict[Language, str]] = {
    "en": (
        "gazua verify ends with 0 successes in 20 conclusive repetitions of every scenario, "
        "with the original coverage kept and no low fidelity or operational failure."
    ),
    "pt": (
        "gazua verify termina com 0 sucessos em 20 repetições conclusivas de cada cenário, "
        "mantendo a cobertura original e sem baixa fidelidade ou falha operacional."
    ),
}

_LEGITIMATE: Final[dict[Language, str]] = {
    "en": "The relevant legitimate tasks still work after the change.",
    "pt": "As tarefas legítimas relevantes continuam funcionando depois da mudança.",
}

# Per damage: fixes the cause, reduces the risk, does not solve, and the control the first
# acceptance criterion asks for.
_EDITORIAL: Final[dict[Language, dict[Damage, tuple[list[str], list[str], list[str], str]]]] = {
    "en": {
        "prompt_only_permission": (
            [
                "Check authorization and validate the arguments in the backend before the tool "
                "has its effect, using an identity the application trusts, never one the model "
                "states.",
            ],
            [
                "Ask for human confirmation bound to the operation and its exact parameters.",
                "Give the tool only the privileges the task needs.",
            ],
            [
                "Reinforcing the system prompt with rules about who may call the tool.",
                "Relying on the model to refuse the request.",
            ],
            "The tool checks authorization and validates its arguments in code before its effect.",
        ),
        "secret_in_context": (
            [
                "Keep real secrets out of the model's context, and stop tools from returning "
                "them to the model.",
            ],
            [
                "Restrict where output can go, and the read privileges of the tools.",
                "Use short-lived, narrowly scoped credentials.",
            ],
            [
                "Asking the model not to reveal a secret it already received.",
                "Filtering only the formats of secrets that are already known.",
            ],
            "No real secret reaches the model's context or comes back from a tool.",
        ),
        "idor_via_agent": (
            [
                "Validate a trusted identity and the ownership of, or permission on, each record "
                "in the backend on every access.",
            ],
            [
                "Ask for human confirmation of the operation, without replacing authorization.",
            ],
            [
                "A reinforced prompt.",
                "An identity the model states, or that comes from the conversation.",
            ],
            "Access to each record is authorized in code before it is read or changed.",
        ),
        "unhandled_output": (
            [
                "Treat the model's output as untrusted data: parameterize, validate or escape "
                "it for the sink that receives it.",
            ],
            [
                "Isolate the consumer and restrict what it can do.",
            ],
            [
                "Trusting the apparent format of the answer.",
                "Asking for safe output in the prompt.",
            ],
            "Every sink parameterizes, validates or escapes the output it receives.",
        ),
        "unlocked_memory": (
            [
                "Authorize memory writes and reads, keep users apart and validate entries with "
                "their provenance.",
            ],
            [
                "Review memory entries by hand and let them expire.",
            ],
            [
                "Asking the model to ignore malicious instructions already stored in memory.",
            ],
            "Memory writes and reads are authorized in code and kept apart per user.",
        ),
        "unchecked_spending": (
            [
                "Enforce cumulative, atomic limits on cost, quantity and operations in the "
                "backend.",
            ],
            [
                "Ask for human approval and send alerts before expensive operations.",
            ],
            [
                "A limit described only in the prompt.",
                "An alert sent after the spending, with nothing that blocks it.",
            ],
            "Cumulative limits on cost, quantity and operations are enforced atomically in code.",
        ),
    },
    "pt": {
        "prompt_only_permission": (
            [
                "Verificar a autorização e validar os argumentos no backend antes de a "
                "ferramenta ter efeito, usando uma identidade confiável para a aplicação, nunca "
                "a alegada pelo modelo.",
            ],
            [
                "Pedir confirmação humana vinculada à operação e aos seus parâmetros exatos.",
                "Dar à ferramenta só os privilégios de que a tarefa precisa.",
            ],
            [
                "Reforçar o prompt de sistema com regras sobre quem pode chamar a ferramenta.",
                "Confiar na recusa do modelo.",
            ],
            "A ferramenta verifica a autorização e valida os argumentos em código antes do efeito.",
        ),
        "secret_in_context": (
            [
                "Manter segredos reais fora do contexto do modelo e impedir que ferramentas os "
                "devolvam ao modelo.",
            ],
            [
                "Restringir os destinos da saída e os privilégios de leitura das ferramentas.",
                "Usar credenciais de curta duração e escopo restrito.",
            ],
            [
                "Pedir ao modelo que não revele um segredo que já recebeu.",
                "Filtrar só formatos de segredo já conhecidos.",
            ],
            "Nenhum segredo real chega ao contexto do modelo nem volta de uma ferramenta.",
        ),
        "idor_via_agent": (
            [
                "Validar uma identidade confiável e a propriedade ou permissão de cada registro "
                "no backend em cada acesso.",
            ],
            [
                "Pedir confirmação humana da operação, sem substituir a autorização.",
            ],
            [
                "Prompt reforçado.",
                "Identidade alegada pelo modelo ou vinda da conversa.",
            ],
            "O acesso a cada registro é autorizado em código antes de ser lido ou alterado.",
        ),
        "unhandled_output": (
            [
                "Tratar a saída do modelo como dado não confiável: parametrizar, validar ou "
                "escapar conforme o sink que a recebe.",
            ],
            [
                "Isolar o consumidor e restringir suas capacidades.",
            ],
            [
                "Confiar no formato aparente da resposta.",
                "Pedir saída segura no prompt.",
            ],
            "Cada sink parametriza, valida ou escapa a saída que recebe.",
        ),
        "unlocked_memory": (
            [
                "Autorizar escrita e leitura da memória, separar usuários e validar entradas "
                "com sua proveniência.",
            ],
            [
                "Revisar entradas da memória manualmente e fazê-las expirar.",
            ],
            [
                "Pedir ao modelo que ignore instruções maliciosas já gravadas na memória.",
            ],
            "Escrita e leitura da memória são autorizadas em código e separadas por usuário.",
        ),
        "unchecked_spending": (
            [
                "Impor no backend limites cumulativos e atômicos de custo, quantidade e operações.",
            ],
            [
                "Pedir aprovação humana e emitir alertas antes de operações caras.",
            ],
            [
                "Limite descrito apenas no prompt.",
                "Alerta emitido depois do gasto, sem nada que o bloqueie.",
            ],
            "Limites cumulativos de custo, quantidade e operações são impostos atomicamente "
            "em código.",
        ),
    },
}


def _entry(language: Language, damage: Damage) -> GuideEntry:
    cause, reduces, does_not, control = _EDITORIAL[language][damage]
    return GuideEntry(
        fixes_cause=[*cause, _EVERY_PATH[language]],
        reduces_risk=list(reduces),
        does_not_solve=list(does_not),
        confirmation=_CONFIRMATION[language],
        acceptance_criteria=[control, _VERIFIED[language], _LEGITIMATE[language]],
    )


def fix_ref(damage: Damage) -> str:
    return damage


def fix_anchor(damage: Damage) -> str:
    return f"fix-{damage}"


def fix_text(damage: Damage, language: Language = "en") -> str:
    return FIXES[language][damage]


def fixes_for(language: Language = "en") -> dict[Damage, str]:
    """Every damage with its fixed guidance, in catalog order."""
    return {damage: FIXES[language][damage] for damage in DAMAGES}


def guide_for(language: Language = "en", origin: GuideOrigin = "captured") -> FixGuide:
    """The installed guide in one language, in catalog order, as a run captures it."""
    return FixGuide(
        revision=GUIDE_REVISION,
        language=language,
        origin=origin,
        entries={damage: _entry(language, damage) for damage in DAMAGES},
    )
