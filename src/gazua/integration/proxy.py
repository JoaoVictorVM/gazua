"""Proxies that stand in for the user's tools during a Gazua run.

For each call the proxy reserves a slot under the execution's tool call ceiling, decides the
mode, imposes the actor, runs the original or returns the
dry-run value, applies injections and records the call. Without a session it only calls the
original. A tool marked dry-run never reaches the original function, whatever else fails.
"""

from __future__ import annotations

import copy
import functools
import inspect
from collections.abc import Callable
from contextlib import AsyncExitStack, ExitStack
from dataclasses import dataclass
from typing import Any, cast

from gazua.integration.calllog import CallLog, call_log_for, log_arguments
from gazua.integration.errors import GazuaBlockedError
from gazua.integration.injection import inject
from gazua.integration.limits import admit
from gazua.integration.observations import record_return
from gazua.integration.session import Decision, InvalidSession, Session, decide, session_state

PROXY_ATTRIBUTE = "__gazua_tool__"
GENERIC_DRY_RUN_RETURN = "ok"

_identity_hooks: dict[str, Callable[..., Any]] = {}


def is_proxy(value: object) -> bool:
    return isinstance(getattr(value, PROXY_ATTRIBUTE, None), str)


def _signature(original: Callable[..., Any]) -> inspect.Signature | None:
    try:
        return inspect.signature(original)
    except (TypeError, ValueError):
        return None


def _accepts(signature: inspect.Signature | None, argument: str) -> bool:
    if signature is None:
        return False
    parameter = signature.parameters.get(argument)
    if parameter is not None:
        return parameter.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
    return any(item.kind is inspect.Parameter.VAR_KEYWORD for item in signature.parameters.values())


def _identity_hook(reference: str) -> Callable[..., Any]:
    hook = _identity_hooks.get(reference)
    if hook is None:
        # Imported here: resolving a reference runs the target's code, which only an active
        # session authorizes, and keeps ``import gazua`` on the standard library.
        from gazua.config.references import resolve_reference

        hook = _identity_hooks[reference] = resolve_reference(reference, "target.as_user")
    return hook


@dataclass(slots=True)
class _Call:
    """One call inside a valid session, from the decision to its log record."""

    name: str
    session: Session
    log: CallLog
    decision: Decision
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    bound: inspect.BoundArguments | None = None
    actor_id: str | None = None
    actor_source: str = "none"

    def finish(self, outcome: str, **fields: Any) -> int:
        arguments: dict[str, object] = (
            dict(self.bound.arguments)
            if self.bound is not None
            else {"$args": list(self.args), **self.kwargs}
        )
        logged, truncated = log_arguments(arguments)
        return self.log.append(
            {
                "tool": self.name,
                "arguments": logged,
                "truncated": truncated,
                "actor": {"id": self.actor_id, "source": self.actor_source},
                "dry_run": self.decision.dry_run,
                "undeclared": self.decision.undeclared,
                "outcome": outcome,
                "low_fidelity": self.decision.low_fidelity,
                "result_type": None,
                "error": None,
                "block_reason": None,
                "injection": None,
                **fields,
            }
        )

    def block(self, reason: str) -> GazuaBlockedError:
        self.finish("blocked", block_reason=reason)
        return GazuaBlockedError(reason)

    def call_arguments(self) -> tuple[tuple[Any, ...], dict[str, Any]]:
        if self.bound is not None:
            return self.bound.args, self.bound.kwargs
        return self.args, self.kwargs

    def dry_run_value(self) -> Any:
        policy = self.decision.policy
        if policy is not None and policy.has_dry_run_return:
            return copy.deepcopy(policy.dry_run_return)
        return GENERIC_DRY_RUN_RETURN

    def returned(self, value: Any) -> Any:
        delivered, injection = inject(self.session, self.name, value)
        seq = self.finish("returned", result_type=type(value).__name__, injection=injection)
        record_return(self.session, seq, value, delivered)
        return delivered

    def raised(self, error: BaseException) -> None:
        self.finish("raised", error={"type": type(error).__name__})


def _start(
    name: str, signature: inspect.Signature | None, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> _Call | None:
    state = session_state()
    if state is None:
        return None
    if isinstance(state, InvalidSession):
        raise GazuaBlockedError("invalid_session", state.reason)
    admit(state)
    log = call_log_for(state.call_log)
    log.check_writable()
    call = _Call(name, state, log, decide(state, name), args, dict(kwargs))
    if signature is not None:
        try:
            call.bound = signature.bind_partial(*args, **kwargs)
        except TypeError:
            call.bound = None
    policy, actor = call.decision.policy, state.actor
    if actor is None:
        return call
    if policy is not None and policy.actor_arg is not None:
        call.actor_id, call.actor_source = actor.id, "actor_arg"
        if not _accepts(signature, policy.actor_arg):
            raise call.block("actor_arg_not_accepted")
        # Arguments that do not fit the signature fail like the original would, before any
        # real work, so there is nothing to impose on.
        if call.bound is not None:
            call.bound.arguments[policy.actor_arg] = actor.id
    elif state.as_user is not None:
        call.actor_id, call.actor_source = actor.id, "as_user"
    return call


def _complete_arguments(call: _Call, signature: inspect.Signature | None) -> None:
    """A dry-run answers like the original would to arguments that do not fit its signature."""
    if signature is None or call.bound is None:
        if signature is not None:
            error = TypeError("The arguments do not match the tool's signature.")
            call.raised(error)
            raise error
        return
    try:
        signature.bind(*call.bound.args, **call.bound.kwargs)
    except TypeError as error:
        call.raised(error)
        raise


def _enter_identity(call: _Call, stack: ExitStack) -> None:
    if call.actor_source != "as_user" or call.actor_id is None or call.session.as_user is None:
        return
    try:
        stack.enter_context(_identity_hook(call.session.as_user)(call.actor_id))
    # The hook is the target's code; any failure means the identity is not in place.
    except (Exception, SystemExit):  # noqa: BLE001
        raise call.block("identity_hook") from None


async def _enter_identity_async(call: _Call, stack: AsyncExitStack) -> None:
    if call.actor_source != "as_user" or call.actor_id is None or call.session.as_user is None:
        return
    try:
        manager = _identity_hook(call.session.as_user)(call.actor_id)
        if hasattr(manager, "__aenter__") and not hasattr(manager, "__enter__"):
            await stack.enter_async_context(manager)
        else:
            stack.enter_context(manager)
    except (Exception, SystemExit):  # noqa: BLE001
        raise call.block("identity_hook") from None


def make_proxy(name: str, original: Callable[..., Any]) -> Callable[..., Any]:
    """A proxy with the original's name, signature and docstring."""
    signature = _signature(original)

    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def async_proxy(*args: Any, **kwargs: Any) -> Any:
            call = _start(name, signature, args, kwargs)
            if call is None:
                return await original(*args, **kwargs)
            if call.decision.dry_run:
                _complete_arguments(call, signature)
                return call.returned(call.dry_run_value())
            async with AsyncExitStack() as stack:
                await _enter_identity_async(call, stack)
                call_args, call_kwargs = call.call_arguments()
                try:
                    value = await original(*call_args, **call_kwargs)
                except BaseException as error:
                    call.raised(error)
                    raise
            return call.returned(value)

        setattr(async_proxy, PROXY_ATTRIBUTE, name)
        return async_proxy

    @functools.wraps(original)
    def proxy(*args: Any, **kwargs: Any) -> Any:
        call = _start(name, signature, args, kwargs)
        if call is None:
            return original(*args, **kwargs)
        if call.decision.dry_run:
            _complete_arguments(call, signature)
            return call.returned(call.dry_run_value())
        with ExitStack() as stack:
            _enter_identity(call, stack)
            call_args, call_kwargs = call.call_arguments()
            try:
                value = original(*call_args, **call_kwargs)
            except BaseException as error:
                call.raised(error)
                raise
        return call.returned(value)

    setattr(proxy, PROXY_ATTRIBUTE, name)
    return cast("Callable[..., Any]", proxy)


def clear_identity_hooks() -> None:
    _identity_hooks.clear()
