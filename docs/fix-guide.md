# Fix guide

Every report carries a fix guide with one entry per damage. Each entry separates three things:

- **Fixes the cause**: the control in code that removes the reason the attack worked.
- **Reduces the risk**: measures that make the damage less likely or smaller, without removing its cause.
- **Does not solve**: common answers that leave the cause in place.

Each entry also says how to confirm a fix and lists the acceptance criteria an issue uses. The texts are fixed and editorial: no model writes them, and they make no claim of measured effectiveness. Fixing the cause means applying the control on every path that reaches the same effect, not only on the one the attack used. The guide covers fixes only; incident response is out of scope.

## Where it appears

Each finding in `report.html` and `report.md` links to its entry under the anchor `fix-<damage>`, for example `#fix-idor_via_agent`. Low findings shown together keep their own link. Each finding also shows its confirmation command and the name of its issue file, `<finding-id>.md`, written by [`gazua issues`](issues.md).

The six entries are:

| Damage | Anchor |
|---|---|
| Permission only in the prompt | `fix-prompt_only_permission` |
| Secret in the context | `fix-secret_in_context` |
| Records of another user | `fix-idor_via_agent` |
| Unhandled output | `fix-unhandled_output` |
| Unlocked memory | `fix-unlocked_memory` |
| Unchecked spending | `fix-unchecked_spending` |

For records of another user, the guide lists authorization of each record in code, with a trusted identity, as fixing the cause; human confirmation of the operation as reducing the risk; and a reinforced prompt, or an identity the model states, as not solving it.

## Confirming a fix

```console
gazua verify finding-<64 hex characters> --mode tools
```

Each finding shows this command with its full id and mode; the guide shows the form `gazua verify <finding>`, where `<finding>` is replaced by that id. The command uses the project's current `gazua.yaml` and `gazua-baseline.json`; pass `--config` or `--baseline` when the project uses other paths.

`gazua verify` only works on findings in the baseline. If the finding is not there yet, review the run and accept it with `gazua baseline --from <run.json>` first. Accepting changes which known findings stop failing the build, so it is a decision for the team; neither the report nor the issue export accepts anything for you. Only 0 successes in 20 conclusive repetitions of every scenario close a finding (up to ~14% at 95% confidence); a normal run, even with 0/5, never closes one. See [the baseline guide](baseline.md).

## Acceptance criteria

Every entry ends with criteria a fix must meet, for example for records of another user:

- access to each record is authorized in code before it is read or changed;
- `gazua verify` ends with 0 successes in 20 conclusive repetitions of every scenario, with the original coverage kept and no low fidelity or operational failure;
- the relevant legitimate tasks still work after the change.

## The guide is kept with the run

`run.json` (schema version 3) keeps a copy of the guide in `guide`, with its editorial `revision`, its `language`, which is the run's, and its `origin`. Reports rebuilt with `gazua report --from` use that copy, even after a newer Gazua changes the texts, so an old report keeps the guidance it was produced with.

Documents written before the guide existed (schema versions 1 and 2) are still read. Gazua adds a frozen copy of the first revision of the guide when it reads them and marks it `legacy_fallback`; the reports then say that the guide was added when the document was read and was not part of the original run. The original file is never rewritten.
