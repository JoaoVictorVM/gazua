# pytest plugin

Installing Gazua also installs a pytest plugin. It runs selected tools molds as tests of your suite, with the same verdicts as `gazua run --tools`.

```console
pytest --gazua
pytest --gazua --gazua-mold idor-01 --gazua-mold secret-01
```

## Activation

The plugin does nothing until you pass `--gazua`: without it, no configuration is read and no mold runs, so installing Gazua never starts an attack by itself.

| Option | Default | Meaning |
|---|---|---|
| `--gazua` | off | Add one test per selected tools mold |
| `--gazua-config PATH` | `gazua.yaml` | Configuration, as `gazua run --config`. Its folder is the project root, where `.gazua/` is written |
| `--gazua-mold ID` | every tools mold | Run this mold, by exact id. Repeat it for more; repetitions count once |
| `--gazua-baseline PATH` | `gazua-baseline.json` when present | Compare with this baseline, as `gazua run --baseline` |

Each mold becomes the item `gazua::<mold-id>`, in catalog order, with the marker `gazua`, so `-m gazua`, `-m "not gazua"` and `-k idor` work as usual. An unknown mold id fails collection with the same message as the CLI, before anything runs.

## States

Each item runs its mold through the same services as `gazua run --tools` and reads the result; it never judges again.

| Mold result | pytest state |
|---|---|
| A new gated finding | failed, with the finding id, severity, damage, tool and the command to reproduce it |
| A finding open in the baseline | xfailed (not strict) |
| A new finding that is not gated | xfailed (not strict), with its severity |
| Every evaluated scenario resisted | passed |
| Nothing could be tested | skipped, `gazua_not_tested` |
| Nothing applied to the target | skipped, `gazua_not_applicable` |
| Operational, configuration or storage error | error |
| Ctrl+C | interrupted, after the project lock is released |

A failure shows the same finding id, state, severity and gate as the CLI, and the same reproduction command. It never shows attack text, payloads or proof; open `.gazua/report.html` for them. An xfailed known finding is not a fix: it stays open in the baseline until `gazua verify` closes it.

Each item writes its run to `.gazua/` like `gazua run`, so the reports of the last item are the latest set and every run is kept in the history.

## Limits

- **Tools mode only.** The plugin calls your tools directly with no model. It does not measure how a model resists; use `gazua run --agent` for that.
- **No parallel workers.** With pytest-xdist and more than one worker, collection stops with `pytest_gazua_xdist_unsupported` before any target runs: concurrent molds would share one `.gazua/`. Run the Gazua items with `-n0`, or in a separate pytest call.
- **Same configuration as the CLI.** HTTP and TypeScript targets are refused, as in `gazua run --tools`.
- Passing means the molds that ran did not prove an effect. It is a floor, not a certificate.
