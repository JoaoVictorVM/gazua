"""Run modes: consumers of the catalog, the run engine and the verdict engine.

Each mode plans its attempts, hands them to the engine and reports the verdicts. Nothing here
runs at ``import gazua``; the CLI imports a mode only when asked to execute it.
"""
