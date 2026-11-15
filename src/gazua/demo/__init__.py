"""Demo of Gazua: a fictional store support assistant and a scripted model.

Importing this package runs nothing: the target, the script and the coordinator are imported
only by whoever uses them, so a consumer can reuse the fixtures without starting a demo.
"""

PROFILE = "gazua-store-demo"
PROFILE_VERSION = 1
TARGET_VERSION = f"demo-profile-{PROFILE_VERSION}"
MODEL_ID = "gazua-scripted-v1"
ENTRYPOINT = "gazua.demo.target:entrypoint"
SIMULATION_NOTICE = {
    "en": (
        "This demo uses a simulated model that follows a fixed script. It shows that Gazua and "
        "the controls it exercises work; it does not measure how a real model resists attacks."
    ),
    "pt": (
        "Esta demo usa um modelo simulado que segue um roteiro fixo. Ela mostra que o Gazua e os "
        "controles exercitados funcionam; não mede a resistência de um modelo real a ataques."
    ),
}

__all__ = [
    "ENTRYPOINT",
    "MODEL_ID",
    "PROFILE",
    "PROFILE_VERSION",
    "SIMULATION_NOTICE",
    "TARGET_VERSION",
]
