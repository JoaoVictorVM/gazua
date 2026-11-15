"""Demo of Gazua: a fictional store support assistant and a scripted model.

Importing this package runs nothing: the target, the script and the coordinator are imported
only by whoever uses them, so a consumer can reuse the fixtures without starting a demo.
"""

PROFILE = "gazua-store-demo"
PROFILE_VERSION = 1
TARGET_VERSION = f"demo-profile-{PROFILE_VERSION}"
MODEL_ID = "gazua-scripted-v1"
ENTRYPOINT = "gazua.demo.target:entrypoint"

__all__ = ["ENTRYPOINT", "MODEL_ID", "PROFILE", "PROFILE_VERSION", "TARGET_VERSION"]
