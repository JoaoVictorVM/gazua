// Starts the runner of the npm package gazua installed in the tested project.
//
// The runner is resolved from the project's own package.json, never from a path the target or
// the configuration gives. Exit codes: 78 when the package or its runner export is missing.
import { createRequire } from "node:module";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = process.argv[2];
if (typeof root !== "string" || root.length === 0) {
  process.exit(64);
}
let resolved;
try {
  resolved = createRequire(join(root, "package.json")).resolve("gazua/runner");
} catch {
  process.exit(78);
}
let runner;
try {
  runner = await import(pathToFileURL(resolved).href);
} catch {
  process.exit(78);
}
if (typeof runner.main !== "function") {
  process.exit(78);
}
runner.main();
