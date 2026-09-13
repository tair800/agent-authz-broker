/**
 * Copy the MEASURED matrix next to the app.
 *
 * The console shipped with a hand-written `fixtures/matrix.json` claiming the naive verifier caused
 * six irreversible effects. It causes four, and it permits two of the five attacks rather than
 * three — the two policies differ only on audience and delegation, and the approval gate sits below
 * both. A reviewer caught the fixture before anything was published.
 *
 * So the fixture is no longer a source of truth: this copies `artifacts/matrix.json`, written by
 * `python -m agent_authz_broker.demo` against real PostgreSQL, into the build root. A deployment
 * whose build root is `frontend/` cannot reach above it, which is the only reason this file exists.
 *
 * Deliberately not a failure when there is nothing to copy: a checkout that has not run the
 * measurement should still build a console, one that shows an empty state naming the command.
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const frontend = path.resolve(here, "..");
const source = path.resolve(frontend, "..", "artifacts", "matrix.json");
const destination = path.join(frontend, "fixtures", "matrix.json");

try {
  await fs.access(source);
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.copyFile(source, destination);
  console.log("artifacts: copied the measured matrix.json");
} catch {
  console.log("artifacts: no measured matrix.json; the console will show its empty state");
}
