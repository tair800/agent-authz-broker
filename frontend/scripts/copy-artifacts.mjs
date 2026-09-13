/**
 * Copy the MEASURED console artifacts next to the app.
 *
 * The console shipped with four hand-written fixtures. One of them was caught before publication —
 * `matrix.json` claimed the naive verifier caused six irreversible effects, and it causes four —
 * and only that one was corrected, because only that one was being looked at. The other three kept
 * the retracted version: the audit trail still showed six `eff-` ids, and the chain fixture still
 * named *alice* as the subject of the four tokens the scenarios mint for *agent-7*.
 *
 * That is the failure mode this file now exists to remove. All four screens are written by
 * `python -m agent_authz_broker.demo` from one run against real PostgreSQL, and this copies all
 * four. A screen cannot be corrected without the others being recomputed, because there is nothing
 * left to correct by hand.
 *
 * Deliberately not a failure when there is nothing to copy: a checkout that has not run the
 * measurement should still build a console, one that shows an empty state naming the command.
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const frontend = path.resolve(here, "..");
const artifacts = path.resolve(frontend, "..", "artifacts");

/** Every screen the console renders. Adding one here is the whole of wiring it up. */
const SCREENS = ["matrix.json", "audit.json", "approvals.json", "chains.json"];

const copied = [];
const missing = [];

for (const name of SCREENS) {
  const source = path.join(artifacts, name);
  try {
    await fs.access(source);
  } catch {
    missing.push(name);
    continue;
  }
  const destination = path.join(frontend, "fixtures", name);
  await fs.mkdir(path.dirname(destination), { recursive: true });
  await fs.copyFile(source, destination);
  copied.push(name);
}

if (copied.length) console.log(`artifacts: copied the measured ${copied.join(", ")}`);
if (missing.length) {
  console.log(
    `artifacts: no measured ${missing.join(", ")}; ` +
      "run `python -m agent_authz_broker.demo` — those screens will show their empty state",
  );
}
