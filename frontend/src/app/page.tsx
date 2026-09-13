import { SecurityMatrix } from "@/components/matrix";
import { Screen, SourceBand } from "@/components/primitives";
import { Empty, Failure } from "@/components/states";
import { fetchMatrix } from "@/lib/server/source";

/**
 * Rendered per request, never prerendered.
 *
 * Without this, a build with no `BROKER_API_BASE_URL` set would bake the fixtures into static HTML
 * and then ignore the variable when it *was* set at runtime — the deployment would claim to be
 * live while serving committed numbers. Every screen in this console carries the same directive
 * for the same reason.
 */
export const dynamic = "force-dynamic";

export default async function MatrixPage() {
  const result = await fetchMatrix();

  return (
    <Screen
      title="Security matrix"
      lead={
        <>
          <p className="text-ink">
            An agent can request an action. It cannot manufacture the authority to perform one.
          </p>
          <p className="mt-2">
            Each row is one way a caller can be wrong. The <strong>naive baseline</strong> is the
            check ADR-001 predeclared before any code was written — signature and expiry only, the
            leaf&rsquo;s <span className="tabular">scope</span> claim taken at its word. It is a
            stated baseline for this comparison and not a claim about what any real product ships.
          </p>
        </>
      }
    >
      {result.ok ? (
        <>
          <SourceBand source={result.source} generatedAt={result.data.generated_at} />
          <p className="tabular text-ink-faint">
            resource server: {result.data.resource_server_url}
          </p>
          {result.data.scenarios.length === 0 ? (
            <Empty
              title="The matrix has no scenarios."
              detail={
                "The broker builds this table by running each scenario through both verifiers " +
                "against its own database. Nothing has been run against this one yet."
              }
              run="uv run pytest -m integration"
            />
          ) : (
            <SecurityMatrix matrix={result.data} />
          )}
        </>
      ) : (
        <Failure failure={result.failure} />
      )}
    </Screen>
  );
}
