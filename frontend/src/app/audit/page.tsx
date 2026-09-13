import { AuditTrail } from "@/components/audit";
import { Screen, SourceBand } from "@/components/primitives";
import { Empty, Failure } from "@/components/states";
import { fetchAudit } from "@/lib/server/source";

export const dynamic = "force-dynamic";

export default async function AuditPage() {
  const result = await fetchAudit(50);

  return (
    <Screen
      title="Audit"
      lead={
        <>
          <p>
            Every decision, newest first, with how far the request got: token, audience, scope
            chain, approval. The reason is the closed vocabulary the server, the tests and this
            console all name identically — a denial whose reason is a sentence somebody typed is a
            denial nobody can aggregate.
          </p>
          <p className="mt-2">
            A stage marked <span className="tabular text-attenuated">not checked</span> is one that
            verifier does not perform. That is the comparison: the naive baseline does not fail the
            audience check, it has no audience check.
          </p>
        </>
      }
    >
      {result.ok ? (
        <>
          <SourceBand source={result.source} />
          {result.data.length === 0 ? (
            <Empty
              title="No decisions have been recorded."
              detail={
                "The audit table is written by the server as it authorizes calls, so an empty " +
                "table means nothing has called this instance yet — not that calls were lost."
              }
              run="uv run pytest -m integration"
            />
          ) : (
            <AuditTrail entries={result.data} />
          )}
        </>
      ) : (
        <Failure failure={result.failure} />
      )}
    </Screen>
  );
}
