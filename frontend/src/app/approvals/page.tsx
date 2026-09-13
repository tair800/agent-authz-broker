import { ApprovalsTable } from "@/components/approvals";
import { Screen, SourceBand } from "@/components/primitives";
import { Empty, Failure } from "@/components/states";
import { fetchApprovals } from "@/lib/server/source";

export const dynamic = "force-dynamic";

export default async function ApprovalsPage() {
  const result = await fetchApprovals();

  return (
    <Screen
      title="Approvals"
      lead={
        <>
          <p>
            An approval is a durable row created out of band by a human. The irreversible tool looks
            for one in this server&rsquo;s own database. There is no tool argument, no header and no
            prompt that can assert that a human agreed — the input schema of{" "}
            <span className="tabular">issue_credit</span> has no field a caller could use to claim
            one.
          </p>
          <p className="mt-2">
            Consumption is a conditional <span className="tabular">UPDATE</span> guarded by a unique
            constraint, so a spent approval is spent for every connection at once. One approval
            authorises exactly one irreversible effect, including under two concurrent calls.
          </p>
        </>
      }
    >
      {result.ok ? (
        <>
          <SourceBand source={result.source} />
          {result.data.length === 0 ? (
            <Empty
              title="No approvals are on file."
              detail={
                "This is the correct resting state of a fresh database: nobody has approved " +
                "anything, so the irreversible tool refuses everything with approval_required. " +
                "The suite creates approvals as part of running the scenarios."
              }
              run="uv run pytest -m integration"
            />
          ) : (
            <ApprovalsTable approvals={result.data} />
          )}
        </>
      ) : (
        <Failure failure={result.failure} />
      )}
    </Screen>
  );
}
