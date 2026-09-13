import { DelegationChain, ScenarioPicker } from "@/components/chain";
import { Screen, SourceBand } from "@/components/primitives";
import { Empty, Failure } from "@/components/states";
import { fetchChain, fetchMatrix } from "@/lib/server/source";

export const dynamic = "force-dynamic";

/** The scenario that actually loses a scope, so the screen opens on the thing it is about. */
const DEFAULT_SCENARIO = "scope_amplification";

function firstParam(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function ChainPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const matrix = await fetchMatrix();

  const known = matrix.ok ? matrix.data.scenarios : [];
  const requested = firstParam(params.scenario);
  const selected =
    requested ?? (known.some((s) => s.id === DEFAULT_SCENARIO) ? DEFAULT_SCENARIO : known[0]?.id);

  const chain = selected === undefined ? null : await fetchChain(selected);

  return (
    <Screen
      title="Delegation"
      lead={
        <>
          <p>
            Effective authority is the intersection of every link in the chain:{" "}
            <span className="tabular">effective = leaf ∩ act[0] ∩ … ∩ root</span>. Attenuation is
            monotone — a hop can only remove authority — and there is no rule anywhere that puts a
            scope back.
          </p>
          <p className="mt-2">
            The leaf&rsquo;s own <span className="tabular">scope</span> claim is the most dangerous
            field in this system. This screen shows what the server computed instead of believing
            it.
          </p>
        </>
      }
    >
      {known.length > 0 && selected !== undefined ? (
        <ScenarioPicker scenarios={known} selected={selected} />
      ) : null}

      {!matrix.ok ? (
        <Failure failure={matrix.failure} />
      ) : selected === undefined ? (
        <Empty
          title="There are no scenarios to walk."
          detail={
            "The chain view renders a scenario the broker has recorded. None exist on this " +
            "instance yet."
          }
          run="uv run pytest -m integration"
        />
      ) : chain === null || !chain.ok ? (
        <Failure
          failure={
            chain === null
              ? { endpoint: "/api/v1/chain", message: "No scenario was selected.", detail: null }
              : chain.failure
          }
        />
      ) : (
        <>
          <SourceBand source={chain.source} />
          {chain.data.links.length === 0 ? (
            <Empty
              title="This scenario recorded no delegation chain."
              detail={
                "A token always has at least its own subject, so an empty chain means the " +
                "scenario was recorded without one rather than that authority was empty."
              }
              run="uv run pytest -m integration"
            />
          ) : (
            <DelegationChain chain={chain.data} />
          )}
        </>
      )}
    </Screen>
  );
}
