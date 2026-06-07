import { useEffect, useRef, useState } from "react";
import { Panel, StatusBadge } from "../components/ui";
import { flag, time } from "../lib/format";

interface LiveAccess {
  kind: "access";
  id: string;
  ts: number;
  status: number;
  method: string;
  hostLabel: string;
  uri: string;
  client: string;
  country: string | null;
}
interface LiveError {
  kind: "error";
  id: string;
  ts: number;
  level: string;
  hostLabel: string;
  message: string;
}
type LiveEntry = LiveAccess | LiveError;

const MAX = 300;

export default function Live() {
  const [entries, setEntries] = useState<LiveEntry[]>([]);
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const pausedRef = useRef(paused);
  const seq = useRef(0);
  pausedRef.current = paused;

  useEffect(() => {
    const es = new EventSource("/api/stream");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    const push = (e: LiveEntry) => {
      if (pausedRef.current) return;
      setEntries((prev) => [e, ...prev].slice(0, MAX));
    };

    es.addEventListener("access", (ev) => {
      const d = JSON.parse((ev as MessageEvent).data);
      push({
        kind: "access",
        id: `a${seq.current++}`,
        ts: d.ts,
        status: d.status,
        method: d.method,
        hostLabel: d.hostLabel,
        uri: d.uri,
        client: d.client,
        country: d.country ?? null,
      });
    });
    es.addEventListener("error", (ev) => {
      // EventSource fires a bare "error" event on disconnect (no data).
      const data = (ev as MessageEvent).data;
      if (!data) return;
      const d = JSON.parse(data);
      push({
        kind: "error",
        id: `e${seq.current++}`,
        ts: d.ts,
        level: d.level,
        hostLabel: d.hostLabel,
        message: d.message,
      });
    });

    return () => es.close();
  }, []);

  return (
    <Panel
      title="Live tail"
      action={
        <div className="flex items-center gap-3 text-xs">
          <span
            className={`flex items-center gap-1.5 ${
              connected ? "text-emerald-400" : "text-gray-500"
            }`}
          >
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                connected ? "bg-emerald-400" : "bg-gray-600"
              }`}
            />
            {connected ? "Connected" : "Reconnecting…"}
          </span>
          <button
            onClick={() => setPaused((p) => !p)}
            className="rounded border border-gray-700 px-2 py-1 text-gray-300"
          >
            {paused ? "Resume" : "Pause"}
          </button>
          <button
            onClick={() => setEntries([])}
            className="rounded border border-gray-700 px-2 py-1 text-gray-300"
          >
            Clear
          </button>
        </div>
      }
    >
      <div className="max-h-[70vh] overflow-y-auto font-mono text-xs">
        {entries.length === 0 && (
          <div className="py-10 text-center text-gray-600">
            Waiting for requests…
          </div>
        )}
        {entries.map((e) =>
          e.kind === "access" ? (
            <div
              key={e.id}
              className="flex items-center gap-2 border-b border-gray-800/40 py-1"
            >
              <span className="text-gray-600">{time(e.ts)}</span>
              <StatusBadge status={e.status} />
              <span className="text-gray-500">{e.method}</span>
              <span className="text-gray-400">{e.hostLabel}</span>
              <span className="truncate text-gray-200">{e.uri}</span>
              <span className="ml-auto whitespace-nowrap text-gray-500">
                {flag(e.country)} {e.client}
              </span>
            </div>
          ) : (
            <div
              key={e.id}
              className="flex items-center gap-2 border-b border-gray-800/40 py-1 text-red-300"
            >
              <span className="text-gray-600">{time(e.ts)}</span>
              <span className="font-semibold uppercase">{e.level}</span>
              <span className="text-gray-400">{e.hostLabel}</span>
              <span className="truncate">{e.message}</span>
            </div>
          ),
        )}
      </div>
    </Panel>
  );
}
