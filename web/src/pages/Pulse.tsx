import { useEffect, useRef, useState } from "react";

/**
 * Pulse — a live, animated picture of traffic flowing through the proxy.
 *
 * Every request from the SSE stream becomes a glowing comet that flies from
 * a lane (keyed to its client, so one visitor always streams from the same
 * height) into the host node it targeted. Hosts ring and glow as they are
 * hit. The bottom edge draws a rolling spectrogram of the last few minutes,
 * stacked by status class. Everything is one <canvas>; the HUD is DOM.
 */

interface StreamEvent {
  ts: number;
  status: number;
  method: string;
  hostLabel: string;
  uri: string;
  client: string;
  bytes: number;
  banned: boolean;
}

interface Particle {
  x: number;
  y: number;
  /** Previous frame position, for drawing a continuous streak. */
  px: number;
  py: number;
  /** Lane progress 0..1 along the flight path. */
  t: number;
  speed: number;
  startY: number;
  size: number;
  color: string;
  banned: boolean;
  host: string;
}

interface Ripple {
  x: number;
  y: number;
  r: number;
  life: number;
  color: string;
}

interface HostNode {
  label: string;
  hits: number;
  lastHit: number;
  /** 0..1 glow that decays between hits. */
  glow: number;
}

const COLORS = {
  ok: "#34d399", // 2xx
  redirect: "#38bdf8", // 3xx
  client: "#fbbf24", // 4xx
  server: "#fb7185", // 5xx
  banned: "#f87171",
} as const;

function statusColor(status: number, banned: boolean): string {
  if (banned) return COLORS.banned;
  if (status >= 500) return COLORS.server;
  if (status >= 400) return COLORS.client;
  if (status >= 300) return COLORS.redirect;
  return COLORS.ok;
}

function statusClass(status: number): 0 | 1 | 2 | 3 {
  if (status >= 500) return 3;
  if (status >= 400) return 2;
  if (status >= 300) return 1;
  return 0;
}

/** Stable 0..1 hash so one client always flies in the same lane. */
function lane(client: string): number {
  let h = 2166136261;
  for (let i = 0; i < client.length; i++) {
    h ^= client.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 10_000) / 10_000;
}

const BUCKET_MS = 2_000;
const BUCKETS = 120; // 4 minutes of spectrogram
const MAX_PARTICLES = 500;
const MAX_HOSTS = 14;
const HUD_WINDOW_MS = 60_000;
const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

interface Sim {
  particles: Particle[];
  ripples: Ripple[];
  hosts: Map<string, HostNode>;
  hostOrder: string[];
  /** Rolling window of recent events for the HUD numbers. */
  recent: { ts: number; status: number; client: string; bytes: number; banned: boolean }[];
  buckets: [number, number, number, number][];
  bucketT0: number;
  last: StreamEvent | null;
  reduced: boolean;
}

function freshSim(): Sim {
  return {
    particles: [],
    ripples: [],
    hosts: new Map(),
    hostOrder: [],
    recent: [],
    buckets: Array.from({ length: BUCKETS }, () => [0, 0, 0, 0]),
    bucketT0: Date.now(),
    last: null,
    reduced:
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  };
}

// --- demo traffic (client-side only, for admiring the view when quiet) -----

const DEMO_HOSTS = ["home.lan", "media.lan", "git.lan", "vault.lan", "grafana.lan"];
const DEMO_PATHS = [
  "/", "/api/v1/items", "/stream/4123", "/static/app.js", "/login",
  "/api/health", "/img/cover.jpg", "/.env", "/feed.xml", "/api/search?q=tv",
];
const DEMO_CLIENTS = [
  "203.0.113.7", "198.51.100.23", "2a00:23c5:1234:5678:abcd::1",
  "92.40.18.6", "2001:db8:7:1::42", "151.101.1.69", "66.249.66.1",
];

function demoEvent(): StreamEvent {
  const r = Math.random();
  const status =
    r < 0.78 ? 200 : r < 0.86 ? 304 : r < 0.93 ? 404 : r < 0.97 ? 401 : 502;
  const banned = Math.random() < 0.02;
  return {
    ts: Date.now(),
    status,
    method: Math.random() < 0.85 ? "GET" : "POST",
    hostLabel: DEMO_HOSTS[Math.floor(Math.random() * DEMO_HOSTS.length)]!,
    uri: DEMO_PATHS[Math.floor(Math.random() * DEMO_PATHS.length)]!,
    client: DEMO_CLIENTS[Math.floor(Math.random() * DEMO_CLIENTS.length)]!,
    bytes: Math.floor(Math.exp(5 + Math.random() * 6)),
    banned,
  };
}

// ---------------------------------------------------------------------------

export default function Pulse() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const sim = useRef<Sim>(freshSim());
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [demo, setDemo] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const [hud, setHud] = useState({
    rpm: 0,
    errPct: 0,
    clients: 0,
    kbMin: 0,
    banned: 0,
    last: null as StreamEvent | null,
  });

  // Feed one event into the simulation.
  const ingest = (e: StreamEvent) => {
    if (pausedRef.current) return;
    const s = sim.current;
    s.last = e;
    s.recent.push({
      ts: e.ts, status: e.status, client: e.client, bytes: e.bytes, banned: e.banned,
    });

    // Spectrogram bucket.
    const idx = Math.floor((Date.now() - s.bucketT0) / BUCKET_MS);
    const bucket = s.buckets[Math.min(idx, BUCKETS - 1)];
    if (bucket) bucket[statusClass(e.status)]++;

    // Host registry (stable first-seen order, capped).
    let node = s.hosts.get(e.hostLabel);
    if (!node) {
      if (s.hostOrder.length >= MAX_HOSTS) {
        node = s.hosts.get(s.hostOrder[s.hostOrder.length - 1]!);
      } else {
        node = { label: e.hostLabel, hits: 0, lastHit: 0, glow: 0 };
        s.hosts.set(e.hostLabel, node);
        s.hostOrder.push(e.hostLabel);
      }
    }
    if (node) {
      node.hits++;
      node.lastHit = e.ts;
    }

    if (s.particles.length < MAX_PARTICLES) {
      s.particles.push({
        x: 0,
        y: 0,
        px: -1,
        py: -1,
        t: s.reduced ? 1 : 0,
        speed: 0.55 + Math.random() * 0.5,
        startY: lane(e.client),
        size: Math.max(1.4, Math.min(4.5, Math.log10(Math.max(e.bytes, 1)) - 0.5)),
        color: statusColor(e.status, e.banned),
        banned: e.banned,
        host: e.hostLabel,
      });
    }
  };

  // Live stream.
  useEffect(() => {
    const es = new EventSource("/api/stream");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener("access", (ev) => {
      const d = JSON.parse((ev as MessageEvent).data);
      ingest({
        ts: d.ts,
        status: d.status,
        method: d.method,
        hostLabel: d.hostLabel,
        uri: d.uri,
        client: d.client,
        bytes: d.bytes ?? 0,
        banned: Boolean(d.banned),
      });
    });
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Demo traffic, Poisson-ish arrivals.
  useEffect(() => {
    if (!demo) return;
    let timer: ReturnType<typeof setTimeout>;
    let alive = true;
    const tick = () => {
      if (!alive) return;
      ingest(demoEvent());
      timer = setTimeout(tick, 60 + Math.random() * 700);
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demo]);

  // HUD numbers at 2 Hz (keeps per-event work off React).
  useEffect(() => {
    const id = setInterval(() => {
      const s = sim.current;
      const cutoff = Date.now() - HUD_WINDOW_MS;
      while (s.recent.length && s.recent[0]!.ts < cutoff) s.recent.shift();
      const total = s.recent.length;
      const errs = s.recent.filter((r) => r.status >= 400).length;
      const banned = s.recent.filter((r) => r.banned).length;
      const clients = new Set(s.recent.map((r) => r.client)).size;
      const kb = s.recent.reduce((sum, r) => sum + r.bytes, 0) / 1024;
      setHud({
        rpm: total,
        errPct: total ? Math.round((errs / total) * 100) : 0,
        clients,
        kbMin: Math.round(kb),
        banned,
        last: s.last,
      });
    }, 500);
    return () => clearInterval(id);
  }, []);

  // The render loop.
  useEffect(() => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let w = 0;
    let h = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const resize = () => {
      w = wrap.clientWidth;
      h = wrap.clientHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = "#070a10";
      ctx.fillRect(0, 0, w, h);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(wrap);

    let raf = 0;
    const draw = () => {
      raf = requestAnimationFrame(draw);
      const s = sim.current;
      const now = Date.now();

      // Advance spectrogram buckets.
      while (now - s.bucketT0 >= BUCKET_MS * BUCKETS) {
        s.buckets.shift();
        s.buckets.push([0, 0, 0, 0]);
        s.bucketT0 += BUCKET_MS;
      }
      const liveIdx = Math.floor((now - s.bucketT0) / BUCKET_MS);
      if (liveIdx >= BUCKETS) {
        const shift = liveIdx - BUCKETS + 1;
        for (let i = 0; i < shift; i++) {
          s.buckets.shift();
          s.buckets.push([0, 0, 0, 0]);
        }
        s.bucketT0 += shift * BUCKET_MS;
      }

      // Afterglow: fade the previous frame instead of clearing it.
      ctx.globalCompositeOperation = "source-over";
      ctx.fillStyle = s.reduced ? "rgba(7,10,16,1)" : "rgba(7,10,16,0.26)";
      ctx.fillRect(0, 0, w, h);

      const specH = Math.min(86, h * 0.18); // spectrogram strip
      const flightTop = 64;
      const flightBottom = h - specH - 56;
      const nodeX = w - 132;

      // --- host nodes -----------------------------------------------------
      const order = s.hostOrder;
      const slot = (i: number) =>
        flightTop + ((i + 0.5) / Math.max(order.length, 1)) * (flightBottom - flightTop);

      // --- particles ------------------------------------------------------
      ctx.globalCompositeOperation = "lighter";
      const next: Particle[] = [];
      for (const p of s.particles) {
        const hi = order.indexOf(p.host);
        const targetY = hi === -1 ? (flightTop + flightBottom) / 2 : slot(hi);
        p.t += (p.speed * 16) / Math.max(w, 1) / (s.reduced ? 0.25 : 1);
        const t = Math.min(p.t, 1);
        // Ease horizontally, drift from the client's lane into the host lane.
        const ease = t * t * (3 - 2 * t);
        const wasFresh = p.px < 0;
        p.px = wasFresh ? 24 : p.x;
        p.py = wasFresh ? 0 : p.y;
        p.x = 24 + ease * (nodeX - 48);
        const laneY = flightTop + p.startY * (flightBottom - flightTop);
        p.y = laneY + (targetY - laneY) * ease;
        if (wasFresh) p.py = p.y;

        if (t >= 1) {
          s.ripples.push({ x: nodeX, y: targetY, r: 3, life: 1, color: p.color });
          const node = s.hosts.get(p.host);
          if (node) node.glow = Math.min(1, node.glow + 0.45);
          continue;
        }
        ctx.shadowBlur = p.banned ? 18 : 10;
        ctx.shadowColor = p.color;
        // A short line from the previous frame keeps the streak continuous.
        ctx.strokeStyle = p.color;
        ctx.lineWidth = p.banned ? p.size + 1 : p.size;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(p.px, p.py);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
        next.push(p);
      }
      s.particles = next;
      ctx.shadowBlur = 0;

      // --- ripples ----------------------------------------------------------
      const ripples: Ripple[] = [];
      for (const r of s.ripples) {
        r.r += s.reduced ? 0 : 1.6;
        r.life -= s.reduced ? 0.1 : 0.04;
        if (r.life <= 0) continue;
        ctx.strokeStyle = r.color;
        ctx.globalAlpha = r.life * 0.6;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(r.x, r.y, r.r, 0, Math.PI * 2);
        ctx.stroke();
        ripples.push(r);
      }
      s.ripples = ripples;
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = "source-over";

      // --- host nodes + labels ---------------------------------------------
      ctx.font = `11px ${MONO}`;
      order.forEach((label, i) => {
        const node = s.hosts.get(label);
        if (!node) return;
        const y = slot(i);
        node.glow *= 0.94;
        const glow = node.glow;
        ctx.shadowBlur = 8 + glow * 22;
        ctx.shadowColor = "#22d3ee";
        ctx.fillStyle = `rgba(34,211,238,${0.35 + glow * 0.65})`;
        ctx.beginPath();
        ctx.arc(nodeX, y, 4 + glow * 3.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.fillStyle = "rgba(148,163,184,0.9)";
        ctx.textAlign = "left";
        ctx.fillText(label, nodeX + 14, y + 3);
        ctx.fillStyle = "rgba(100,116,139,0.65)";
        ctx.fillText(String(node.hits), nodeX + 14, y + 15);
      });

      // --- spectrogram (newest bucket pinned to the right edge) -------------
      const bw = w / BUCKETS;
      const maxCount = Math.max(4, ...s.buckets.map((b) => b[0] + b[1] + b[2] + b[3]));
      const palette = [COLORS.ok, COLORS.redirect, COLORS.client, COLORS.server];
      const live = Math.min(liveIdx, BUCKETS - 1);
      for (let i = 0; i <= live; i++) {
        const b = s.buckets[i]!;
        const x = w - (live - i + 1) * bw;
        let yTop = h - 8;
        for (let c = 0; c < 4; c++) {
          const v = b[c]!;
          if (!v) continue;
          const bh = (v / maxCount) * (specH - 14);
          ctx.fillStyle = palette[c]!;
          ctx.globalAlpha = 0.85;
          ctx.fillRect(x + 0.5, yTop - bh, Math.max(bw - 1.5, 1), bh);
          yTop -= bh;
        }
      }
      ctx.globalAlpha = 1;
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  const last = hud.last;

  return (
    <div
      ref={wrapRef}
      className="pulse-root relative h-[calc(100vh-180px)] min-h-[460px] overflow-hidden rounded-2xl border border-cyan-900/40 bg-[#070a10]"
    >
      <canvas ref={canvasRef} className="absolute inset-0" />

      {/* Atmosphere */}
      <div className="pulse-grid pointer-events-none absolute inset-0" />
      <div className="pulse-scanlines pointer-events-none absolute inset-0" />
      <div className="pulse-vignette pointer-events-none absolute inset-0" />

      {/* HUD — top-left instrument cluster */}
      <div className="pointer-events-none absolute left-5 right-44 top-4 flex flex-wrap gap-x-6 gap-y-1 sm:gap-x-8">
        <Meter label="req / min" value={String(hud.rpm)} accent />
        <Meter
          label="err rate"
          value={`${hud.errPct}%`}
          tone={hud.errPct >= 20 ? "bad" : hud.errPct > 5 ? "warn" : undefined}
        />
        <Meter label="clients" value={String(hud.clients)} />
        <Meter
          label="kb / min"
          value={hud.kbMin >= 10_000 ? `${Math.round(hud.kbMin / 1024)}M` : String(hud.kbMin)}
        />
        {hud.banned > 0 && <Meter label="banned hits" value={String(hud.banned)} tone="bad" />}
      </div>

      {/* HUD — top-right controls */}
      <div className="absolute right-4 top-4 flex items-center gap-3 font-mono text-[11px]">
        <span
          className={`flex items-center gap-2 uppercase tracking-[0.2em] ${
            connected ? "text-rose-400" : "text-gray-500"
          }`}
        >
          <span
            className={`inline-block h-2 w-2 rounded-full ${
              connected ? "pulse-live-dot bg-rose-500" : "bg-gray-600"
            }`}
          />
          {connected ? "live" : "linking…"}
        </span>
        <button
          onClick={() => setDemo((d) => !d)}
          className={`rounded border px-2 py-1 uppercase tracking-widest transition ${
            demo
              ? "border-cyan-400/60 bg-cyan-400/10 text-cyan-300"
              : "border-gray-700 text-gray-400 hover:text-gray-200"
          }`}
          title="Synthesise fake traffic so you can see the visualisation"
        >
          demo
        </button>
        <button
          onClick={() => setPaused((p) => !p)}
          className="rounded border border-gray-700 px-2 py-1 uppercase tracking-widest text-gray-400 transition hover:text-gray-200"
        >
          {paused ? "resume" : "pause"}
        </button>
      </div>

      {/* Ticker — last request, bottom-left above the spectrogram */}
      <div className="pointer-events-none absolute inset-x-5 bottom-[96px] font-mono text-[11px]">
        {last ? (
          <div key={last.ts + last.uri} className="pulse-ticker flex items-center gap-2 text-gray-400">
            <span style={{ color: statusColor(last.status, last.banned) }}>
              {last.status}
            </span>
            <span className="text-gray-500">{last.method}</span>
            <span className="max-w-[40%] truncate text-gray-300">{last.uri}</span>
            <span className="text-gray-600">→ {last.hostLabel}</span>
            <span className="ml-auto truncate text-gray-600">{last.client}</span>
            {last.banned && (
              <span className="rounded border border-red-900/70 px-1.5 text-[10px] uppercase tracking-widest text-red-400">
                banned
              </span>
            )}
          </div>
        ) : (
          <div className="text-gray-600">
            awaiting packets… {demo ? "" : "(hit demo to see it move)"}
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="pointer-events-none absolute bottom-3 right-5 flex gap-4 rounded-md border border-gray-800/60 bg-[#070a10]/85 px-2.5 py-1 font-mono text-[10px] uppercase tracking-widest text-gray-500 backdrop-blur-sm">
        {([
          ["2xx", COLORS.ok],
          ["3xx", COLORS.redirect],
          ["4xx", COLORS.client],
          ["5xx", COLORS.server],
        ] as const).map(([label, color]) => (
          <span key={label} className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

function Meter({
  label,
  value,
  accent,
  tone,
}: {
  label: string;
  value: string;
  accent?: boolean;
  tone?: "warn" | "bad";
}) {
  const colour =
    tone === "bad"
      ? "text-rose-400"
      : tone === "warn"
        ? "text-amber-300"
        : accent
          ? "pulse-glow-text text-cyan-300"
          : "text-gray-200";
  return (
    <div className="font-mono">
      <div className="text-[10px] uppercase tracking-[0.25em] text-cyan-200/40">{label}</div>
      <div className={`text-2xl tabular-nums sm:text-3xl ${colour}`}>{value}</div>
    </div>
  );
}
