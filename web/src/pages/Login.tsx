import { useState, type FormEvent } from "react";
import { api } from "../lib/api";
import { LogoMark } from "../components/Logo";

export default function Login({ onSuccess }: { onSuccess: (name: string) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.login(email, password);
      onSuccess(r.name);
    } catch {
      setError("Invalid credentials");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center px-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-2xl border border-gray-800 bg-gray-900/60 p-8 shadow-xl"
      >
        <div className="mb-4 flex items-center gap-3">
          <LogoMark size={40} />
          <div>
            <h1 className="text-xl font-semibold text-white">
              Proxy<span className="text-teal-400">Logs</span>
            </h1>
            <p className="text-xs text-gray-500">NPM log dashboard</p>
          </div>
        </div>
        <p className="mb-6 text-sm text-gray-400">
          Sign in with your Nginx Proxy Manager account.
        </p>

        <label className="mb-1 block text-xs font-medium text-gray-400">Email</label>
        <input
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          className="mb-4 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
        />

        <label className="mb-1 block text-xs font-medium text-gray-400">Password</label>
        <input
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          className="mb-4 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
        />

        {error && <p className="mb-4 text-sm text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-blue-500 disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
