import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api, ApiError } from "./lib/api";
import Login from "./pages/Login";
import Layout from "./components/Layout";
import Overview from "./pages/Overview";
import Logs from "./pages/Logs";
import Errors from "./pages/Errors";
import Live from "./pages/Live";
import Hosts from "./pages/Hosts";
import World from "./pages/World";
import type { Filters } from "./lib/types";

type AuthState =
  | { status: "loading" }
  | { status: "out" }
  | { status: "in"; name: string };

function defaultFilters(): Filters {
  const now = Date.now();
  return { from: now - 86_400_000, to: now, hostId: "all" };
}

export default function App() {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });
  const [filters, setFilters] = useState<Filters>(defaultFilters);

  useEffect(() => {
    api
      .me()
      .then((u) => setAuth({ status: "in", name: u.name }))
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          setAuth({ status: "out" });
        } else {
          setAuth({ status: "out" });
        }
      });
  }, []);

  if (auth.status === "loading") {
    return (
      <div className="flex h-full items-center justify-center text-gray-500">
        Loading…
      </div>
    );
  }

  if (auth.status === "out") {
    return <Login onSuccess={(name) => setAuth({ status: "in", name })} />;
  }

  const onLogout = async () => {
    await api.logout();
    setAuth({ status: "out" });
  };

  return (
    <Routes>
      <Route
        element={
          <Layout
            name={auth.name}
            filters={filters}
            setFilters={setFilters}
            onLogout={onLogout}
          />
        }
      >
        <Route
          path="/"
          element={<Overview filters={filters} setFilters={setFilters} />}
        />
        <Route path="/logs" element={<Logs filters={filters} />} />
        <Route path="/errors" element={<Errors filters={filters} />} />
        <Route path="/live" element={<Live />} />
        <Route
          path="/hosts"
          element={<Hosts filters={filters} setFilters={setFilters} />}
        />
        <Route
          path="/world"
          element={<World filters={filters} setFilters={setFilters} />}
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
