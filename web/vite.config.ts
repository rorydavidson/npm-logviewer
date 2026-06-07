import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In dev, proxy API calls to the backend so the SPA and API share an origin.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": {
        target: process.env.API_TARGET ?? "http://localhost:8090",
        changeOrigin: true,
      },
    },
  },
  build: { outDir: "dist" },
});
