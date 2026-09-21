import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(fileURLToPath(import.meta.url));

// Single-server architecture: production build is served by FastAPI from the same origin.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: path.resolve(rootDir, "../backend/app/web/static/spa"),
    emptyOutDir: true,
    assetsDir: "assets",
  },
  server: {
    port: 5173,
    proxy: {
      "/auth": "http://127.0.0.1:8000",
      "/admin/users": "http://127.0.0.1:8000",
      "/admin/audit-events": "http://127.0.0.1:8000",
    },
  },
});
