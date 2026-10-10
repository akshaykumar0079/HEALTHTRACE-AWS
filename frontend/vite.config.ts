/// <reference types="vitest/config" />
import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const backend = env.HEALTHTRACE_BACKEND ?? "http://127.0.0.1:8010";

  return {
    plugins: [react(), tailwindcss()],
    resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
    server: {
      port: 5173,
      proxy: {
        "/api": { target: backend, changeOrigin: true },
        "/ws": { target: backend.replace(/^http/, "ws"), ws: true, changeOrigin: true },
      },
    },
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      css: false,
      restoreMocks: true,
    },
    build: {
      target: "es2022",
      sourcemap: false,
      // three.js (~1 MB) only loads with the lazy 3D scene.
      chunkSizeWarningLimit: 1400,
    },
  };
});
