import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // 9090 is reserved by Hyper-V on some Windows setups, so the dev proxy target
    // has to be overridable instead of hardcoded.
    proxy: { "/api": process.env.WAFFYNX_API_URL ?? "http://localhost:9090" },
  },
  build: { outDir: "dist", emptyOutDir: true },
});
