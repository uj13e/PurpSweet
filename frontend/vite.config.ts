import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During `npm run dev`, proxy API + WS to the FastAPI server on :8777 so the
// browser sees a single origin. In production the FastAPI server serves dist/.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8777",
      "/ws": { target: "ws://127.0.0.1:8777", ws: true },
    },
  },
  build: { outDir: "dist" },
});
