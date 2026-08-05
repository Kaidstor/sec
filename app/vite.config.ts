import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(async () => ({
  plugins: [react(), tailwindcss()],
  server: { port: 1430, strictPort: true, watch: { ignored: ["**/src-tauri/**"] } },
}));
