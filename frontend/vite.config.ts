import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // the dev server forwards api calls to the fastapi backend, so no cors setup is needed
    proxy: {
      "/api": "http://127.0.0.1:8000",
    },
  },
});
