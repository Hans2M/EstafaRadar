import { defineConfig } from 'vite';

const apiTarget = process.env.VITE_API_PROXY_TARGET || 'http://localhost:8000';

export default defineConfig({
  server: {
    proxy: {
      '/api': apiTarget,
    },
  },
});
