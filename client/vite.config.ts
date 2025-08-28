import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: '/ddoser/',
  plugins: [react()],
  server: {
    host: true,
    port: 3043,
  },
  preview: {
    port: 3043,
  },
});
