// client/vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: '/ddoser/',
  plugins: [react()],
  server: {
    host: true,
    port: 3043,
    proxy: {
      // /ddoser/api/* → http://localhost:5043/api/*
      '/ddoser/api': {
        target: 'http://localhost:5043',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/ddoser\/api/, '/api'),
        configure: (proxy /*: import('http-proxy').ProxyServer*/) => {
          proxy.on('error', (err, res /* ServerResponse | Socket */) => {
            // Если это ServerResponse — ответим текстом; если Socket — просто закроем.
            const anyRes = res as any;
            try {
              if (anyRes && typeof anyRes.writeHead === 'function') {
                anyRes.writeHead(500, { 'Content-Type': 'text/plain' });
                anyRes.end('proxy error: ' + err.message);
              } else {
                anyRes?.end?.();
              }
            } catch (_) {
              /* ignore */
            }
            console.error('[vite-proxy] error:', err?.message || err);
          });

          proxy.on('proxyReq', (proxyReq, req) => {
            console.log(
              '[vite-proxy] →',
              req.method,
              req.url,
              '→',
              proxyReq.getHeader('host')
            );
          });

          proxy.on('proxyRes', (proxyRes, req) => {
            console.log(
              '[vite-proxy] ←',
              req.method,
              req.url,
              '←',
              proxyRes.statusCode
            );
          });
        },
      },
    },
  },
  preview: {
    port: 3043,
  },
});
