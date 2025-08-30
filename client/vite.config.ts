/* eslint-disable @typescript-eslint/no-explicit-any */
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

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
            } catch (err) {
              console.log(err);
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
  resolve: {
    alias: {
      '@app': path.resolve(__dirname, 'src/app'),
      '@entities': path.resolve(__dirname, 'src/entities'),
      '@features': path.resolve(__dirname, 'src/features'),
      '@shared': path.resolve(__dirname, 'src/shared'),
      '@widgets': path.resolve(__dirname, 'src/widgets'),
    },
  },
});
