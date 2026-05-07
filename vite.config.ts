// FILE: vite.config.ts — Vite build configuration. Sets up React plugin, Tailwind, path alias (@), and dev proxy for /api and /uploads to the Express server.

// =============================================================================
// FILE: vite.config.ts
// WHAT: Vite build tool configuration for the React frontend.
// WHY:  Vite handles fast hot-module replacement in dev and optimised bundling
//       for production. This config sets up React support and Tailwind CSS.
// =============================================================================

import tailwindcss from '@tailwindcss/vite';
import react       from '@vitejs/plugin-react';
import path        from 'path';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
    react(),       // Enables JSX transform and React Fast Refresh in dev
    tailwindcss(), // Processes Tailwind CSS utility classes
  ],

  resolve: {
    alias: {
      // '@' resolves to the project root — lets you import '@/src/...' anywhere
      '@': path.resolve(__dirname, '.'),
    },
  },

  build: {
    // Output to /dist — this is what gets served in production
    outDir: 'dist',
    // Split code into chunks for better browser caching
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          firebase: ['firebase/app', 'firebase/auth', 'firebase/firestore'],
        },
      },
    },
  },

  server: {
    // In development, Vite proxies API calls to the Express server
    // so you don't get CORS errors when running both on different ports
    proxy: {
      '/api': { target: 'http://localhost:3000', changeOrigin: true },
      '/uploads': { target: 'http://localhost:3000', changeOrigin: true },
    },
  },
});
