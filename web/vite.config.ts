import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    minify: 'esbuild',
    rollupOptions: {
      output: {
        // Single bundle — no code splitting to keep embed simple.
        manualChunks: undefined,
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    // In dev Vite runs on 5173; Go UI server runs on 7890.
    // Production: Go serves the built dist at 7890 with no Vite.
    proxy: {
      '/api': 'http://127.0.0.1:7890',
      '/v1': 'http://127.0.0.1:7890',
      '/__bootstrap': 'http://127.0.0.1:7890',
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
    },
  },
})
