import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// The build lands in internal/web/dist, which the Go server embeds.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: { outDir: '../internal/web/dist', emptyOutDir: true },
  // `npm run dev` proxies the API to a locally running server or demo.
  server: { proxy: { '/api': 'http://127.0.0.1:8080' } },
  test: { environment: 'node' },
})
