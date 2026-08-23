import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Build lands in webui/dist, which go:embed bakes into overmesh-server.
export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    // `npm run dev` against a locally running overmesh-server.
    proxy: { '/api': 'http://localhost:8080' },
  },
})
