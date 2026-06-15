import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'

// Built assets are embedded into the Go binary via internal/adminui
// (go:embed all:dist) and served under /admin/. base:'./' keeps asset URLs
// relative so they resolve correctly behind the /admin/ StripPrefix mount.
export default defineConfig({
  base: './',
  plugins: [svelte(), tailwindcss()],
  server: {
    proxy: {
      '/admin/api': 'http://localhost:8443',
    },
  },
  build: {
    outDir: '../internal/adminui/dist',
    emptyOutDir: true,
  },
})
