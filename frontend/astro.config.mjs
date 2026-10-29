// @ts-check
import { defineConfig } from 'astro/config';

export default defineConfig({
  vite: {
    server: {
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:3000',
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  },
});
