// @ts-check
import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
  vite: {
    server: {
      // przeglądarka woła /api/* na tym samym originie, więc ciasteczko sesji działa bez CORS
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:3000',
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  },
});
