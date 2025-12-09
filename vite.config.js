import { defineConfig } from 'vite';

export default defineConfig({
    // Ensure relative paths in the build output so it can be hosted on any static path
    base: './',
    server: {
        port: 3000,
        open: true
    },
    build: {
        outDir: 'dist',
        assetsDir: 'assets'
    }
});
