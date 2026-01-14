import { defineConfig } from 'vite';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
    build: {
        lib: {
            entry: resolve(__dirname, 'src/index.ts'),
            name: 'JellyHA',
            fileName: 'jellyha',
            formats: ['es'],
        },
        rollupOptions: {
            output: {
                entryFileNames: 'jellyha-cards.js',
            },
        },
        target: 'es2021',
        minify: true,
        sourcemap: true,
    },
});

