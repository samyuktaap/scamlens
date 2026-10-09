import { defineConfig, loadEnv } from 'vite';
import { resolve } from 'path';
import fs from 'fs';

// Plugin to copy extension files to dist after build
function copyExtensionFiles() {
  return {
    name: 'copy-extension-files',
    closeBundle() {
      // Copy manifest.json
      if (fs.existsSync('manifest.json')) {
        fs.copyFileSync('manifest.json', 'dist/manifest.json');
      }

      // Copy background scripts
      const scriptsDir = 'dist/src/scripts';
      if (!fs.existsSync(scriptsDir)) fs.mkdirSync(scriptsDir, { recursive: true });
      if (fs.existsSync('src/scripts/background.js')) fs.copyFileSync('src/scripts/background.js', `${scriptsDir}/background.js`);
      if (fs.existsSync('src/scripts/content.js')) fs.copyFileSync('src/scripts/content.js', `${scriptsDir}/content.js`);
      if (fs.existsSync('src/scripts/fingerprinter-shield.js')) fs.copyFileSync('src/scripts/fingerprinter-shield.js', `${scriptsDir}/fingerprinter-shield.js`);
      if (fs.existsSync('src/scripts/telemetry.js')) fs.copyFileSync('src/scripts/telemetry.js', `${scriptsDir}/telemetry.js`);
      if (fs.existsSync('src/scripts/rules.js')) fs.copyFileSync('src/scripts/rules.js', `${scriptsDir}/rules.js`);

      // Copy page JS files that aren't bundled
      const pagesDir = 'dist/src/pages';
      if (!fs.existsSync(pagesDir)) fs.mkdirSync(pagesDir, { recursive: true });
      fs.readdirSync('src/pages').forEach(file => {
        if (file.endsWith('.js')) {
          fs.copyFileSync(`src/pages/${file}`, `${pagesDir}/${file}`);
        }
      });

      console.log('[ScamLens] Extension files copied to dist/');
    }
  };
}

export default defineConfig(({ mode }) => {
  // Load .env variables (supports .env, .env.local, .env.development, etc.)
  const env = loadEnv(mode, process.cwd(), '');

  return {
    root: '.',
    base: './',
    publicDir: 'public',
    plugins: [copyExtensionFiles()],

    // Inject VITE_ env vars as build-time constants accessible in JS as __ENV__.*
    define: {
      '__ENV__.GEMINI_API_KEY': JSON.stringify(env.VITE_GEMINI_API_KEY || ''),
      '__ENV__.BACKEND_URL':    JSON.stringify(env.VITE_BACKEND_URL    || ''),
      '__ENV__.SHARED_TOKEN':   JSON.stringify(env.VITE_SHARED_TOKEN   || 'scamlens-demo-token'),
    },

    build: {
      outDir: 'dist',
      rollupOptions: {
        input: {
          main:      resolve(__dirname, 'index.html'),
          dashboard: resolve(__dirname, 'src/pages/dashboard.html'),
          pro:       resolve(__dirname, 'src/pages/pro.html'),
          onboard:   resolve(__dirname, 'src/pages/onboard.html'),
          report:    resolve(__dirname, 'src/pages/report.html'),
          popup:     resolve(__dirname, 'src/pages/popup.html'),
          whatif:    resolve(__dirname, 'src/pages/whatif.html'),
          history:   resolve(__dirname, 'src/pages/history.html'),
        },
      },
    },
  };
});
