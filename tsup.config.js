import { defineConfig } from 'tsup'
import packageJson from './package.json' with { type: 'json' }

export default defineConfig({
  entry: {
    index: 'src/main.ts',
    post: 'src/post.ts'
  },
  dts: false,
  clean: true,
  target: 'es2020',
  format: 'cjs',
  sourcemap: false,
  platform: 'node',
  minify: false,
  // shim `import.meta.url` in CJS output; some deps (e.g. @azure/storage-common) rely on it
  shims: true,
  define: {
    __SETUP_PIXI_VERSION__: JSON.stringify(packageJson.version)
  },
  outExtension() {
    return {
      js: '.js'
    }
  },
  // need to bundle dependencies because they aren't available otherwise when run inside the action
  noExternal: [
    '@actions/core',
    '@actions/exec',
    '@actions/http-client',
    '@actions/cache',
    '@actions/io',
    '@actions/tool-cache',
    '@sigstore/bundle',
    '@sigstore/protobuf-specs',
    '@sigstore/tuf',
    '@sigstore/verify',
    'handlebars',
    'untildify',
    'smol-toml',
    'undici',
    'which',
    'zod'
  ]
})
