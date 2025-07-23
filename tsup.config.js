import { defineConfig } from 'tsup'

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
  outExtension() {
    return {
      js: '.js'
    }
  },
  // need to bundle dependencies because they aren't available otherwise when run inside the action
  noExternal: [
    '@actions/core',
    '@actions/exec',
    '@actions/cache',
    '@actions/io',
    '@actions/tool-cache',
    'handlebars',
    'untildify',
    'smol-toml',
    'which',
    'zod'
  ]
})
