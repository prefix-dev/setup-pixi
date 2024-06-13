import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/main.ts',
    post: 'src/post.ts'
  },
  dts: false,
  clean: true,
  target: 'es2020',
  format: ['esm'],
  sourcemap: true,
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
    'untildify',
    '@iarna/toml',
    'which',
    'zod'
  ]
})
