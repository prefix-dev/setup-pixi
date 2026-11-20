// Updates the trust material in src/trusted-root/ from GitHub's TUF repository.
// The TUF client only accepts new metadata that is signed by the keys of the currently bundled root,
// so this script never needs to trust anything that isn't already bundled.
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import { getTrustedRoot } from '@sigstore/tuf'

const MIRROR_URL = 'https://tuf-repo.github.com'
const trustedRootDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'trusted-root')
const tufRootPath = path.join(trustedRootDir, 'tuf-root.json')
const trustedRootPath = path.join(trustedRootDir, 'trusted_root.json')

const cachePath = await fs.mkdtemp(path.join(os.tmpdir(), 'setup-pixi-tuf-'))
try {
  await getTrustedRoot({ mirrorURL: MIRROR_URL, rootPath: tufRootPath, cachePath, forceInit: true })
  const repoCache = path.join(cachePath, new URL(MIRROR_URL).host)
  await fs.copyFile(path.join(repoCache, 'root.json'), tufRootPath)
  await fs.copyFile(path.join(repoCache, 'targets', 'trusted_root.json'), trustedRootPath)
  const { signed } = JSON.parse(await fs.readFile(tufRootPath, 'utf8'))
  console.log(`Updated TUF root to version ${signed.version} and refreshed trusted_root.json.`)
} finally {
  await fs.rm(cachePath, { recursive: true, force: true })
}
