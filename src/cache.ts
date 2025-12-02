import fs from 'fs/promises'
import path from 'path'
import * as core from '@actions/core'
import * as cache from '@actions/cache'
import { options } from './options'
import { getCondaArch, sha256 } from './util'

const getYearMonth = () => {
  // this gets us the current month formatted as YYYY-MM
  return new Date().toLocaleDateString('en-CA', { year: 'numeric', month: '2-digit' })
}

let pixiSha: string | undefined
const getPixiSha = async () => {
  if (pixiSha) {
    return pixiSha
  }
  const pixiBinary = await fs.readFile(options.pixiBinPath)
  pixiSha = sha256(pixiBinary)
  return pixiSha
}

export const generateProjectCacheKey = async (cacheKeyPrefix: string) => {
  try {
    const [lockfileContent, pixiSha] = await Promise.all([fs.readFile(options.pixiLockFile), getPixiSha()])
    const lockfileSha = sha256(lockfileContent)
    core.debug(`lockfileSha: ${lockfileSha}`)
    core.debug(`pixiSha: ${pixiSha}`)
    // the path to the lock file decides where the pixi env is created (../.pixi/env)
    // since conda envs are not relocatable, we need to include the path in the cache key
    const lockfilePathSha = sha256(options.pixiLockFile)
    core.debug(`lockfilePathSha: ${lockfilePathSha}`)
    const environments = sha256(options.environments?.join(' ') ?? '')
    core.debug(`environments: ${environments}`)
    // since the lockfile path is not necessarily absolute, we need to include the working directory in the cache key
    const cwdSha = sha256(options.workingDirectory)
    core.debug(`cwdSha: ${cwdSha}`)
    const sha = sha256(lockfileSha + environments + pixiSha + lockfilePathSha + cwdSha)
    core.debug(`sha: ${sha}`)
    return `${cacheKeyPrefix}${getCondaArch()}-${sha}`
  } catch (err: unknown) {
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    throw new Error(`Failed to generate cache key: ${err}`)
  }
}

export const generateGlobalCacheKey = async (cacheKeyPrefix: string) => {
  try {
    const pixiSha = await getPixiSha()
    core.debug(`pixiSha: ${pixiSha}`)
    const globalEnvironments = sha256(options.globalEnvironments?.join(' ') ?? '')
    core.debug(`globalEnvironments: ${globalEnvironments}`)
    const sha = sha256(globalEnvironments + pixiSha + getGlobalCachePath())
    core.debug(`sha: ${sha}`)
    return `${cacheKeyPrefix}${getCondaArch()}-${getYearMonth()}-${sha}`
  } catch (err: unknown) {
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    throw new Error(`Failed to generate cache key: ${err}`)
  }
}

const projectCachePath = path.join(path.dirname(options.pixiLockFile), '.pixi')

const getGlobalCachePath = () => {
  const pixiHome = process.env.PIXI_HOME
  if (pixiHome) {
    return path.join(pixiHome, 'envs')
  }

  const home = process.env.HOME
  if (home) {
    return path.join(home, '.pixi', 'envs')
  }

  throw new Error('Neither PIXI_HOME nor HOME environment variables are set.')
}

let projectCacheHit = false
let globalCacheHit = false

async function _tryRestoreCache(
  type: 'project' | 'global',
  keyPrefix: string,
  generateKey: (prefix: string) => Promise<string>,
  cachePath: string,
  onHit: () => void
): Promise<string | undefined> {
  return core.group(`Restoring ${type} cache`, async () => {
    const cacheKey = await generateKey(keyPrefix)
    core.debug(`Cache key: ${cacheKey}`)
    core.debug(`Cache path: ${cachePath}`)
    const key = await cache.restoreCache([cachePath], cacheKey, undefined, undefined, false)
    if (key) {
      core.info(`Restored cache with key \`${key}\``)
      onHit()
    } else {
      core.info(`Cache miss`)
    }
    return key
  })
}

async function _saveCache(
  type: 'project' | 'global',
  wasHit: boolean,
  keyPrefix: string,
  generateKey: (prefix: string) => Promise<string>,
  cachePath: string
) {
  if (wasHit) {
    core.debug(`Skipping ${type} cache save because cache was restored.`)
    return
  }

  await core.group(`Saving ${type.toLowerCase()} cache`, async () => {
    const cacheKey = await generateKey(keyPrefix)
    try {
      const cacheId = await cache.saveCache([cachePath], cacheKey, undefined, false)
      core.info(`Saved cache with ID "${cacheId.toString()}"`)
    } catch (err: unknown) {
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
      core.error(`Error saving ${type} cache: ${err}`)
    }
  })
}

export const tryRestoreProjectCache = async (): Promise<string | undefined> => {
  const cache_ = options.cache
  if (!cache_) {
    core.debug('Skipping project cache restore.')
    return undefined
  }
  return _tryRestoreCache('project', cache_.cacheKeyPrefix, generateProjectCacheKey, projectCachePath, () => {
    projectCacheHit = true
  })
}

export const tryRestoreGlobalCache = async (): Promise<string | undefined> => {
  const cache_ = options.globalCache
  if (!cache_ || !options.globalEnvironments || options.globalEnvironments.length === 0) {
    core.debug('Skipping global cache restore.')
    return undefined
  }
  return _tryRestoreCache('global', cache_.cacheKeyPrefix, generateGlobalCacheKey, getGlobalCachePath(), () => {
    globalCacheHit = true
  })
}

export const saveProjectCache = async () => {
  const cache_ = options.cache
  if (!cache_?.cacheWrite || !options.runInstall) {
    core.debug('Skipping project cache save.')
    return
  }
  await _saveCache('project', projectCacheHit, cache_.cacheKeyPrefix, generateProjectCacheKey, projectCachePath)
}

export const saveGlobalCache = async () => {
  const cache_ = options.globalCache
  if (!cache_?.cacheWrite || !options.globalEnvironments || options.globalEnvironments.length === 0) {
    core.debug('Skipping global cache save.')
    return
  }
  await _saveCache('global', globalCacheHit, cache_.cacheKeyPrefix, generateGlobalCacheKey, getGlobalCachePath())
}
