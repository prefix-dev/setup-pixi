import fs from 'fs/promises'
import path from 'path'
import * as core from '@actions/core'
import * as cache from '@actions/cache'
import { options } from './options'
import { getCondaArch, sha256 } from './util'

export const generateProjectCacheKey = async (cacheKeyPrefix: string) => {
  try {
    const [lockfileContent, pixiBinary] = await Promise.all([
      fs.readFile(options.pixiLockFile),
      fs.readFile(options.pixiBinPath)
    ])
    const lockfileSha = sha256(lockfileContent)
    core.debug(`lockfileSha: ${lockfileSha}`)
    const pixiSha = sha256(pixiBinary)
    core.debug(`pixiSha: ${pixiSha}`)
    // the path to the lock file decides where the pixi env is created (../.pixi/env)
    // since conda envs are not relocatable, we need to include the path in the cache key
    const lockfilePathSha = sha256(options.pixiLockFile)
    core.debug(`lockfilePathSha: ${lockfilePathSha}`)
    const environments = sha256(options.environments?.join(' ') ?? '')
    core.debug(`environments: ${environments}`)
    // since the lockfile path is not necessarily absolute, we need to include the cwd in the cache key
    const cwdSha = sha256(process.cwd())
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
    const pixiBinary = await fs.readFile(options.pixiBinPath)
    const pixiSha = sha256(pixiBinary)
    core.debug(`pixiSha: ${pixiSha}`)
    const globalEnvironments = sha256(options.globalEnvironments?.join(' ') ?? '')
    core.debug(`globalEnvironments: ${globalEnvironments}`)
    const sha = sha256(globalEnvironments + pixiSha)
    core.debug(`sha: ${sha}`)
    return `${cacheKeyPrefix}${getCondaArch()}-${sha}`
  } catch (err: unknown) {
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    throw new Error(`Failed to generate cache key: ${err}`)
  }
}

const projectCachePath = path.join(path.dirname(options.pixiLockFile), '.pixi')

const getGlobalCachePath = () => {
  const home = process.env.HOME
  if (!home) {
    throw new Error('HOME environment variable is not set.')
  }
  return path.join(home, '.pixi', 'envs')
}

let projectCacheHit = false
let globalCacheHit = false

export const tryRestoreProjectCache = async (): Promise<string | undefined> => {
  const cache_ = options.cache
  if (!cache_) {
    core.debug('Skipping pixi cache restore.')
    return undefined
  }
  return core.group('Restoring pixi cache', async () => {
    const cacheKey = await generateProjectCacheKey(cache_.projectCacheKeyPrefix)
    core.debug(`Cache key: ${cacheKey}`)
    core.debug(`Cache path: ${projectCachePath}`)
    const key = await cache.restoreCache([projectCachePath], cacheKey, undefined, undefined, false)
    if (key) {
      core.info(`Restored cache with key \`${key}\``)
      projectCacheHit = true
    } else {
      core.info(`Cache miss`)
    }
    return key
  })
}

export const tryRestoreGlobalCache = async (): Promise<boolean> => {
  const cache_ = options.cache
  if (!cache_ || !options.globalEnvironments || options.globalEnvironments.length === 0) {
    core.debug('Skipping global cache restore.')
    return false
  }
  return core.group('Restoring global cache', async () => {
    const cacheKey = await generateGlobalCacheKey(cache_.globalCacheKeyPrefix)
    const cachePath = getGlobalCachePath()
    core.debug(`Cache key: ${cacheKey}`)
    core.debug(`Cache path: ${cachePath}`)
    const key = await cache.restoreCache([cachePath], cacheKey, undefined, undefined, false)
    if (key) {
      core.info(`Restored cache with key \`${key}\``)
      globalCacheHit = true
    } else {
      core.info(`Cache miss`)
    }
    return globalCacheHit
  })
}

export const saveProjectCache = async () => {
  const cache_ = options.cache
  if (!cache_?.cacheWrite || !options.runInstall) {
    core.debug('Skipping project cache save.')
    return
  }
  if (projectCacheHit) {
    core.debug('Skipping project cache save because cache was restored.')
    return
  }
  await core.group('Saving project cache', async () => {
    const cacheKey = await generateProjectCacheKey(cache_.projectCacheKeyPrefix)
    try {
      const cacheId = await cache.saveCache([projectCachePath], cacheKey, undefined, false)
      core.info(`Saved cache with ID "${cacheId.toString()}"`)
    } catch (err: unknown) {
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
      core.error(`Error saving cache: ${err}`)
    }
  })
}

export const saveGlobalCache = async () => {
  const cache_ = options.cache
  if (!cache_?.cacheWrite || !options.globalEnvironments || options.globalEnvironments.length === 0) {
    core.debug('Skipping global cache save.')
    return
  }
  if (globalCacheHit) {
    core.debug('Skipping global cache save because cache was restored.')
    return
  }
  await core.group('Saving global cache', async () => {
    const cacheKey = await generateGlobalCacheKey(cache_.globalCacheKeyPrefix)
    try {
      const cacheId = await cache.saveCache([getGlobalCachePath()], cacheKey, undefined, false)
      core.info(`Saved cache with ID "${cacheId.toString()}"`)
    } catch (err: unknown) {
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
      core.error(`Error saving cache: ${err}`)
    }
  })
}
