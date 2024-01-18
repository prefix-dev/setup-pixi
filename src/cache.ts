import fs from 'fs/promises'
import path from 'path'
import * as core from '@actions/core'
import * as cache from '@actions/cache'
import { options } from './options'
import { getCondaArch, sha256 } from './util'

export const generateCacheKey = async (cacheKeyPrefix: string) =>
  Promise.all([fs.readFile(options.pixiLockFile), fs.readFile(options.pixiBinPath)])
    .then(([lockfileContent, pixiBinary]) => {
      const lockfileSha = sha256(lockfileContent)
      core.debug(`lockfileSha: ${lockfileSha}`)
      const pixiSha = sha256(pixiBinary)
      core.debug(`pixiSha: ${pixiSha}`)
      // the path to the lock file decides where the pixi env is created (../.pixi/env)
      // since conda envs are not relocatable, we need to include the path in the cache key
      const lockfilePathSha = sha256(options.pixiLockFile)
      core.debug(`lockfilePathSha: ${lockfilePathSha}`)
      const sha = sha256(lockfileSha + lockfilePathSha + pixiSha)
      core.debug(`sha: ${sha}`)
      return `${cacheKeyPrefix}${getCondaArch()}-${sha}`
    })
    .catch((err) => {
      throw new Error(`Failed to generate cache key: ${err}`)
    })

const cachePath = path.join(path.dirname(options.pixiLockFile), '.pixi')

let cacheHit = false

export const tryRestoreCache = (): Promise<string | undefined> => {
  const cache_ = options.cache
  if (!cache_) {
    core.debug('Skipping pixi cache restore.')
    return Promise.resolve(undefined)
  }
  return core.group('Restoring pixi cache', () =>
    generateCacheKey(cache_.cacheKeyPrefix).then((cacheKey) => {
      core.debug(`Cache key: ${cacheKey}`)
      core.debug(`Cache path: ${cachePath}`)
      return cache.restoreCache([cachePath], cacheKey, undefined, undefined, false).then((key) => {
        if (key) {
          core.info(`Restored cache with key \`${key}\``)
          cacheHit = true
        } else {
          core.info(`Cache miss`)
        }
        return key
      })
    })
  )
}

export const saveCache = () => {
  const cache_ = options.cache
  if (!cache_ || !cache_.cacheWrite) {
    core.debug('Skipping pixi cache save.')
    return Promise.resolve(undefined)
  }
  if (cacheHit) {
    core.debug('Skipping pixi cache save because cache was restored.')
    return Promise.resolve(undefined)
  }
  return core.group('Saving pixi cache', () =>
    generateCacheKey(cache_.cacheKeyPrefix).then((cacheKey) =>
      cache
        .saveCache([cachePath], cacheKey, undefined, false)
        .then((cacheId) => {
          core.info(`Saved cache with ID \`${cacheId}\``)
        })
        .catch((err) => {
          core.error(`Error saving cache: ${err.message}`)
        })
    )
  )
}
