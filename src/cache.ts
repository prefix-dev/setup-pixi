import fs from 'fs/promises'
import path from 'path'
import * as core from '@actions/core'
import * as cache from '@actions/cache'
import { options } from './options'
import { getCondaArch, sha256 } from './util'

export const generateCacheKey = async (cacheKeyPrefix: string) =>
  fs
    .readFile(options.pixiLockFile, 'utf-8')
    .then((content) => `${cacheKeyPrefix}${getCondaArch()}-${sha256(content)}`)
    .catch((err) => {
      throw new Error(`Failed to generate cache key: ${err}`)
    })

const cachePath = path.join(path.dirname(options.pixiLockFile), '.pixi')

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
          core.saveState('cache-hit', 'true')
        } else {
          core.info(`Cache miss`)
          core.saveState('cache-hit', 'false')
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
  const cacheHit = core.getState('cache-hit')
  if (cacheHit === 'true') {
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
