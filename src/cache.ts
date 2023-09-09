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
  const cacheKeyPrefix = options.cacheKey
  if (!cacheKeyPrefix) {
    core.debug('Skipping pixi cache restore.')
    return Promise.resolve(undefined)
  }
  return core.group('Restoring pixi cache', () =>
    generateCacheKey(cacheKeyPrefix).then((cacheKey) => {
      core.debug(`Cache key: ${cacheKey}`)
      core.debug(`Cache path: ${cachePath}`)
      return cache.restoreCache([cachePath], cacheKey, undefined, undefined, false).then((key) => {
        if (key) {
          core.info(`Restored cache with key \`${key}\``)
        } else {
          core.info(`Cache miss`)
        }
        return key
      })
    })
  )
}

export const saveCache = () => {
  const cacheKeyPrefix = options.cacheKey
  if (!cacheKeyPrefix) {
    core.debug('Skipping pixi cache save.')
    return Promise.resolve(undefined)
  }
  return core.group('Saving pixi cache', () =>
    generateCacheKey(cacheKeyPrefix).then((cacheKey) =>
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
