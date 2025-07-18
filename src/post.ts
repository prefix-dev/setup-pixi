import fs from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import os from 'os'
import { exit } from 'process'
import * as core from '@actions/core'
import { options } from './options'

const removeEmptyParentDirs = (dirPath: string): Promise<void> => {
  if (existsSync(dirPath)) {
    return fs.readdir(dirPath).then((files) => {
      if (files.length === 0) {
        core.debug(`Removing empty directory ${dirPath}.`)
        return fs.rm(dirPath, { recursive: true, force: true }).then(() => {
          const parentDir = path.dirname(dirPath)
          if (parentDir !== dirPath) {
            return removeEmptyParentDirs(parentDir)
          }
        })
      }
    })
  }
  return Promise.resolve()
}

const cleanupPixiBin = () => {
  const pixiBinPath = options.pixiBinPath
  const pixiBinDir = path.dirname(pixiBinPath)
  core.debug(`Cleaning up pixi binary ${pixiBinPath}.`)
  if (existsSync(pixiBinPath)) {
    return fs.rm(pixiBinPath).then(() => removeEmptyParentDirs(pixiBinDir))
  } else {
    return removeEmptyParentDirs(pixiBinDir)
  }
}

const cleanupEnv = () => {
  if (!options.runInstall) {
    core.debug('Skipping cleanup of .pixi directory.')
    return Promise.resolve()
  }
  const envDir = path.join(path.dirname(options.manifestPath), '.pixi')
  core.debug(`Cleaning up .pixi directory ${envDir}.`)
  return fs.rm(envDir, {
    recursive: true,
    // Ignore exceptions if environment does not exist anymore,
    // to avoid errors if setup-pixi is used multiple times within the same workflow.
    force: true
  })
}

const determineCacheDir = (): string => {
  // rattler uses dirs::cache_dir https://docs.rs/dirs/latest/dirs/fn.cache_dir.html
  if (os.platform() === 'win32') {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return process.env.LOCALAPPDATA!
  }
  if (os.platform() === 'linux') {
    return process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), '.cache')
  }
  return path.join(os.homedir(), 'Library', 'Caches')
}

const cleanupRattler = () => {
  const rattlerPath = path.join(os.homedir(), '.rattler')
  const cacheDir = determineCacheDir()
  const rattlerCachePath = path.join(cacheDir, 'rattler')
  core.debug(`Cleaning up rattler directories ${rattlerPath} and ${rattlerCachePath}.`)
  return Promise.all([
    fs.rm(rattlerPath, { recursive: true, force: true }),
    fs.rm(rattlerCachePath, { recursive: true, force: true })
  ])
}

const run = () => {
  const postCleanup = options.postCleanup
  if (postCleanup) {
    return Promise.all([cleanupPixiBin(), cleanupEnv(), cleanupRattler()])
  }
  core.debug('Skipping post-cleanup.')
  return Promise.resolve()
}

run()
  .then(() => exit(0)) // workaround for https://github.com/actions/toolkit/issues/1578
  .catch((error: unknown) => {
    if (core.isDebug()) {
      throw error
    }
    if (error instanceof Error) {
      core.setFailed(error.message)
      exit(1)
    } else if (typeof error === 'string') {
      core.setFailed(error)
      exit(1)
    }
    throw error
  })
