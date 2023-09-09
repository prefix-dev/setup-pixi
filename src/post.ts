import fs from 'fs/promises'
import path from 'path'
import * as os from 'os'
import * as core from '@actions/core'
import { options } from './options'

const cleanupPixiBin = () => {
  const pixiBinPath = options.pixiBinPath
  const pixiBinDir = path.dirname(pixiBinPath)
  core.debug(`Cleaning up pixi binary ${pixiBinPath}.`)
  return fs
    .rm(options.pixiBinPath)
    .then(() => fs.readdir(pixiBinDir))
    .then((files) => {
      if (files.length === 0) {
        core.debug(`Removing empty directory ${pixiBinDir}.`)
        return fs.rm(pixiBinDir, { recursive: true })
      }
      return Promise.resolve()
    })
}

const cleanupEnv = () => {
  if (!options.runInstall) {
    core.debug('Skipping cleanup of .pixi directory.')
  }
  const envDir = path.join(path.dirname(options.manifestPath), '.pixi')
  core.debug(`Cleaning up .pixi directory ${envDir}.`)
  fs.rm(envDir, { recursive: true })
}

const cleanupRattler = () => {
  const rattlerPath = path.join(os.homedir(), '.rattler')
  const rattlerCachePath = path.join(os.homedir(), '.cache', 'rattler')
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
