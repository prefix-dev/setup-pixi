import fs from 'fs/promises'
import path from 'path'
import * as os from 'os'
import * as core from '@actions/core'
import { options } from './options'

const cleanupPixiBin = () => {
  const pixiBinPath = options.pixiBinPath
  const pixiBinDir = path.dirname(pixiBinPath)
  return fs
    .rm(options.pixiBinPath)
    .then(() => fs.readdir(pixiBinDir))
    .then((files) => {
      if (files.length === 0) {
        return fs.rm(pixiBinDir)
      }
      return Promise.resolve()
    })
}

const cleanupEnv = () => {
  if (!options.runInstall) {
    core.debug('Skipping cleanup of .pixi directory.')
  }
  fs.rm(path.join(path.dirname(options.manifestPath), '.pixi'), { recursive: true })
}

const cleanupRattler = () => {
  const rattlerPath = path.join(os.homedir(), '.rattler')
  const rattlerCachePath = path.join(os.homedir(), '.cache', 'rattler')
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
