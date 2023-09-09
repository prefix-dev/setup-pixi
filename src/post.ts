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

const cleanupEnv = () => fs.rm(path.join(path.dirname(options.manifestPath), '.pixi'), { recursive: true })

const cleanupRattler = () =>
  Promise.all([
    fs.rm(path.join(os.homedir(), '.rattler'), { recursive: true }),
    fs.rm(path.join(os.homedir(), '.cache', 'rattler'), { recursive: true })
  ])

const run = () => {
  const postCleanup = options.postCleanup
  if (postCleanup) {
    return Promise.all([cleanupPixiBin(), cleanupEnv(), cleanupRattler()])
  }
  core.debug('Skipping post-cleanup.')
  return Promise.resolve()
}

run()
