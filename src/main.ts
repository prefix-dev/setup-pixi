import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import * as core from '@actions/core'
import { downloadTool } from '@actions/tool-cache'
import type { PixiSource } from './options'
import { PATHS, options } from './options'
import { execute, getPixiUrlFromVersion, pixiCmd } from './util'
import { saveCache, tryRestoreCache } from './cache'

const downloadPixi = (source: PixiSource) => {
  const url = 'version' in source ? getPixiUrlFromVersion(source.version) : source.url
  return core.group('Downloading Pixi', () => {
    core.debug('Installing pixi')
    core.debug(`Downloading pixi from ${url}`)
    return fs
      .mkdir(path.dirname(options.pixiBinPath), { recursive: true })
      .then(() => downloadTool(url, options.pixiBinPath))
      .then((_downloadPath) => fs.chmod(options.pixiBinPath, 0o755))
      .then(() => core.info(`Pixi installed to ${options.pixiBinPath}`))
  })
}

const pixiLogin = () => {
  const auth = options.auth
  if (!auth) {
    core.debug('Skipping pixi login.')
    return Promise.resolve(0)
  }
  return core.group('Logging in to private channel', () => {
    // tokens get censored in the logs as long as they are a github secret
    if ('token' in auth) {
      core.debug(`Logging in to ${auth.host} with token`)
      return execute(pixiCmd(`auth login --token ${auth.token} ${auth.host}`, false))
    }
    if ('username' in auth) {
      core.debug(`Logging in to ${auth.host} with username and password`)
      return execute(pixiCmd(`auth login --username ${auth.username} --password ${auth.password} ${auth.host}`, false))
    }
    core.debug(`Logging in to ${auth.host} with conda token`)
    return execute(pixiCmd(`auth login --conda-token ${auth.condaToken} ${auth.host}`, false))
  })
}

const addPixiToPath = () => {
  core.addPath(path.dirname(options.pixiBinPath))
}

const pixiInstall = async () => {
  if (!options.runInstall) {
    core.debug('Skipping pixi install.')
    return Promise.resolve()
  }
  return tryRestoreCache()
    .then((_cacheKey) => execute(pixiCmd('install')))
    .then(saveCache)
}

const generatePixiRunShell = () => {
  if (!options.generateRunShell) {
    core.debug('Skipping pixi run shell generation.')
    return Promise.resolve()
  }
  if (os.platform() === 'win32') {
    core.info('Skipping pixi run shell on Windows.')
    return Promise.resolve()
  }
  core.info('Generating pixi run shell.')
  const pixiRunShellContents = `#!/usr/bin/env sh
chmod +x $1
pixi run $1
`
  return core.group('Generating pixi run shell', () => {
    core.debug(`Writing pixi run shell to ${PATHS.pixiRunShellScript}`)
    core.debug(`File contents:\n"${pixiRunShellContents}"`)
    return fs.writeFile(PATHS.pixiRunShellScript, pixiRunShellContents, { encoding: 'utf8', mode: 0o755 })
  })
}

const generateInfo = () => core.group('pixi info', () => execute(pixiCmd('info')))

const run = async () => {
  core.debug(`process.env.HOME: ${process.env.HOME}`)
  core.debug(`os.homedir(): ${os.homedir()}`)
  core.debug(`bashProfile ${PATHS.bashProfile}`)
  await downloadPixi(options.pixiSource)
  addPixiToPath()
  await pixiLogin()
  await pixiInstall()
  await generatePixiRunShell()
  await generateInfo()
}

run().catch((error) => core.setFailed(error.message))
