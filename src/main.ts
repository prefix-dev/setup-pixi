import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { exit } from 'process'
import * as core from '@actions/core'
import { downloadTool } from '@actions/tool-cache'
import type { PixiSource } from './options'
import { options } from './options'
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
  core.debug(`auth keys: ${Object.keys(auth)}`)
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
    .then(async (_cacheKey) => {
      if (options.environments) {
        for (const environment of options.environments) {
          core.debug(`Installing environment ${environment}`)
          const command = `install -e ${environment}${options.frozen ? ' --frozen' : ''}${
            options.locked ? ' --locked' : ''
          }`
          await core.group(`pixi ${command}`, () => execute(pixiCmd(command)))
        }
      } else {
        const command = `install${options.frozen ? ' --frozen' : ''}${options.locked ? ' --locked' : ''}`
        return core.group(`pixi ${command}`, () => execute(pixiCmd(command)))
      }
    })
    .then(saveCache)
}

const generateList = async () => {
  if (!options.runInstall) {
    core.debug('Skipping pixi list.')
    return Promise.resolve()
  }
  if (
    'version' in options.pixiSource &&
    options.pixiSource.version !== 'latest' &&
    options.pixiSource.version < 'v0.13.0'
  ) {
    core.warning(
      'pixi list is not supported for pixi versions < `v0.13.0`. Please set `pixi-version` to `v0.13.0` or later.'
    )
    return Promise.resolve()
  }
  let command = 'list'
  if (
    'version' in options.pixiSource &&
    options.pixiSource.version !== 'latest' &&
    options.pixiSource.version < 'v0.14.0'
  ) {
    if (options.frozen) core.warning('pixi versions < `v0.14.0` do not support the --frozen option for pixi list.')
    if (options.locked) core.warning('pixi versions < `v0.14.0` do not support the --locked option for pixi list.')
  } else {
    command = `${command}${options.frozen ? ' --frozen' : ''}${options.locked ? ' --locked' : ''}`
  }
  if (options.environments) {
    for (const environment of options.environments) {
      core.debug(`Listing environment ${environment}`)
      await core.group(`pixi ${command} -e ${environment}`, () => execute(pixiCmd(`${command} -e ${environment}`)))
    }
    return Promise.resolve()
  } else {
    return core.group(`pixi ${command}`, () => execute(pixiCmd(command)))
  }
}

const generateInfo = () => core.group('pixi info', () => execute(pixiCmd('info')))

const run = async () => {
  core.debug(`process.env.HOME: ${process.env.HOME}`)
  core.debug(`os.homedir(): ${os.homedir()}`)
  await downloadPixi(options.pixiSource)
  addPixiToPath()
  await pixiLogin()
  await pixiInstall()
  await generateInfo()
  await generateList()
}

run().catch((error) => {
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
