import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { exit } from 'process'
import * as core from '@actions/core'
import { downloadTool } from '@actions/tool-cache'
import type { PixiSource } from './options'
import { options } from './options'
import { execute, pixiCmd, renderPixiUrl } from './util'
import { tryRestoreGlobalCache, tryRestoreProjectCache, saveGlobalCache, saveProjectCache } from './cache'
import { activateEnvironment } from './activate'

const downloadPixi = async (source: PixiSource) => {
  const url = renderPixiUrl(source.urlTemplate, source.version)
  await core.group('Downloading Pixi', async () => {
    core.debug('Installing pixi')
    core.debug(`Downloading pixi from ${url}`)
    core.debug(`Using headers: ${JSON.stringify(source.headers)}`)
    await fs.mkdir(path.dirname(options.pixiBinPath), { recursive: true })
    await downloadTool(url, options.pixiBinPath, undefined, source.headers)
    await fs.chmod(options.pixiBinPath, 0o755)
    core.info(`Pixi installed to ${options.pixiBinPath}`)
  })
}

const pixiLogin = async () => {
  const auth = options.auth
  if (!auth) {
    core.debug('Skipping pixi login.')
    return
  }
  core.debug(`auth keys: ${Object.keys(auth).toString()}`)
  await core.group('Logging in to private channel', async () => {
    // tokens get censored in the logs as long as they are a github secret
    if ('token' in auth) {
      core.debug(`Logging in to ${auth.host} with token`)
      await execute(pixiCmd(`auth login --token ${auth.token} ${auth.host}`, false))
    } else if ('username' in auth) {
      core.debug(`Logging in to ${auth.host} with username and password`)
      await execute(pixiCmd(`auth login --username ${auth.username} --password ${auth.password} ${auth.host}`, false))
    } else if ('s3AccessKeyId' in auth) {
      core.debug(`Logging in to ${auth.host} with s3 credentials`)
      const command = auth.s3SessionToken
        ? `auth login --s3-access-key-id ${auth.s3AccessKeyId} --s3-secret-access-key ${auth.s3SecretAccessKey} --s3-session-token ${auth.s3SessionToken} ${auth.host}`
        : `auth login --s3-access-key-id ${auth.s3AccessKeyId} --s3-secret-access-key ${auth.s3SecretAccessKey} ${auth.host}`
      await execute(pixiCmd(command, false))
    } else if ('condaToken' in auth) {
      core.debug(`Logging in to ${auth.host} with conda token`)
      await execute(pixiCmd(`auth login --conda-token ${auth.condaToken} ${auth.host}`, false))
    }
  })
}

const addPixiToPath = () => {
  core.addPath(path.dirname(options.pixiBinPath))
}

const pixiGlobalInstall = async () => {
  const { globalEnvironments } = options
  if (!globalEnvironments) {
    core.debug('Skipping pixi global install.')
    return
  }

  await tryRestoreGlobalCache()

  core.debug('Installing global environments')
  for (const env of globalEnvironments) {
    const command = `global install ${env}`
    await core.group(`pixi ${command}`, () => execute(pixiCmd(command, false)))
  }

  await saveGlobalCache()
}

const pixiInstall = async () => {
  if (!options.runInstall) {
    core.debug('Skipping pixi install.')
    return
  }

  await tryRestoreProjectCache()

  const environments = options.environments ?? [undefined]
  for (const environment of environments) {
    core.debug(`Installing environment ${environment ?? 'default'}`)
    let command = `install`
    if (environment) {
      command += ` -e ${environment}`
    }
    if (options.frozen) {
      command += ' --frozen'
    }
    if (options.locked) {
      command += ' --locked'
    }
    if (options.pypiKeyringProvider) {
      command += ` --pypi-keyring-provider ${options.pypiKeyringProvider}`
    }
    await core.group(`pixi ${command}`, () => execute(pixiCmd(command)))
  }

  await saveProjectCache()
}

const generateList = async () => {
  if (!options.runInstall) {
    core.debug('Skipping pixi list.')
    return
  }
  if (
    'version' in options.pixiSource &&
    options.pixiSource.version !== 'latest' &&
    options.pixiSource.version < 'v0.13.0'
  ) {
    core.warning(
      'pixi list is not supported for pixi versions < `v0.13.0`. Please set `pixi-version` to `v0.13.0` or later.'
    )
    return
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
      const cmd = `${command} -e ${environment}`
      await core.group(`pixi ${cmd}`, () => execute(pixiCmd(cmd)))
    }
  } else {
    await core.group(`pixi ${command}`, () => execute(pixiCmd(command)))
  }
}

const generateInfo = async () => {
  await core.group('pixi info', () => execute(pixiCmd('info')))
}

const activateEnv = async (environment: string) => {
  await core.group('Activate environment', () => activateEnvironment(environment))
}

const run = async () => {
  core.debug(`process.env.HOME: ${process.env.HOME ?? '-'}`)
  core.debug(`os.homedir(): ${os.homedir()}`)
  if (options.downloadPixi) {
    await downloadPixi(options.pixiSource)
  }
  addPixiToPath()
  await pixiLogin()
  await pixiGlobalInstall()
  await generateInfo()
  await pixiInstall()
  await generateList()
  if (options.activatedEnvironment) {
    await activateEnv(options.activatedEnvironment)
  }
}

const main = async () => {
  try {
    await run()
    // workaround for https://github.com/actions/toolkit/issues/1578
    exit(0)
  } catch (error: unknown) {
    if (core.isDebug()) {
      throw error
    }
    if (error instanceof Error) {
      core.setFailed(error.message)
      exit(1)
    } else if (typeof error === 'string') {
      core.setFailed(error)
      exit(1)
    } else {
      throw error
    }
  }
}

void main()
