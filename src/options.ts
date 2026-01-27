import path from 'path'
import os from 'os'
import { exit } from 'process'
import { existsSync, readFileSync } from 'fs'
import * as core from '@actions/core'
import * as z from 'zod'
import untildify from 'untildify'
import { parse } from 'smol-toml'
import which from 'which'
import { DEFAULT_PIXI_URL_TEMPLATE } from './util'

type Inputs = Readonly<{
  pixiVersion?: string
  pixiUrl?: string
  pixiUrlHeaders?: NodeJS.Dict<string>
  logLevel?: LogLevel
  manifestPath?: string
  workingDirectory?: string
  runInstall?: boolean
  environments?: string[]
  activateEnvironment?: string
  frozen?: boolean
  locked?: boolean
  cache?: boolean
  globalCache?: boolean
  cacheKey?: string
  globalCacheKey?: string
  cacheWrite?: boolean
  pixiBinPath?: string
  authHost?: string
  authToken?: string
  authUsername?: string
  authPassword?: string
  authCondaToken?: string
  authS3AccessKeyId?: string
  authS3SecretAccessKey?: string
  authS3SessionToken?: string
  pypiKeyringProvider?: 'disabled' | 'subprocess'
  postCleanup?: boolean
  globalEnvironments?: string[]
}>

export interface PixiSource {
  urlTemplate: string
  headers?: NodeJS.Dict<string>
  version: string
}

type Auth = {
  host: string
} & (
  | {
      token: string
    }
  | {
      username: string
      password: string
    }
  | {
      condaToken: string
    }
  | {
      s3AccessKeyId: string
      s3SecretAccessKey: string
      s3SessionToken?: string
    }
)

interface Cache {
  cacheKeyPrefix: string
  cacheWrite: boolean
}

interface GlobalCache {
  cacheKeyPrefix: string
  cacheWrite: boolean
}

export type Options = Readonly<{
  pixiSource: PixiSource
  downloadPixi: boolean
  logLevel: LogLevel
  manifestPath: string
  workingDirectory: string
  pixiLockFile: string
  runInstall: boolean
  environments?: string[]
  frozen: boolean
  locked: boolean
  cache?: Cache
  globalCache?: GlobalCache
  pixiBinPath: string
  auth?: Auth
  pypiKeyringProvider?: 'disabled' | 'subprocess'
  postCleanup: boolean
  activatedEnvironment?: string
  globalEnvironments?: string[]
}>
const pixiPath = 'pixi.toml'
const pyprojectPath = 'pyproject.toml'

const logLevelSchema = z.enum(['q', 'default', 'v', 'vv', 'vvv'])
export type LogLevel = z.infer<typeof logLevelSchema>

const pypiKeyringProviderSchema = z.enum(['disabled', 'subprocess'])
export type PypiKeyringProvider = z.infer<typeof pypiKeyringProviderSchema>

export const PATHS = {
  pixiBin: path.join(os.homedir(), '.pixi', 'bin', `pixi${os.platform() === 'win32' ? '.exe' : ''}`)
}

const getEnvironmentVariableName = (key: string): string => {
  return `SETUP_PIXI_${key.toUpperCase().replace(/-/g, '_')}`
}

const inputOrEnvironmentVariable = (key: string): string | undefined => {
  const inputValue = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string
  if (inputValue !== '') {
    return inputValue
  }

  const envVarName = getEnvironmentVariableName(key)
  const envVarValue = process.env[envVarName]
  // Empty environment variables are treated as undefined
  if (envVarValue !== undefined && envVarValue !== '') {
    core.debug(`Using environment variable ${envVarName} with value: ${envVarValue}`)
    return envVarValue
  }
  return undefined
}

const parseOrUndefined = <T>(key: string, schema: z.ZodType<T>, errorMessage?: string): T | undefined => {
  const input = inputOrEnvironmentVariable(key)
  if (input === undefined) {
    return undefined
  }
  const maybeResult = schema.safeParse(input)
  if (!maybeResult.success) {
    if (!errorMessage) {
      throw new Error(`${key} is not valid: ${maybeResult.error.message}`)
    }
    throw new Error(errorMessage)
  }
  return maybeResult.data
}

const parseOrUndefinedJSON = <T>(key: string, schema: z.ZodType<T>): T | undefined => {
  const input = inputOrEnvironmentVariable(key)
  if (input === undefined) {
    return undefined
  }
  return schema.parse(JSON.parse(input))
}

const parseOrUndefinedList = <T>(key: string, schema: z.ZodType<T>): T[] | undefined => {
  const input = inputOrEnvironmentVariable(key)
  if (input === undefined) {
    return undefined
  }
  return input
    .split(' ')
    .map((s) => schema.parse(s))
    .filter((s) => s !== '')
}

const parseOrUndefinedMultilineList = <T>(key: string, schema: z.ZodType<T>): T[] | undefined => {
  const input = inputOrEnvironmentVariable(key)
  if (input === undefined) {
    return undefined
  }
  return input
    .split('\n')
    .map((s) => schema.parse(s.trim()))
    .filter((s) => s !== '')
}

const validateInputs = (inputs: Inputs): void => {
  if (inputs.pixiUrlHeaders && !inputs.pixiUrl) {
    throw new Error('You need to specify pixi-url when using pixi-url-headers')
  }
  if (inputs.cacheKey !== undefined && inputs.cache === false) {
    throw new Error('Cannot specify project cache key without project caching')
  }
  if (inputs.globalCacheKey !== undefined && inputs.globalCache === false) {
    throw new Error('Cannot specify global cache key without global caching')
  }
  if (inputs.runInstall === false && inputs.cache === true) {
    throw new Error('Cannot cache without running install')
  }
  if (inputs.globalCache === true && (!inputs.globalEnvironments || inputs.globalEnvironments.length === 0)) {
    throw new Error('Cannot use global-cache without specifying global-environments')
  }
  if (inputs.runInstall === false && inputs.frozen === true) {
    throw new Error('Cannot use `frozen: true` when not running install')
  }
  if (inputs.runInstall === false && inputs.locked === true) {
    throw new Error('Cannot use `locked: true` when not running install')
  }
  if (inputs.locked === true && inputs.frozen === true) {
    throw new Error('Cannot use `locked: true` and `frozen: true` at the same time')
  }
  if ((inputs.authUsername && !inputs.authPassword) || (!inputs.authUsername && inputs.authPassword)) {
    throw new Error('You need to specify both auth-username and auth-password')
  }
  if (
    (inputs.authS3AccessKeyId && !inputs.authS3SecretAccessKey) ||
    (!inputs.authS3AccessKeyId && inputs.authS3SecretAccessKey)
  ) {
    throw new Error('You need to specify both auth-s3-access-key-id and auth-s3-secret-access-key')
  }
  if (inputs.authS3SessionToken && (!inputs.authS3AccessKeyId || !inputs.authS3SecretAccessKey)) {
    throw new Error(
      'You need to specify both auth-s3-access-key-id and auth-s3-secret-access-key when using auth-s3-session-token'
    )
  }
  // now we can assume that authUsername is defined iff authPassword is defined
  if (inputs.authHost) {
    if (!inputs.authToken && !inputs.authUsername && !inputs.authCondaToken && !inputs.authS3AccessKeyId) {
      throw new Error('You need to specify either auth-token or auth-username and auth-password or auth-conda-token')
    }
    let authCount = 0
    if (inputs.authToken) {
      authCount++
    }
    if (inputs.authUsername) {
      authCount++
    }
    if (inputs.authCondaToken) {
      authCount++
    }
    if (inputs.authS3AccessKeyId) {
      authCount++
    }
    if (authCount > 1) {
      throw new Error('You cannot specify multiple auth methods')
    }
  }
  if (!inputs.authHost) {
    if (inputs.authToken || inputs.authUsername || inputs.authCondaToken || inputs.authS3AccessKeyId) {
      throw new Error('You need to specify auth-host')
    }
  }
  if (inputs.runInstall === false && inputs.environments) {
    throw new Error('Cannot specify environments without running install')
  }
  if (inputs.activateEnvironment === 'true' && inputs.environments && inputs.environments.length > 1) {
    throw new Error('When installing multiple environments, `activate-environment` must specify the environment name')
  }
}

const determinePixiInstallation = (pixiUrlOrVersionSet: boolean, pixiBinPath: string | undefined) => {
  const preinstalledPixi = which.sync('pixi', { nothrow: true })

  if (pixiUrlOrVersionSet || pixiBinPath) {
    if (preinstalledPixi) {
      core.debug(`Local pixi found at ${preinstalledPixi} is being ignored.`)
    }
    return {
      downloadPixi: true,
      pixiBinPath: pixiBinPath ? path.resolve(untildify(pixiBinPath)) : PATHS.pixiBin
    }
  }

  if (preinstalledPixi) {
    core.info(`Using pre-installed pixi at ${preinstalledPixi}`)
    return { downloadPixi: false, pixiBinPath: preinstalledPixi }
  }

  return { downloadPixi: true, pixiBinPath: PATHS.pixiBin }
}

const inferOptions = (inputs: Inputs): Options => {
  const runInstall = inputs.runInstall ?? true
  const pixiSource: PixiSource = {
    urlTemplate: inputs.pixiUrl ?? DEFAULT_PIXI_URL_TEMPLATE,
    headers: inputs.pixiUrlHeaders,
    version: inputs.pixiVersion ?? 'latest'
  }

  const { downloadPixi, pixiBinPath } = determinePixiInstallation(
    !!inputs.pixiVersion || !!inputs.pixiUrl,
    inputs.pixiBinPath
  )
  const logLevel = inputs.logLevel ?? (core.isDebug() ? 'vv' : 'default')

  // Determine the working directory - resolve to absolute path if provided
  const workingDirectory = inputs.workingDirectory ? path.resolve(untildify(inputs.workingDirectory)) : process.cwd()
  core.debug(`Working directory: ${workingDirectory}`)

  // infer manifest path from inputs or default to pixi.toml or pyproject.toml depending on what is present in the working directory.
  const pixiTomlPathInWorkingDir = path.join(workingDirectory, pixiPath)
  const pyprojectTomlPathInWorkingDir = path.join(workingDirectory, pyprojectPath)

  let manifestPath = pixiTomlPathInWorkingDir // default
  if (inputs.manifestPath) {
    // If manifest path is provided, resolve it relative to working directory if it's not absolute
    manifestPath = path.isAbsolute(inputs.manifestPath)
      ? path.resolve(untildify(inputs.manifestPath))
      : path.resolve(workingDirectory, inputs.manifestPath)
  } else {
    if (existsSync(pixiTomlPathInWorkingDir)) {
      manifestPath = pixiTomlPathInWorkingDir
      core.debug(`Found pixi.toml at: ${manifestPath}`)
    } else if (existsSync(pyprojectTomlPathInWorkingDir)) {
      try {
        const fileContent = readFileSync(pyprojectTomlPathInWorkingDir, 'utf-8')
        const parsedContent: Record<string, unknown> = parse(fileContent)

        // Test if the tool.pixi table is present in the pyproject.toml file, if so, use it as the manifest file.
        if (parsedContent.tool && typeof parsedContent.tool === 'object' && 'pixi' in parsedContent.tool) {
          core.debug(`The tool.pixi table found, using ${pyprojectTomlPathInWorkingDir} as manifest file.`)
          manifestPath = pyprojectTomlPathInWorkingDir
        }
      } catch (error) {
        core.error(`Error while trying to read ${pyprojectTomlPathInWorkingDir} file.`)
        core.error(error as Error)
      }
    } else if (runInstall) {
      core.warning(
        `Could not find any manifest file in ${workingDirectory}. Defaulting to ${pixiTomlPathInWorkingDir}.`
      )
    }
  }

  const pixiLockFile = path.join(path.dirname(manifestPath), 'pixi.lock')
  const lockFileAvailable = existsSync(pixiLockFile)
  core.debug(`lockFileAvailable: ${lockFileAvailable ? 'yes' : 'no'}`)
  if (!lockFileAvailable && inputs.cacheWrite === true) {
    throw new Error('You cannot specify cache-write = true without a lock file present')
  }
  let activatedEnvironment // default is undefined
  if (inputs.activateEnvironment === 'true') {
    if (inputs.environments) {
      activatedEnvironment = inputs.environments[0]
    } else {
      activatedEnvironment = 'default'
    }
  } else if (inputs.activateEnvironment && inputs.activateEnvironment !== 'false') {
    activatedEnvironment = inputs.activateEnvironment
  }
  const cache =
    inputs.cache === true || (lockFileAvailable && inputs.cache !== false)
      ? {
          cacheKeyPrefix: inputs.cacheKey ?? 'pixi-',
          cacheWrite: inputs.cacheWrite ?? true
        }
      : undefined
  const globalCache =
    inputs.globalCache === true && inputs.globalEnvironments && inputs.globalEnvironments.length > 0
      ? {
          cacheKeyPrefix: inputs.globalCacheKey ?? 'pixi-global-',
          cacheWrite: inputs.cacheWrite ?? true
        }
      : undefined
  const frozen = inputs.frozen ?? false
  const locked = inputs.locked ?? (lockFileAvailable && !frozen)
  const auth = !inputs.authHost
    ? undefined
    : ((inputs.authToken
        ? {
            host: inputs.authHost,
            token: inputs.authToken
          }
        : inputs.authCondaToken
          ? {
              host: inputs.authHost,
              condaToken: inputs.authCondaToken
            }
          : inputs.authUsername
            ? {
                host: inputs.authHost,
                username: inputs.authUsername,
                password: inputs.authPassword
              }
            : {
                host: inputs.authHost,
                s3AccessKeyId: inputs.authS3AccessKeyId,
                s3SecretAccessKey: inputs.authS3SecretAccessKey,
                s3SessionToken: inputs.authS3SessionToken
              }) as Auth)
  const postCleanup = inputs.postCleanup ?? true
  const pypiKeyringProvider = inputs.pypiKeyringProvider
  return {
    globalEnvironments: inputs.globalEnvironments,
    pixiSource,
    pypiKeyringProvider,
    downloadPixi,
    logLevel,
    manifestPath,
    workingDirectory,
    pixiLockFile,
    runInstall,
    environments: inputs.environments,
    activatedEnvironment,
    frozen,
    locked,
    cache,
    globalCache,
    pixiBinPath,
    auth,
    postCleanup
  }
}

const assertOptions = (_options: Options) => {
  // const assert = (condition: boolean, message?: string) => {
  //   if (!condition) {
  //     throw new Error(message)
  //   }
  // }
  // TODO
}

const getOptions = () => {
  const inputs: Inputs = {
    pixiVersion: parseOrUndefined(
      'pixi-version',
      z.union([z.literal('latest'), z.string().regex(/^v\d+\.\d+\.\d+$/)]),
      'pixi-version must either be `latest` or a version string matching `vX.Y.Z`.'
    ),
    pixiUrl: parseOrUndefined('pixi-url', z.string()),
    pixiUrlHeaders: parseOrUndefinedJSON('pixi-url-headers', z.record(z.string(), z.string())),
    logLevel: parseOrUndefined(
      'log-level',
      logLevelSchema,
      'log-level must be one of `q`, `default`, `v`, `vv`, `vvv`.'
    ),
    manifestPath: parseOrUndefined('manifest-path', z.string()),
    workingDirectory: parseOrUndefined('working-directory', z.string()),
    runInstall: parseOrUndefinedJSON('run-install', z.boolean()),
    environments: parseOrUndefinedList('environments', z.string()),
    activateEnvironment: parseOrUndefined('activate-environment', z.string()),
    locked: parseOrUndefinedJSON('locked', z.boolean()),
    frozen: parseOrUndefinedJSON('frozen', z.boolean()),
    cache: parseOrUndefinedJSON('cache', z.boolean()),
    globalCache: parseOrUndefinedJSON('global-cache', z.boolean()),
    cacheKey: parseOrUndefined('cache-key', z.string()),
    globalCacheKey: parseOrUndefined('global-cache-key', z.string()),
    cacheWrite: parseOrUndefinedJSON('cache-write', z.boolean()),
    pixiBinPath: parseOrUndefined('pixi-bin-path', z.string()),
    authHost: parseOrUndefined('auth-host', z.string()),
    authToken: parseOrUndefined('auth-token', z.string()),
    authUsername: parseOrUndefined('auth-username', z.string()),
    authPassword: parseOrUndefined('auth-password', z.string()),
    authCondaToken: parseOrUndefined('auth-conda-token', z.string()),
    authS3AccessKeyId: parseOrUndefined('auth-s3-access-key-id', z.string()),
    authS3SecretAccessKey: parseOrUndefined('auth-s3-secret-access-key', z.string()),
    authS3SessionToken: parseOrUndefined('auth-s3-session-token', z.string()),
    pypiKeyringProvider: parseOrUndefined('pypi-keyring-provider', pypiKeyringProviderSchema),
    globalEnvironments: parseOrUndefinedMultilineList('global-environments', z.string()),
    postCleanup: parseOrUndefinedJSON('post-cleanup', z.boolean())
  }
  core.debug(`Inputs: ${JSON.stringify(inputs)}`)
  validateInputs(inputs)
  const options = inferOptions(inputs)
  core.debug(`Inferred options: ${JSON.stringify(options)}`)
  assertOptions(options)
  return options
}

let _options: Options
try {
  _options = getOptions()
} catch (error) {
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
}

export const options = _options
