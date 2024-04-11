import path from 'path'
import os from 'os'
import { exit } from 'process'
import { existsSync } from 'fs'
import * as core from '@actions/core'
import * as z from 'zod'
import untildify from 'untildify'

type Inputs = Readonly<{
  pixiVersion?: string
  pixiUrl?: string
  logLevel?: LogLevel
  manifestPath?: string
  runInstall?: boolean
  environments?: string[]
  frozen?: boolean
  locked?: boolean
  cache?: boolean
  cacheKey?: string
  cacheWrite?: boolean
  pixiBinPath?: string
  authHost?: string
  authToken?: string
  authUsername?: string
  authPassword?: string
  authCondaToken?: string
  postCleanup?: boolean
}>

export type PixiSource =
  | {
      version: string
    }
  | {
      url: string
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
)

type Cache = {
  cacheKeyPrefix: string
  cacheWrite: boolean
}

export type Options = Readonly<{
  pixiSource: PixiSource
  logLevel: LogLevel
  manifestPath: string
  pixiLockFile: string
  runInstall: boolean
  environments?: string[]
  frozen: boolean
  locked: boolean
  cache?: Cache
  pixiBinPath: string
  auth?: Auth
  postCleanup: boolean
}>

const logLevelSchema = z.enum(['q', 'default', 'v', 'vv', 'vvv'])
export type LogLevel = z.infer<typeof logLevelSchema>

export const PATHS = {
  pixiBin: path.join(os.homedir(), '.pixi', 'bin', `pixi${os.platform() === 'win32' ? '.exe' : ''}`)
}

const parseOrUndefined = <T>(key: string, schema: z.ZodSchema<T>, errorMessage?: string): T | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
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

const parseOrUndefinedJSON = <T>(key: string, schema: z.ZodSchema<T>): T | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  return schema.parse(JSON.parse(input))
}

const parseOrUndefinedList = <T>(key: string, schema: z.ZodSchema<T>): T[] | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  return input
    .split(' ')
    .map((s) => schema.parse(s))
    .filter((s) => s !== '')
}

const validateInputs = (inputs: Inputs): void => {
  if (inputs.pixiVersion && inputs.pixiUrl) {
    throw new Error('You need to specify either pixi-version or pixi-url')
  }
  if (inputs.cacheKey !== undefined && inputs.cache === false) {
    throw new Error('Cannot specify cache key without caching')
  }
  if (inputs.runInstall === false && inputs.cache === true) {
    throw new Error('Cannot cache without running install')
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
  // now we can assume that authUsername is defined iff authPassword is defined
  if (inputs.authHost) {
    if (!inputs.authToken && !inputs.authUsername && !inputs.authCondaToken) {
      throw new Error('You need to specify either auth-token or auth-username and auth-password or auth-conda-token')
    }
    if (
      (inputs.authToken && (inputs.authUsername || inputs.authCondaToken)) ||
      (inputs.authUsername && inputs.authCondaToken)
    ) {
      throw new Error('You cannot specify two auth methods')
    }
  }
  if (!inputs.authHost) {
    if (inputs.authToken || inputs.authUsername || inputs.authCondaToken) {
      throw new Error('You need to specify auth-host')
    }
  }
  if (inputs.runInstall === false && inputs.environments) {
    throw new Error('Cannot specify environments without running install')
  }
}

const inferOptions = (inputs: Inputs): Options => {
  const runInstall = inputs.runInstall ?? true
  const pixiSource = inputs.pixiVersion
    ? { version: inputs.pixiVersion }
    : inputs.pixiUrl
      ? { url: inputs.pixiUrl }
      : { version: 'latest' }
  const logLevel = inputs.logLevel ?? (core.isDebug() ? 'vv' : 'default')
  const manifestPath = inputs.manifestPath ? path.resolve(untildify(inputs.manifestPath)) : 'pixi.toml'
  const pixiLockFile = path.join(path.dirname(manifestPath), 'pixi.lock')
  core.info(`pixi lock file is : ${pixiLockFile}`)
  const lockFileAvailable = existsSync(pixiLockFile)
  core.info(`lockFileAvailable: ${lockFileAvailable}`)
  if (!lockFileAvailable && inputs.cacheWrite === true) {
    throw new Error('You cannot specify cache-write = true without a lock file present')
  }
  const cache = inputs.cacheKey
    ? { cacheKeyPrefix: inputs.cacheKey, cacheWrite: inputs.cacheWrite ?? true }
    : inputs.cache === true || (lockFileAvailable && inputs.cache !== false)
      ? { cacheKeyPrefix: 'pixi-', cacheWrite: inputs.cacheWrite ?? true }
      : undefined
  const pixiBinPath = inputs.pixiBinPath ? path.resolve(untildify(inputs.pixiBinPath)) : PATHS.pixiBin
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
          : {
              host: inputs.authHost,
              username: inputs.authUsername!,
              password: inputs.authPassword!
            }) as Auth)
  const postCleanup = inputs.postCleanup ?? true
  return {
    pixiSource,
    logLevel,
    manifestPath,
    pixiLockFile,
    runInstall,
    environments: inputs.environments,
    frozen,
    locked,
    cache,
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
    pixiUrl: parseOrUndefined('pixi-url', z.string().url()),
    logLevel: parseOrUndefined(
      'log-level',
      logLevelSchema,
      'log-level must be one of `q`, `default`, `v`, `vv`, `vvv`.'
    ),
    manifestPath: parseOrUndefined('manifest-path', z.string()),
    runInstall: parseOrUndefinedJSON('run-install', z.boolean()),
    environments: parseOrUndefinedList('environments', z.string()),
    locked: parseOrUndefinedJSON('locked', z.boolean()),
    frozen: parseOrUndefinedJSON('frozen', z.boolean()),
    cache: parseOrUndefinedJSON('cache', z.boolean()),
    cacheKey: parseOrUndefined('cache-key', z.string()),
    cacheWrite: parseOrUndefinedJSON('cache-write', z.boolean()),
    pixiBinPath: parseOrUndefined('pixi-bin-path', z.string()),
    authHost: parseOrUndefined('auth-host', z.string()),
    authToken: parseOrUndefined('auth-token', z.string()),
    authUsername: parseOrUndefined('auth-username', z.string()),
    authPassword: parseOrUndefined('auth-password', z.string()),
    authCondaToken: parseOrUndefined('auth-conda-token', z.string()),
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
