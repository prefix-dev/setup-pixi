import path from 'path'
import os from 'os'
import * as core from '@actions/core'
import * as z from 'zod'
import untildify from 'untildify'

type Inputs = {
  pixiVersion?: string
  pixiUrl?: string
  logLevel?: LogLevel
  manifestPath?: string
  runInstall?: boolean
  generateRunShell?: boolean
  cache?: boolean
  cacheKey?: string
  cacheWrite?: boolean
  pixiBinPath?: string
  authHost?: string
  authToken?: string
  authUsername?: string
  authPassword?: string
  authCondaToken?: string
  postCleanup?: PostCleanup
}

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
  generateRunShell: boolean
  cache?: Cache
  pixiBinPath: string
  pixiRunShell: string
  auth?: Auth
  postCleanup: PostCleanup
}>

const logLevelSchema = z.enum(['quiet', 'warn', 'info', 'debug', 'trace'])
export type LogLevel = z.infer<typeof logLevelSchema>

const postCleanupSchema = z.enum(['none', 'environment', 'all'])
export type PostCleanup = z.infer<typeof postCleanupSchema>

export const PATHS = {
  pixiBin: path.join(os.homedir(), '.pixi', 'bin', `pixi${os.platform() === 'win32' ? '.exe' : ''}`)
}

const parseOrUndefined = <T>(key: string, schema: z.ZodSchema<T>): T | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  return schema.parse(input)
}

const parseOrUndefinedJSON = <T>(key: string, schema: z.ZodSchema<T>): T | undefined => {
  const input = core.getInput(key)
  // GitHub actions sets empty inputs to the empty string, but we want undefined
  if (input === '') {
    return undefined
  }
  return schema.parse(JSON.parse(input))
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
  if (inputs.cacheWrite && !inputs.cacheKey && !inputs.cache) {
    throw new Error('cache-write is only valid with cache-key or cache specified.')
  }
}

const inferOptions = (inputs: Inputs): Options => {
  const runInstall = inputs.runInstall ?? true
  const pixiSource = inputs.pixiVersion
    ? { version: inputs.pixiVersion }
    : inputs.pixiUrl
    ? { url: inputs.pixiUrl }
    : { version: 'latest' }
  const logLevel = inputs.logLevel ?? (core.isDebug() ? 'debug' : 'warn')
  const manifestPath = inputs.manifestPath ? path.resolve(untildify(inputs.manifestPath)) : 'pixi.toml'
  const pixiLockFile = path.join(path.dirname(manifestPath), path.basename(manifestPath).replace(/\.toml$/, '.lock'))
  const generateRunShell = inputs.generateRunShell ?? runInstall
  const cache = inputs.cacheKey
    ? { cacheKeyPrefix: inputs.cacheKey, cacheWrite: inputs.cacheWrite ?? true }
    : inputs.cache
    ? { cacheKeyPrefix: 'pixi-', cacheWrite: true }
    : undefined
  const pixiBinPath = inputs.pixiBinPath ? path.resolve(untildify(inputs.pixiBinPath)) : PATHS.pixiBin
  const pixiRunShell = path.join(path.dirname(pixiBinPath), 'pixi-shell')
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
  const postCleanup = inputs.postCleanup ?? 'all'
  return {
    pixiSource,
    logLevel,
    manifestPath,
    pixiLockFile,
    runInstall,
    generateRunShell,
    cache,
    pixiBinPath,
    pixiRunShell,
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
    pixiVersion: parseOrUndefined('pixi-version', z.union([z.literal('latest'), z.string().regex(/^v\d+\.\d+\.\d+$/)])),
    pixiUrl: parseOrUndefined('pixi-url', z.string().url()),
    logLevel: parseOrUndefined('log-level', logLevelSchema),
    manifestPath: parseOrUndefined('manifest-path', z.string()),
    runInstall: parseOrUndefinedJSON('run-install', z.boolean()),
    generateRunShell: parseOrUndefinedJSON('generate-run-shell', z.boolean()),
    cache: parseOrUndefinedJSON('cache', z.boolean()),
    cacheKey: parseOrUndefined('cache-key', z.string()),
    cacheWrite: parseOrUndefinedJSON('cache-write', z.boolean()),
    pixiBinPath: parseOrUndefined('pixi-bin-path', z.string()),
    authHost: parseOrUndefined('auth-host', z.string()),
    authToken: parseOrUndefined('auth-token', z.string()),
    authUsername: parseOrUndefined('auth-username', z.string()),
    authPassword: parseOrUndefined('auth-password', z.string()),
    authCondaToken: parseOrUndefined('auth-conda-token', z.string()),
    postCleanup: parseOrUndefined('post-cleanup', postCleanupSchema)
  }
  core.debug(`Inputs: ${JSON.stringify(inputs)}`)
  validateInputs(inputs)
  const options = inferOptions(inputs)
  core.debug(`Inferred options: ${JSON.stringify(options)}`)
  assertOptions(options)
  return options
}

export const options = getOptions()
