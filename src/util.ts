import { createHash } from 'crypto'
import os from 'os'
import * as core from '@actions/core'
import type { ExecOptions } from '@actions/exec'
import { exec, getExecOutput } from '@actions/exec'
import { options } from './options'
import Handlebars from 'handlebars'
import { HttpClient } from '@actions/http-client'
import { fetch as undiciFetch } from 'undici'
import { downloadTool, HTTPError } from '@actions/tool-cache'

// setup-pixi resolves `latest` to a concrete release before rendering this template, see `resolveLatestPixiVersion`.
export const DEFAULT_PIXI_URL_TEMPLATE = 'https://github.com/prefix-dev/pixi/releases/download/{{version}}/{{pixiFile}}'

export const USER_AGENT = `setup-pixi/${__SETUP_PIXI_VERSION__}`

const PIXI_LATEST_RELEASE_URL = 'https://github.com/prefix-dev/pixi/releases/latest'

const MAX_ATTEMPTS = 3

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

// Waits 2 s, then 4 s, plus up to 1 s of jitter so that parallel jobs don't retry in lockstep.
const backoffMs = (attempt: number) => 2 ** attempt * 1000 + Math.random() * 1000

const isRetryableResponse = (response: Response) =>
  response.status >= 500 ||
  response.status === 429 ||
  (response.status === 403 &&
    (response.headers.get('x-ratelimit-remaining') === '0' || response.headers.has('retry-after')))

/**
 * Like `fetch`, but retries network errors, server errors and rate limits, since GitHub occasionally answers with them.
 * Returns the last response if all attempts fail, so that callers can report its status.
 */
export const fetchWithRetry = async (url: string, init: RequestInit): Promise<Response> => {
  for (let attempt = 1; ; attempt++) {
    let response: Response
    try {
      response = await fetch(url, init)
    } catch (error) {
      // `fetch` reports network errors as "fetch failed" with the reason in `cause`.
      const reason = (((error as Error).cause as Error | undefined)?.message ?? (error as Error).message).replace(
        /\.$/,
        ''
      )
      if (attempt >= MAX_ATTEMPTS) {
        throw new Error(`Request to ${url} failed: ${reason}`, { cause: error })
      }
      core.info(`Request to ${url} failed: ${reason}. Retrying.`)
      await sleep(backoffMs(attempt))
      continue
    }
    if (!isRetryableResponse(response) || attempt >= MAX_ATTEMPTS) {
      return response
    }
    // GitHub sends `retry-after` in seconds for secondary rate limits.
    const retryAfterMs = Number(response.headers.get('retry-after') ?? 0) * 1000
    core.info(`Request to ${url} failed with HTTP ${response.status}. Retrying.`)
    await sleep(Math.min(Math.max(retryAfterMs, backoffMs(attempt)), 60_000))
  }
}

/**
 * Downloads the pixi binary with `downloadTool`.
 * `downloadTool` retries server errors itself, but GitHub also answers release downloads with transient 403s.
 * We retry those only for github.com, because a 403 from a custom mirror usually means wrong credentials.
 */
export const downloadPixiBinary = async (url: string, dest: string, headers?: NodeJS.Dict<string>) => {
  const isGitHubDownload = new URL(url).hostname === 'github.com'
  for (let attempt = 1; ; attempt++) {
    try {
      return await downloadTool(url, dest, undefined, headers)
    } catch (error) {
      const isTransient = isGitHubDownload && error instanceof HTTPError && error.httpStatusCode === 403
      if (!isTransient || attempt >= MAX_ATTEMPTS) {
        throw new Error(`Downloading pixi from ${url} failed: ${(error as Error).message}`, { cause: error })
      }
      core.info(`Downloading pixi from ${url} failed with HTTP 403. Retrying.`)
      await sleep(backoffMs(attempt))
    }
  }
}

/**
 * Resolves the tag of the latest pixi release from the redirect of the `releases/latest` page.
 * Downloading from the concrete tag afterwards ensures that the binary we verify belongs to the version we resolved,
 * even if a new release is published in between.
 */
export const resolveLatestPixiVersion = async () => {
  const response = await fetchWithRetry(PIXI_LATEST_RELEASE_URL, {
    redirect: 'manual',
    headers: { 'User-Agent': USER_AGENT }
  })
  const location = response.headers.get('location')
  const version = location?.match(/\/releases\/tag\/(v\d+\.\d+\.\d+)$/)?.[1]
  if (!version) {
    throw new Error(
      `Could not resolve the latest pixi version: ${PIXI_LATEST_RELEASE_URL} returned HTTP ${response.status} with location ${location}`
    )
  }
  return version
}

/**
 * Makes `fetch` respect the `HTTP(S)_PROXY` and `NO_PROXY` environment variables, like `@actions/tool-cache` does.
 * This also covers the `fetch` calls in the TUF client.
 * `undici.setGlobalDispatcher` is not enough because Node's built-in `fetch` doesn't reliably pick it up.
 */
export const configureFetchProxy = () => {
  const httpClient = new HttpClient(USER_AGENT)
  const builtinFetch = globalThis.fetch
  const proxyAwareFetch = (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const dispatcher = httpClient.getAgentDispatcher(url)
    if (!dispatcher) {
      return builtinFetch(input, init)
    }
    core.debug(`Using proxy for ${url}`)
    return undiciFetch(input as Parameters<typeof undiciFetch>[0], {
      ...(init as Parameters<typeof undiciFetch>[1]),
      dispatcher
    }) as unknown as Promise<Response>
  }
  globalThis.fetch = proxyAwareFetch as typeof fetch
}

export const getCondaArch = () => {
  const archDict: Record<string, string> = {
    'darwin-x64': 'osx-64',
    'darwin-arm64': 'osx-arm64',
    'linux-x64': 'linux-64',
    'linux-arm64': 'linux-aarch64',
    'linux-ppc64': 'linux-ppc64le',
    'linux-riscv64': 'linux-riscv64',
    'win32-x64': 'win-64',
    'win32-arm64': 'win-arm64'
  }
  const arch = archDict[`${os.platform()}-${os.arch()}`]
  if (!arch) {
    throw new Error(`Unsupported platform: ${os.platform()}-${os.arch()}`)
  }
  return arch
}

const getPlatform = () => {
  const platform = os.platform()
  const arch = os.arch()

  switch (platform) {
    case 'darwin':
      return 'apple-darwin'
    case 'linux':
      if (arch == 'riscv64') {
        // https://github.com/prefix-dev/pixi/issues/6903
        return 'unknown-linux-gnu'
      }
      return 'unknown-linux-musl'
    case 'win32':
      return 'pc-windows-msvc'
    default:
      throw new Error(`Unsupported platform: ${platform}`)
  }
}

const getArch = () => {
  const arch = os.arch()
  switch (arch) {
    case 'x64':
      return 'x86_64'
    case 'arm64':
      return 'aarch64'
    case 'riscv64':
      return 'riscv64gc'
    default:
      throw new Error(`Unsupported architecture: ${arch}`)
  }
}

export const renderPixiUrl = (urlTemplate: string, version: string) => {
  const latest = version == 'latest'
  const arch = getArch()
  const platform = getPlatform()
  const pixiFile = `pixi-${arch}-${platform}${platform === 'pc-windows-msvc' ? '.exe' : ''}`
  const template = Handlebars.compile(urlTemplate)
  return template({
    version,
    latest,
    pixiFile
  })
}

export const sha256 = (s: string | NodeJS.ArrayBufferView) => {
  return createHash('sha256').update(s).digest('hex')
}

export const sha256Short = (s: string | NodeJS.ArrayBufferView) => {
  return sha256(s).slice(0, 7)
}

export const execute = (cmd: string[]) => {
  core.debug(`Executing: \`${cmd.toString()}\``)
  // needs escaping if cmd[0] contains spaces
  // https://github.com/prefix-dev/setup-pixi/issues/184#issuecomment-2765724843
  return exec(`"${cmd[0]}"`, cmd.slice(1), { cwd: options.workingDirectory })
}

export const executeGetOutput = (cmd: string[], execOptions: ExecOptions) => {
  core.debug(`Executing: \`${cmd.toString()}\``)
  // needs escaping if cmd[0] contains spaces
  // https://github.com/prefix-dev/setup-pixi/issues/184#issuecomment-2765724843
  const defaultOptions = { cwd: options.workingDirectory }
  return getExecOutput(`"${cmd[0]}"`, cmd.slice(1), { ...defaultOptions, ...execOptions })
}

export const pixiCmd = (command: string, withManifestPath = true) => {
  let commandArray = [options.pixiBinPath].concat(command.split(' ').filter((x) => x !== ''))
  if (withManifestPath) {
    commandArray = commandArray.concat(['--manifest-path', options.manifestPath])
  }
  commandArray = commandArray.concat(['--color', 'always'])
  switch (options.logLevel) {
    case 'vvv':
      commandArray = commandArray.concat(['-vvv'])
      break
    case 'vv':
      commandArray = commandArray.concat(['-vv'])
      break
    case 'v':
      commandArray = commandArray.concat(['-v'])
      break
    case 'default':
      break
    case 'q':
      commandArray = commandArray.concat(['-q'])
      break
  }
  return commandArray
}
