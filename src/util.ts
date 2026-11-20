import { createHash } from 'crypto'
import os from 'os'
import * as core from '@actions/core'
import type { ExecOptions } from '@actions/exec'
import { exec, getExecOutput } from '@actions/exec'
import { options } from './options'
import Handlebars from 'handlebars'
import { HttpClient } from '@actions/http-client'
import { fetch as undiciFetch } from 'undici'

// setup-pixi resolves `latest` to a concrete release before rendering this template, see `resolveLatestPixiVersion`.
export const DEFAULT_PIXI_URL_TEMPLATE = 'https://github.com/prefix-dev/pixi/releases/download/{{version}}/{{pixiFile}}'

export const USER_AGENT = `setup-pixi/${__SETUP_PIXI_VERSION__}`

const PIXI_LATEST_RELEASE_URL = 'https://github.com/prefix-dev/pixi/releases/latest'

/**
 * Resolves the tag of the latest pixi release from the redirect of the `releases/latest` page.
 * Downloading from the concrete tag afterwards ensures that the binary we verify belongs to the version we resolved,
 * even if a new release is published in between.
 */
export const resolveLatestPixiVersion = async () => {
  const response = await fetch(PIXI_LATEST_RELEASE_URL, {
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
