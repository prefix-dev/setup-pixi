import type { BinaryLike } from 'crypto'
import { createHash } from 'crypto'
import os from 'os'
import * as core from '@actions/core'
import type { ExecOptions } from '@actions/exec'
import { exec, getExecOutput } from '@actions/exec'
import { options } from './options'
import Handlebars from 'handlebars'

export const DEFAULT_PIXI_URL_TEMPLATE = `\
{{#if latest~}}
https://github.com/prefix-dev/pixi/releases/latest/download/{{pixiFile}}
{{~else~}}
https://github.com/prefix-dev/pixi/releases/download/{{version}}/{{pixiFile}}
{{~/if}}`

export const getCondaArch = () => {
  const archDict: Record<string, string> = {
    'darwin-x64': 'osx-64',
    'darwin-arm64': 'osx-arm64',
    'linux-x64': 'linux-64',
    'linux-arm64': 'linux-aarch64',
    'linux-ppc64': 'linux-ppc64le',
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
  switch (platform) {
    case 'darwin':
      return 'apple-darwin'
    case 'linux':
      return 'unknown-linux-musl'
    case 'win32':
      return 'pc-windows-msvc'
    default:
      throw new Error(`Unsupported architecture: ${platform}`)
  }
}

const getArch = () => {
  const arch = os.arch()
  switch (arch) {
    case 'x64':
      return 'x86_64'
    case 'arm64':
      return 'aarch64'
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

export const sha256 = (s: BinaryLike) => {
  return createHash('sha256').update(s).digest('hex')
}

export const sha256Short = (s: BinaryLike) => {
  return sha256(s).slice(0, 7)
}

export const execute = (cmd: string[]) => {
  core.debug(`Executing: \`${cmd.toString()}\``)
  // needs escaping if cmd[0] contains spaces
  // https://github.com/prefix-dev/setup-pixi/issues/184#issuecomment-2765724843
  return exec(`"${cmd[0]}"`, cmd.slice(1))
}

export const executeGetOutput = (cmd: string[], options?: ExecOptions) => {
  core.debug(`Executing: \`${cmd.toString()}\``)
  // needs escaping if cmd[0] contains spaces
  // https://github.com/prefix-dev/setup-pixi/issues/184#issuecomment-2765724843
  return getExecOutput(`"${cmd[0]}"`, cmd.slice(1), options)
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
