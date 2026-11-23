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

const parseVersion = (version: string) => version.replace(/^v/, '').split('.').map(Number)

const compareVersions = (a: number[], b: number[]) => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0)
    if (diff !== 0) return diff
  }
  return 0
}

const hasPrefix = (version: number[], prefix: number[]) => prefix.every((part, i) => (version[i] ?? 0) === part)

// Supports the common subset of conda version specs: `,` (and), `|` (or), `==`, `!=`, `>=`, `>`, `<=`, `<`, `~=`, `=` and `.*`
const satisfiesConstraint = (version: number[], constraint: string): boolean => {
  if (constraint.trim() === '*') return true
  const match = /^(==|!=|>=|<=|~=|>|<|=)?\s*v?([\d.]+?)(\.\*)?$/.exec(constraint.trim())
  if (!match) throw new Error(`Unsupported requires-pixi constraint: \`${constraint}\``)
  const [, operator = '==', raw, wildcard] = match
  const target = parseVersion(raw)
  const cmp = compareVersions(version, target)
  if (wildcard || operator === '=') return hasPrefix(version, target) === (operator !== '!=')
  switch (operator) {
    case '==':
      return cmp === 0
    case '!=':
      return cmp !== 0
    case '>=':
      return cmp >= 0
    case '>':
      return cmp > 0
    case '<=':
      return cmp <= 0
    case '<':
      return cmp < 0
    default: // ~=
      return cmp >= 0 && hasPrefix(version, target.slice(0, -1))
  }
}

const satisfies = (version: string, spec: string) =>
  spec
    .split('|')
    .some((alternative) => alternative.split(',').every((c) => satisfiesConstraint(parseVersion(version), c)))

type Release = { tag_name: string; published_at: string; draft: boolean; prerelease: boolean }

// Highest pixi release matching `spec`, ignoring releases published after `excludeNewer`
// unless none of the older ones match, in which case the oldest matching release is used.
export const resolveRequiresPixi = async (spec: string, excludeNewer?: string) => {
  const token = process.env.GITHUB_TOKEN
  const releases: Release[] = []
  for (let page = 1; ; page++) {
    const response = await fetch(`https://api.github.com/repos/prefix-dev/pixi/releases?per_page=100&page=${page}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : undefined
    })
    if (!response.ok) throw new Error(`Failed to list pixi releases: ${response.status} ${response.statusText}`)
    const batch = (await response.json()) as Release[]
    releases.push(...batch)
    if (batch.length < 100) break
  }
  const matching = releases
    .filter((r) => !r.draft && !r.prerelease && satisfies(r.tag_name, spec))
    .sort((a, b) => compareVersions(parseVersion(b.tag_name), parseVersion(a.tag_name)))
  if (matching.length === 0) throw new Error(`No pixi release satisfies requires-pixi \`${spec}\``)
  const cutoff = excludeNewer ? new Date(excludeNewer) : undefined
  const release =
    matching.find((r) => !cutoff || Number.isNaN(cutoff.getTime()) || new Date(r.published_at) <= cutoff) ??
    matching[matching.length - 1]
  core.info(`Using pixi ${release.tag_name} to satisfy requires-pixi \`${spec}\``)
  return release.tag_name
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
