import os from 'os'
import * as osPath from 'path'
import * as core from '@actions/core'
import { executeGetOutput, pixiCmd } from './util'

interface ShellHook {
  environment_variables: Record<string, string>
}

const splitEnvironment = (shellHook: ShellHook): [Record<string, string>, string?] => {
  if (os.platform() === 'win32') {
    // On Windows, environment variables are case-insensitive but JSON isn't...
    const pathEnvs = Object.keys(shellHook.environment_variables).filter((k) => k.toUpperCase() === 'PATH')
    if (pathEnvs.length > 0) {
      const caseSensitivePathName = pathEnvs[0]
      const path = shellHook.environment_variables[caseSensitivePathName]
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete shellHook.environment_variables[caseSensitivePathName]
      return [shellHook.environment_variables, path]
    }
  } else {
    if ('PATH' in shellHook.environment_variables) {
      const path = shellHook.environment_variables.PATH
      delete shellHook.environment_variables.PATH
      return [shellHook.environment_variables, path]
    }
  }

  // If the path cannot be found, return all other environment variables
  return [shellHook.environment_variables]
}

const getNewPathComponents = (path: string): string[] => {
  const currentPath = process.env.PATH
  if (!currentPath) {
    throw new Error('Unable to obtain current PATH from environment')
  }
  if (!path.endsWith(currentPath)) {
    throw new Error('Unable to handle environment activation which does not only append to PATH')
  }
  core.debug(`Found current path '${currentPath}'`)
  core.debug(`Got new path '${path}'`)
  const newPath = path.slice(0, path.length - currentPath.length)
  return newPath.split(osPath.delimiter).filter((p) => p.length > 0)
}

export const activateEnvironment = async (environment: string): Promise<void> => {
  // First, obtain the environment variables that would be set by environment activation
  const envOption = environment === 'default' ? '' : `-e ${environment}`
  const shellHookOutput = await executeGetOutput(pixiCmd(`shell-hook ${envOption} --json`), { silent: true })
  const shellHook = JSON.parse(shellHookOutput.stdout) as ShellHook

  // Then, we split the environment variables into the special 'PATH' and all others
  const [envVars, path] = splitEnvironment(shellHook)

  // Finally, new path components are added...
  if (path) {
    const newComponents = getNewPathComponents(path)
    for (const component of newComponents) {
      core.info(`Adding path component '${component}'`)
      core.addPath(component)
    }
  }

  // ... as well as all remaining environment variables
  for (const key of Object.keys(envVars)) {
    core.info(`Exporting environment variable '${key}=${envVars[key]}'`)
    core.exportVariable(key, envVars[key])
  }
}
