import {
  __toESM,
  options,
  require_core
} from "./chunk-272HO3UQ.js";

// src/post.ts
var core = __toESM(require_core(), 1);
import fs from "fs/promises";
import path from "path";
import * as os from "os";
import { exit } from "process";
var removeEmptyParentDirs = (dirPath) => {
  return fs.readdir(dirPath).then((files) => {
    if (files.length === 0) {
      core.debug(`Removing empty directory ${dirPath}.`);
      return fs.rm(dirPath, { recursive: true }).then(() => {
        const parentDir = path.dirname(dirPath);
        if (parentDir !== dirPath) {
          return removeEmptyParentDirs(parentDir);
        }
      });
    }
    return Promise.resolve();
  });
};
var cleanupPixiBin = () => {
  const pixiBinPath = options.pixiBinPath;
  const pixiBinDir = path.dirname(pixiBinPath);
  core.debug(`Cleaning up pixi binary ${pixiBinPath}.`);
  return fs.rm(pixiBinPath).then(() => removeEmptyParentDirs(pixiBinDir));
};
var cleanupEnv = () => {
  if (!options.runInstall) {
    core.debug("Skipping cleanup of .pixi directory.");
    return Promise.resolve();
  }
  const envDir = path.join(path.dirname(options.manifestPath), ".pixi");
  core.debug(`Cleaning up .pixi directory ${envDir}.`);
  return fs.rm(envDir, { recursive: true });
};
var determineCacheDir = () => {
  if (os.platform() === "win32") {
    return process.env.LOCALAPPDATA;
  }
  if (os.platform() === "linux") {
    return process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), ".cache");
  }
  return path.join(os.homedir(), "Library", "Caches");
};
var cleanupRattler = () => {
  const rattlerPath = path.join(os.homedir(), ".rattler");
  const cacheDir = determineCacheDir();
  const rattlerCachePath = path.join(cacheDir, "rattler");
  core.debug(`Cleaning up rattler directories ${rattlerPath} and ${rattlerCachePath}.`);
  return Promise.all([
    fs.rm(rattlerPath, { recursive: true, force: true }),
    fs.rm(rattlerCachePath, { recursive: true, force: true })
  ]);
};
var run = () => {
  const postCleanup = options.postCleanup;
  if (postCleanup) {
    return Promise.all([cleanupPixiBin(), cleanupEnv(), cleanupRattler()]);
  }
  core.debug("Skipping post-cleanup.");
  return Promise.resolve();
};
void async function() {
  try {
    await run();
  } catch (error) {
    if (core.isDebug()) {
      throw error;
    }
    if (error instanceof Error) {
      core.setFailed(error.message);
      exit(1);
    } else if (typeof error === "string") {
      core.setFailed(error);
      exit(1);
    }
    throw error;
  }
}();
//# sourceMappingURL=post.js.map