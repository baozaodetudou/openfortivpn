import { existsSync, rmSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const appDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tauriDirectory = join(appDirectory, "src-tauri");
const configuredTarget = process.env.CARGO_TARGET_DIR;
const targetRoot = configuredTarget
  ? resolve(
      isAbsolute(configuredTarget) ? configuredTarget : tauriDirectory,
      configuredTarget,
    )
  : join(tauriDirectory, "target");
const profile = process.env.TAURI_ENV_DEBUG === "true" ? "debug" : "release";
const targetTriple = process.env.TAURI_ENV_TARGET_TRIPLE;
const tripleProfile = targetTriple
  ? join(targetRoot, targetTriple, profile)
  : undefined;
const nativeProfile = join(targetRoot, profile);
const executableName =
  process.env.TAURI_ENV_PLATFORM === "windows"
    ? "openfortivpn-manager.exe"
    : "openfortivpn-manager";
const profileCandidates = [nativeProfile, tripleProfile]
  .filter((candidate) => candidate && existsSync(join(candidate, executableName)))
  .sort(
    (left, right) =>
      statSync(join(right, executableName)).mtimeMs -
      statSync(join(left, executableName)).mtimeMs,
  );
const profileDirectory =
  profileCandidates[0] ?? tripleProfile ?? nativeProfile;
const bundleDirectory = resolve(profileDirectory, "bundle");
const normalizedTargetRoot = `${resolve(targetRoot)}${sep}`;

if (
  basename(bundleDirectory) !== "bundle" ||
  !bundleDirectory.startsWith(normalizedTargetRoot)
) {
  throw new Error(`Refusing to clean unsafe bundle path: ${bundleDirectory}`);
}

rmSync(bundleDirectory, { recursive: true, force: true });
console.log(`Prepared clean Tauri bundle output: ${bundleDirectory}`);
