import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const appDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryDirectory = resolve(appDirectory, "..");
const buildDirectory = join(repositoryDirectory, "build", "app-engine");
const resourceDirectory = join(appDirectory, "src-tauri", "resources", "bin");
const windows = process.platform === "win32";
const executableName = windows ? "openfortivpn.exe" : "openfortivpn";

if (process.env.OPENFORTIVPN_SKIP_ENGINE_BUILD === "1") {
  console.log("Skipping openfortivpn engine build by request.");
  process.exit(0);
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryDirectory,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}`);
  }
}

mkdirSync(buildDirectory, { recursive: true });
mkdirSync(resourceDirectory, { recursive: true });

run("cmake", [
  "-S",
  repositoryDirectory,
  "-B",
  buildDirectory,
  "-DCMAKE_BUILD_TYPE=Release",
  "-DOPENSSL_USE_STATIC_LIBS=TRUE",
  "-DBUILD_TESTING=OFF",
]);
run("cmake", ["--build", buildDirectory, "--config", "Release", "--parallel"]);

const executableCandidates = [
  join(buildDirectory, executableName),
  join(buildDirectory, "Release", executableName),
];
const executable = executableCandidates.find(existsSync);
if (!executable) {
  throw new Error(`Cannot find built ${executableName} in ${buildDirectory}`);
}
copyFileSync(executable, join(resourceDirectory, executableName));

if (windows) {
  const wintunCandidates = [
    process.env.WINTUN_DLL,
    join(repositoryDirectory, "vendor", "wintun", "bin", "amd64", "wintun.dll"),
    join(buildDirectory, "wintun.dll"),
  ].filter(Boolean);
  const wintun = wintunCandidates.find(existsSync);
  if (wintun) {
    copyFileSync(wintun, join(resourceDirectory, "wintun.dll"));
  } else {
    console.warn(
      "WINTUN_DLL is not set; add wintun.dll before running a Windows VPN connection.",
    );
  }
}

console.log(`Prepared ${join(resourceDirectory, executableName)}`);
