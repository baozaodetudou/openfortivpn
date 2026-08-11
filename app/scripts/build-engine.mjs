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
const helperDirectory = join(appDirectory, "src-tauri", "helper");
const helperName = "openfortivpn-manager-helper";

const skipEngineBuild = process.env.OPENFORTIVPN_SKIP_ENGINE_BUILD === "1";

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

mkdirSync(resourceDirectory, { recursive: true });

if (skipEngineBuild) {
  console.log("Skipping openfortivpn engine build by request.");
  if (
    !existsSync(join(resourceDirectory, executableName)) &&
    process.env.OPENFORTIVPN_ALLOW_MISSING_ENGINE !== "1"
  ) {
    throw new Error(`Prebuilt ${executableName} is missing from ${resourceDirectory}`);
  }
} else {
  mkdirSync(buildDirectory, { recursive: true });
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
}

if (!windows) {
  run("cargo", ["build", "--release", "--manifest-path", join(helperDirectory, "Cargo.toml")]);
  const helperExecutable = join(helperDirectory, "target", "release", helperName);
  if (!existsSync(helperExecutable)) {
    throw new Error(`Cannot find built ${helperName} in ${helperDirectory}`);
  }
  copyFileSync(helperExecutable, join(resourceDirectory, helperName));
}

if (process.platform === "darwin" && process.env.APPLE_SIGNING_IDENTITY) {
  for (const binary of [executableName, helperName]) {
    const codesignArguments = ["--force", "--sign", process.env.APPLE_SIGNING_IDENTITY];
    if (process.env.APPLE_SIGNING_IDENTITY !== "-") {
      codesignArguments.push("--options", "runtime", "--timestamp");
    }
    codesignArguments.push(join(resourceDirectory, binary));
    run("codesign", codesignArguments);
  }
}

if (windows && process.env.OPENFORTIVPN_ALLOW_MISSING_ENGINE !== "1") {
  const wintunCandidates = [
    process.env.WINTUN_DLL,
    join(repositoryDirectory, "vendor", "wintun", "bin", "amd64", "wintun.dll"),
    join(buildDirectory, "wintun.dll"),
  ].filter(Boolean);
  const wintun = wintunCandidates.find(existsSync);
  if (wintun) {
    copyFileSync(wintun, join(resourceDirectory, "wintun.dll"));
  } else {
    throw new Error(
      "WINTUN_DLL is not set; refusing to create a Windows application that cannot connect.",
    );
  }
}

console.log(`Prepared platform resources in ${resourceDirectory}`);
