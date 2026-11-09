use openfortivpn_manager_core::supervisor::OwnedProcess;
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

const APP_IDENTIFIER: &str = "com.baozaodetudou.openfortivpn";
const COMPONENT_DIRECTORY: &str = "/var/lib/openfortivpn-manager/components";
const RUN_DIRECTORY: &str = "/var/run/openfortivpn-manager";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const INSTANCE_RECORD_VERSION: u32 = 1;
const INSTANCE_IDENTIFIER_BYTES: usize = 16;
const CONTROL_TOKEN_BYTES: usize = 32;
const CONTROL_MESSAGE_LIMIT: u64 = 256;
const HELPER_RUN_FAILED: i32 = 72;

#[cfg(target_os = "macos")]
const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/com.baozaodetudou.openfortivpn.helper";
#[cfg(not(target_os = "macos"))]
const HELPER_PATH: &str = "/usr/local/libexec/openfortivpn-manager/helper";

#[cfg(target_os = "macos")]
const ENGINE_PATH: &str = "/Library/PrivilegedHelperTools/com.baozaodetudou.openfortivpn.engine";
#[cfg(not(target_os = "macos"))]
const ENGINE_PATH: &str = "/usr/local/libexec/openfortivpn-manager/openfortivpn";

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("{}", message.as_ref());
    process::exit(1);
}

fn require_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err("helper 必须由 sudo 以 root 身份运行".to_string())
    }
}

fn invoking_uid() -> Result<u32, String> {
    let value = env::var("SUDO_UID").map_err(|_| "缺少 SUDO_UID".to_string())?;
    let uid = value
        .parse::<u32>()
        .map_err(|_| "SUDO_UID 无效".to_string())?;
    if uid == 0 {
        return Err("拒绝为 root 账户安装用户级 helper".to_string());
    }
    Ok(uid)
}

fn passwd_for_uid(uid: u32) -> Result<(String, PathBuf), String> {
    let entry = unsafe { libc::getpwuid(uid) };
    if entry.is_null() {
        return Err(format!("找不到 UID {uid} 对应的本地账户"));
    }
    let name = unsafe { CStr::from_ptr((*entry).pw_name) }
        .to_str()
        .map_err(|_| "本地账户名不是 UTF-8".to_string())?
        .to_string();
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("本地账户名包含 sudoers 不支持的字符".to_string());
    }
    let home = unsafe { CStr::from_ptr((*entry).pw_dir) }
        .to_str()
        .map_err(|_| "用户主目录不是 UTF-8".to_string())?;
    Ok((name, PathBuf::from(home)))
}

fn ensure_regular_safe_file(path: &Path, owner: Option<u32>) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("无法检查 {}：{error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{} 必须是普通文件且不能是符号链接", path.display()));
    }
    if let Some(owner) = owner {
        if metadata.uid() != owner {
            return Err(format!("{} 的所有者不正确", path.display()));
        }
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!("{} 不能由组或其他用户写入", path.display()));
    }
    Ok(metadata)
}

fn chown_root(path: &Path) -> Result<(), String> {
    let value = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("路径包含 NUL：{}", path.display()))?;
    let result = unsafe { libc::chown(value.as_ptr(), 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "无法设置 {} 的所有者：{}",
            path.display(),
            io::Error::last_os_error()
        ))
    }
}

fn component_directory() -> Result<PathBuf, String> {
    let path = PathBuf::from(COMPONENT_DIRECTORY);
    let mut options = fs::DirBuilder::new();
    use std::os::unix::fs::DirBuilderExt;
    options
        .recursive(true)
        .mode(0o700)
        .create(&path)
        .map_err(|_| "无法创建系统组件恢复目录")?;
    openfortivpn_manager_core::private_file::verify_directory(&path)
        .map_err(|_| "系统组件恢复目录的所有者或权限不安全")?;
    Ok(path)
}
fn component_guard(shared: bool) -> Result<File, String> {
    let directory = component_directory()?;
    openfortivpn_manager_core::private_file::try_lock(&directory.join(".components.lock"), shared)
        .map_err(|_| "系统组件正在运行或升级，请停止所有连接后重试".into())
}
fn component_bundle(uid: u32) -> Result<openfortivpn_manager_core::bundle::Bundle, String> {
    use openfortivpn_manager_core::bundle::{Bundle, Target};
    let mut targets = Vec::new();
    for (name, path, mode) in [
        ("engine", PathBuf::from(ENGINE_PATH), 0o755),
        ("helper", PathBuf::from(HELPER_PATH), 0o755),
        ("sudoers", sudoers_path(uid), 0o440),
    ] {
        let parent = path.parent().ok_or("组件目标缺少目录")?;
        fs::create_dir_all(parent).map_err(|_| "无法创建系统组件目录")?;
        let metadata = fs::symlink_metadata(parent).map_err(|_| "无法检查组件目录")?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("系统组件目录的所有者或权限不安全".into());
        }
        let canonical = fs::canonicalize(parent).map_err(|_| "无法确认组件目标目录")?;
        targets.push(Target {
            name: name.into(),
            path: canonical.join(path.file_name().ok_or("无效组件路径")?),
            mode,
        });
    }
    Bundle::open(&component_directory()?, targets).map_err(|e| e.to_string())
}
fn read_component_source(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "无法打开系统组件来源")?;
    let metadata = file.metadata().map_err(|_| "无法检查系统组件来源")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 256 * 1024 * 1024 {
        return Err("系统组件必须是非空且大小受限的普通文件".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "无法读取系统组件")?;
    if bytes.len() as u64 != metadata.len() {
        return Err("系统组件来源在读取时发生变化".into());
    }
    Ok(bytes)
}
fn refuse_records(directory: &Path, depth: u8) -> Result<(), String> {
    if !directory.try_exists().map_err(|_| "无法检查组件恢复目录")? {
        return Ok(());
    }
    let mut count = 0;
    for entry in fs::read_dir(directory).map_err(|_| "无法检查遗留组件实例")? {
        count += 1;
        if count > 4096 {
            return Err("组件实例目录超过限制".into());
        }
        let entry = entry.map_err(|_| "无法读取组件实例")?;
        let kind = entry.file_type().map_err(|_| "无法检查实例类型")?;
        if kind.is_symlink() {
            return Err("组件恢复目录包含符号链接".into());
        }
        if entry
            .path()
            .extension()
            .is_some_and(|s| s == "instance" || s == "launch")
        {
            return Err("存在未完成的 helper 实例，请先完成进程与网络恢复".into());
        }
        if kind.is_dir() {
            if depth == 0 {
                return Err("组件实例目录层级无效".into());
            }
            refuse_records(&entry.path(), depth - 1)?;
        }
    }
    Ok(())
}
fn refuse_unfinished_components() -> Result<(), String> {
    refuse_records(Path::new(RUN_DIRECTORY), 2)
}
fn network_maintenance_guard(
) -> Result<openfortivpn_manager_core::network_authority::MaintenanceGuard, String> {
    let directory = openfortivpn_manager_core::network_authority::system_directory()
        .map_err(|e| e.to_string())?;
    openfortivpn_manager_core::network_authority::maintenance_guard(&directory)
        .map_err(|e| e.to_string())
}

fn sudoers_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/etc/sudoers.d/openfortivpn-manager-{uid}"))
}

fn visudo_path() -> Option<&'static str> {
    ["/usr/sbin/visudo", "/sbin/visudo"]
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
}

fn checked_sudoers(uid: u32, username: &str) -> Result<Vec<u8>, String> {
    let contents = format!("# Managed by OpenFortiVPN Manager for UID {uid}\n{username} ALL=(root) NOPASSWD: {HELPER_PATH}\n").into_bytes();
    let random = random_hex(16)?;
    let temporary = component_directory()?.join(format!(".sudoers-check-{}", random));
    openfortivpn_manager_core::atomic_file::write_new_private(&temporary, &contents)
        .map_err(|_| "无法暂存 sudoers 规则")?;
    let result = (|| {
        let visudo = visudo_path().ok_or("系统未安装 visudo")?;
        let status = Command::new(visudo)
            .arg("-cf")
            .arg(&temporary)
            .stdin(Stdio::null())
            .status()
            .map_err(|_| "无法运行 visudo")?;
        if !status.success() {
            return Err("visudo 拒绝了生成的权限规则".into());
        }
        Ok(contents)
    })();
    let _ = fs::remove_file(temporary);
    result
}

fn current_is_installed_helper() -> bool {
    env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .zip(Path::new(HELPER_PATH).canonicalize().ok())
        .is_some_and(|(current, installed)| current == installed)
}

fn check_installation() -> Result<(), String> {
    require_root()?;
    if !current_is_installed_helper() {
        return Err("必须通过固定安装路径调用 helper".to_string());
    }
    ensure_regular_safe_file(Path::new(HELPER_PATH), Some(0))?;
    ensure_regular_safe_file(Path::new(ENGINE_PATH), Some(0))?;
    Ok(())
}

fn install(engine_source: &Path) -> Result<(), String> {
    require_root()?;
    if current_is_installed_helper() {
        return Err("已安装的免密 helper 禁止覆盖安装；请从应用包内重新执行安装".to_string());
    }
    let uid = invoking_uid()?;
    let (username, _) = passwd_for_uid(uid)?;
    let helper_source = env::current_exe().map_err(|error| format!("无法定位 helper：{error}"))?;
    let _guard = component_guard(false)?;
    let _network = network_maintenance_guard()?;
    refuse_unfinished_components()?;
    let mut bundle = component_bundle(uid)?;
    bundle.recover().map_err(|e| e.to_string())?;
    let sudoers = checked_sudoers(uid, &username)?;
    bundle
        .install(BTreeMap::from([
            ("engine".into(), read_component_source(engine_source)?),
            ("helper".into(), read_component_source(&helper_source)?),
            ("sudoers".into(), sudoers),
        ]))
        .map_err(|e| e.to_string())?;
    println!("installed");
    Ok(())
}

fn allowed_runtime_directory(uid: u32) -> Result<PathBuf, String> {
    let (_, home) = passwd_for_uid(uid)?;
    #[cfg(target_os = "macos")]
    let directory = home
        .join("Library")
        .join("Application Support")
        .join(APP_IDENTIFIER)
        .join("runtime");
    #[cfg(not(target_os = "macos"))]
    let directory = home
        .join(".local")
        .join("share")
        .join(APP_IDENTIFIER)
        .join("runtime");
    Ok(directory)
}

fn open_runtime_config(path: &Path, uid: u32) -> Result<File, String> {
    let runtime = allowed_runtime_directory(uid)?;
    if path.parent() != Some(runtime.as_path())
        || path.extension().and_then(|value| value.to_str()) != Some("conf")
    {
        return Err("运行配置不在应用的受保护 runtime 目录中".to_string());
    }
    let directory_metadata = fs::symlink_metadata(&runtime)
        .map_err(|error| format!("无法检查运行目录 {}：{error}", runtime.display()))?;
    if directory_metadata.file_type().is_symlink()
        || !directory_metadata.is_dir()
        || directory_metadata.uid() != uid
        || directory_metadata.mode() & 0o777 != 0o700
    {
        return Err("应用 runtime 目录必须由调用用户拥有、使用 0700 且不能是符号链接".to_string());
    }

    // Open first, then validate the opened file descriptor. O_NOFOLLOW blocks
    // final-component symlinks and descriptor validation prevents a rename or
    // parent-directory swap from turning this privileged read into a root-file
    // disclosure race.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("无法安全打开运行配置：{error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("无法检查已打开的运行配置：{error}"))?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err("运行配置必须是调用用户拥有的 0600 普通文件且不能超过 64 KiB".to_string());
    }
    Ok(file)
}

fn validate_config_contents(contents: &str) -> Result<(), String> {
    if contents.len() as u64 > MAX_CONFIG_BYTES || contents.contains('\0') {
        return Err("运行配置大小或编码无效".to_string());
    }
    let mut keys = HashSet::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("运行配置第 {} 行格式无效", index + 1))?;
        let key = key.trim();
        let value = value.trim();
        if !keys.insert(key) {
            return Err(format!("运行配置包含重复字段：{key}"));
        }
        match key {
            "host" | "username" | "password" | "realm" => {}
            "gateway-dns" => {
                if value.is_empty() {
                    return Err("网关 DNS 不能为空；使用系统 DNS 时应省略该字段".into());
                }
                openfortivpn_manager_core::validation::gateway_dns(value)
                    .map_err(|error| error.to_string())?;
            }
            "port" => {
                let port = value
                    .parse::<u16>()
                    .map_err(|_| "VPN 端口无效".to_string())?;
                if port == 0 {
                    return Err("VPN 端口不能为 0".to_string());
                }
            }
            "trusted-cert" => {
                if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err("受信证书指纹必须是 64 位十六进制 SHA-256".to_string());
                }
            }
            "set-routes" | "set-dns" | "pppd-use-peerdns" | "half-internet-routes" => {
                if value != "0" && value != "1" {
                    return Err(format!("{key} 只能是 0 或 1"));
                }
            }
            _ => return Err(format!("系统 helper 拒绝未授权的配置字段：{key}")),
        }
    }
    if !keys.contains("host") || !keys.contains("port") {
        return Err("运行配置缺少 host 或 port".to_string());
    }
    Ok(())
}

fn write_root_runtime_config(contents: &str, uid: u32) -> Result<PathBuf, String> {
    let directory = Path::new(RUN_DIRECTORY);
    fs::create_dir_all(directory).map_err(|error| format!("无法创建 root 运行目录：{error}"))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("无法保护 root 运行目录：{error}"))?;
    chown_root(directory)?;
    let path = directory.join(format!("{uid}-{}.conf", process::id()));
    let _ = fs::remove_file(&path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("无法创建 root 运行配置：{error}"))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("无法写入 root 运行配置：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("无法同步 root 运行配置：{error}"))?;
    chown_root(&path)?;
    Ok(path)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: i32,
    parent_pid: i32,
    process_group: i32,
    effective_uid: u32,
    start_primary: u64,
    start_secondary: u64,
    executable_device: u64,
    executable_inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InstanceRecord {
    instance_id: String,
    control_token: String,
    owner_uid: u32,
    supervisor: ProcessIdentity,
    engine: ProcessIdentity,
}

fn random_hex(byte_count: usize) -> Result<String, String> {
    let mut bytes = vec![0_u8; byte_count];
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| format!("无法生成安全实例标识：{error}"))?;
    let mut encoded = String::with_capacity(byte_count * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}

fn process_executable_identity(pid: i32) -> Result<(PathBuf, u64, u64), String> {
    #[cfg(target_os = "macos")]
    let path = {
        let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let length = unsafe {
            libc::proc_pidpath(
                pid,
                buffer.as_mut_ptr().cast(),
                libc::PROC_PIDPATHINFO_MAXSIZE as u32,
            )
        };
        if length <= 0 {
            return Err(format!(
                "无法读取进程 {pid} 的可执行文件：{}",
                io::Error::last_os_error()
            ));
        }
        buffer.truncate(length as usize);
        PathBuf::from(std::ffi::OsString::from_vec(buffer))
    };

    #[cfg(not(target_os = "macos"))]
    let path = fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|error| format!("无法读取进程 {pid} 的可执行文件：{error}"))?;

    #[cfg(target_os = "macos")]
    let metadata_path = path.clone();
    #[cfg(not(target_os = "macos"))]
    let metadata_path = PathBuf::from(format!("/proc/{pid}/exe"));

    let metadata = fs::metadata(&metadata_path)
        .map_err(|error| format!("无法读取进程 {pid} 的可执行文件身份：{error}"))?;
    Ok((path, metadata.dev(), metadata.ino()))
}

#[cfg(target_os = "macos")]
fn read_process_identity_once(pid: i32) -> Result<ProcessIdentity, String> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected_size = std::mem::size_of::<libc::proc_bsdinfo>();
    let actual_size = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            expected_size as i32,
        )
    };
    if actual_size != expected_size as i32 {
        return Err(format!(
            "无法读取进程 {pid} 的内核身份：{}",
            io::Error::last_os_error()
        ));
    }
    let info = unsafe { info.assume_init() };
    let (_, executable_device, executable_inode) = process_executable_identity(pid)?;
    Ok(ProcessIdentity {
        pid: info.pbi_pid as i32,
        parent_pid: info.pbi_ppid as i32,
        process_group: info.pbi_pgid as i32,
        effective_uid: info.pbi_uid,
        start_primary: info.pbi_start_tvsec,
        start_secondary: info.pbi_start_tvusec,
        executable_device,
        executable_inode,
    })
}

#[cfg(not(target_os = "macos"))]
fn read_process_identity_once(pid: i32) -> Result<ProcessIdentity, String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("无法读取进程 {pid} 的启动身份：{error}"))?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| format!("进程 {pid} 的内核状态格式无效"))?;
    let fields: Vec<&str> = fields.split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(format!("进程 {pid} 的内核状态字段不足"));
    }
    let parse_field = |index: usize, name: &str| {
        fields[index]
            .parse::<i32>()
            .map_err(|_| format!("进程 {pid} 的 {name} 无效"))
    };
    let parent_pid = parse_field(1, "父进程编号")?;
    let process_group = parse_field(2, "进程组编号")?;
    let start_primary = fields[19]
        .parse::<u64>()
        .map_err(|_| format!("进程 {pid} 的启动时钟无效"))?;

    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| format!("无法读取进程 {pid} 的用户身份：{error}"))?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| format!("进程 {pid} 缺少用户身份"))?;
    let effective_uid = uid_line
        .split_whitespace()
        .nth(2)
        .ok_or_else(|| format!("进程 {pid} 的有效用户身份缺失"))?
        .parse::<u32>()
        .map_err(|_| format!("进程 {pid} 的有效用户身份无效"))?;
    let (_, executable_device, executable_inode) = process_executable_identity(pid)?;
    Ok(ProcessIdentity {
        pid,
        parent_pid,
        process_group,
        effective_uid,
        start_primary,
        start_secondary: 0,
        executable_device,
        executable_inode,
    })
}

fn read_process_identity(pid: i32) -> Result<ProcessIdentity, String> {
    if pid <= 1 {
        return Err("进程编号无效".to_string());
    }
    let first = read_process_identity_once(pid)?;
    let second = read_process_identity_once(pid)?;
    if first != second {
        return Err(format!("进程 {pid} 在身份校验期间发生变化"));
    }
    Ok(first)
}

fn verify_fixed_executable(identity: &ProcessIdentity, expected: &Path) -> Result<(), String> {
    let metadata = ensure_regular_safe_file(expected, Some(0))?;
    if identity.executable_device != metadata.dev() || identity.executable_inode != metadata.ino() {
        return Err(format!(
            "进程 {} 并非由固定可执行文件 {} 启动",
            identity.pid,
            expected.display()
        ));
    }
    Ok(())
}

fn protect_root_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("无法创建 {}：{error}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("无法检查 {}：{error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} 必须是非符号链接目录", path.display()));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("无法保护 {}：{error}", path.display()))?;
    chown_root(path)?;
    Ok(())
}

fn instance_directory(uid: u32) -> Result<PathBuf, String> {
    let run_directory = Path::new(RUN_DIRECTORY);
    protect_root_directory(run_directory)?;
    let instances = run_directory.join("instances");
    protect_root_directory(&instances)?;
    let user_instances = instances.join(uid.to_string());
    protect_root_directory(&user_instances)?;
    Ok(user_instances)
}

fn instance_record_path(uid: u32, instance_id: &str) -> Result<PathBuf, String> {
    Ok(instance_directory(uid)?.join(format!("{instance_id}.instance")))
}

fn instance_socket_path(uid: u32, instance_id: &str) -> Result<PathBuf, String> {
    Ok(instance_directory(uid)?.join(format!("{instance_id}.sock")))
}

fn serialize_process(prefix: &str, identity: &ProcessIdentity, output: &mut String) {
    use std::fmt::Write as _;
    writeln!(output, "{prefix}_pid={}", identity.pid).unwrap();
    writeln!(output, "{prefix}_parent_pid={}", identity.parent_pid).unwrap();
    writeln!(output, "{prefix}_process_group={}", identity.process_group).unwrap();
    writeln!(output, "{prefix}_effective_uid={}", identity.effective_uid).unwrap();
    writeln!(output, "{prefix}_start_primary={}", identity.start_primary).unwrap();
    writeln!(
        output,
        "{prefix}_start_secondary={}",
        identity.start_secondary
    )
    .unwrap();
    writeln!(
        output,
        "{prefix}_executable_device={}",
        identity.executable_device
    )
    .unwrap();
    writeln!(
        output,
        "{prefix}_executable_inode={}",
        identity.executable_inode
    )
    .unwrap();
}

fn serialize_instance_record(record: &InstanceRecord) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    writeln!(output, "version={INSTANCE_RECORD_VERSION}").unwrap();
    writeln!(output, "instance_id={}", record.instance_id).unwrap();
    writeln!(output, "control_token={}", record.control_token).unwrap();
    writeln!(output, "owner_uid={}", record.owner_uid).unwrap();
    serialize_process("supervisor", &record.supervisor, &mut output);
    serialize_process("engine", &record.engine, &mut output);
    output
}

fn parse_instance_record(contents: &str) -> Result<InstanceRecord, String> {
    let mut values = std::collections::HashMap::new();
    for line in contents.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "实例记录格式无效".to_string())?;
        if key.is_empty() || value.is_empty() || values.insert(key, value).is_some() {
            return Err("实例记录包含空值或重复字段".to_string());
        }
    }
    let expected_fields = 4 + 8 * 2;
    if values.len() != expected_fields {
        return Err("实例记录字段数量无效".to_string());
    }
    let value = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("实例记录缺少字段：{key}"))
    };
    if value("version")?.parse::<u32>().ok() != Some(INSTANCE_RECORD_VERSION) {
        return Err("实例记录版本不受支持".to_string());
    }
    let instance_id = value("instance_id")?.to_string();
    let control_token = value("control_token")?.to_string();
    let valid_hex = |text: &str, bytes: usize| {
        text.len() == bytes * 2
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if !valid_hex(&instance_id, INSTANCE_IDENTIFIER_BYTES)
        || !valid_hex(&control_token, CONTROL_TOKEN_BYTES)
    {
        return Err("实例标识或控制令牌无效".to_string());
    }
    let number = |key: &str| {
        value(key)?
            .parse::<u64>()
            .map_err(|_| format!("实例记录数值无效：{key}"))
    };
    let process = |prefix: &str| -> Result<ProcessIdentity, String> {
        let signed = |suffix: &str| {
            value(&format!("{prefix}_{suffix}"))?
                .parse::<i32>()
                .map_err(|_| format!("实例记录进程字段无效：{prefix}_{suffix}"))
        };
        let unsigned = |suffix: &str| number(&format!("{prefix}_{suffix}"));
        Ok(ProcessIdentity {
            pid: signed("pid")?,
            parent_pid: signed("parent_pid")?,
            process_group: signed("process_group")?,
            effective_uid: unsigned("effective_uid")?
                .try_into()
                .map_err(|_| "实例记录 UID 超出范围".to_string())?,
            start_primary: unsigned("start_primary")?,
            start_secondary: unsigned("start_secondary")?,
            executable_device: unsigned("executable_device")?,
            executable_inode: unsigned("executable_inode")?,
        })
    };
    Ok(InstanceRecord {
        instance_id,
        control_token,
        owner_uid: number("owner_uid")?
            .try_into()
            .map_err(|_| "实例记录所有者 UID 超出范围".to_string())?,
        supervisor: process("supervisor")?,
        engine: process("engine")?,
    })
}

fn write_instance_record(record: &InstanceRecord) -> Result<PathBuf, String> {
    let destination = instance_record_path(record.owner_uid, &record.instance_id)?;
    if destination.exists() {
        return Err("安全实例标识发生冲突".to_string());
    }
    let temporary = destination.with_extension(format!("tmp-{}", process::id()));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("无法创建实例记录：{error}"))?;
    file.write_all(serialize_instance_record(record).as_bytes())
        .map_err(|error| format!("无法写入实例记录：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("无法同步实例记录：{error}"))?;
    drop(file);
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("无法保护实例记录：{error}"))?;
    chown_root(&temporary)?;
    fs::rename(&temporary, &destination).map_err(|error| format!("无法发布实例记录：{error}"))?;
    File::open(destination.parent().ok_or("实例记录缺少目录")?)
        .and_then(|f| f.sync_all())
        .map_err(|_| "无法同步实例记录目录")?;
    Ok(destination)
}

fn read_instance_record(path: &Path) -> Result<InstanceRecord, String> {
    let bytes = openfortivpn_manager_core::private_file::read(path, 8192)
        .map_err(|_| "无法安全读取 root 实例记录")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "实例记录编码无效")?;
    parse_instance_record(text)
}

fn process_matches_record(expected: &ProcessIdentity, actual: &ProcessIdentity) -> bool {
    expected == actual
}

fn validate_instance_relationships(record: &InstanceRecord) -> Result<(), String> {
    if record.owner_uid == 0
        || record.supervisor.process_group <= 1
        || record.engine.parent_pid != record.supervisor.pid
        || record.engine.process_group != record.supervisor.process_group
        || record.supervisor.effective_uid != 0
        || record.engine.effective_uid != 0
    {
        return Err("实例记录的所有权或进程关系无效".to_string());
    }
    Ok(())
}

fn validate_live_instance(record: &InstanceRecord) -> Result<(), String> {
    validate_instance_relationships(record)?;
    let supervisor = read_process_identity(record.supervisor.pid)?;
    let engine = read_process_identity(record.engine.pid)?;
    if !process_matches_record(&record.supervisor, &supervisor)
        || !process_matches_record(&record.engine, &engine)
    {
        return Err("实例进程已退出或 PID/PGID 已被复用".to_string());
    }
    Ok(())
}

fn bind_control_socket(record: &InstanceRecord) -> Result<(UnixListener, PathBuf), String> {
    let socket_path = instance_socket_path(record.owner_uid, &record.instance_id)?;
    if socket_path.exists() {
        return Err("实例控制套接字已存在".to_string());
    }
    let listener = UnixListener::bind(&socket_path)
        .map_err(|error| format!("无法创建实例控制通道：{error}"))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("无法保护实例控制通道：{error}"))?;
    chown_root(&socket_path)?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("无法设置实例控制通道：{error}"))?;
    Ok((listener, socket_path))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut different = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        different |= usize::from(left_byte ^ right_byte);
    }
    different == 0
}

fn handle_control_request(mut stream: UnixStream, record: &InstanceRecord) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("无法设置控制请求超时：{error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("无法设置控制响应超时：{error}"))?;
    let mut request = Vec::new();
    Read::by_ref(&mut stream)
        .take(CONTROL_MESSAGE_LIMIT)
        .read_to_end(&mut request)
        .map_err(|error| format!("无法读取控制请求：{error}"))?;
    let expected = format!("stop {}\n", record.control_token);
    if !constant_time_equal(&request, expected.as_bytes()) {
        let _ = stream.write_all(b"denied\n");
        return Err("实例控制令牌无效".to_string());
    }
    validate_live_instance(record)?;
    let result = unsafe { libc::kill(-record.supervisor.process_group, libc::SIGTERM) };
    if result != 0 {
        let message = format!("无法停止 VPN 进程组：{}", io::Error::last_os_error());
        let _ = stream.write_all(b"error\n");
        return Err(message);
    }
    stream
        .write_all(b"ok\n")
        .map_err(|error| format!("无法确认停止请求：{error}"))
}

fn supervise_engine(
    child: &OwnedProcess,
    listener: &UnixListener,
    record: &InstanceRecord,
) -> Result<ExitStatus, String> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("无法等待固定 VPN 引擎：{error}"))?
        {
            return Ok(status);
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(message) = handle_control_request(stream, record) {
                    eprintln!("拒绝实例控制请求：{message}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(format!("无法接收实例控制请求：{error}")),
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn relay_engine_output<R: openfortivpn_manager_core::process_output::Pipe + Send + 'static>(
    stream: R,
    fd: i32,
    lifecycle: std::sync::Arc<
        std::sync::Mutex<openfortivpn_manager_core::lifecycle::EngineLifecycle>,
    >,
) -> Result<openfortivpn_manager_core::supervisor::StreamWorker, String> {
    use openfortivpn_manager_core::protocol::{Line, LineDecoder};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("无法建立非阻塞引擎输出转发".into());
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    let join = thread::spawn(move || {
        let mut stream =
            openfortivpn_manager_core::process_output::CancellablePipe::new(stream, flag.clone());
        let mut decoder = LineDecoder::default();
        let mut buffer = [0u8; 4096];
        let mut complete = true;
        let mut forward = true;
        loop {
            let length = match stream.read(&mut buffer) {
                Ok(n) => n,
                Err(_) => {
                    complete = false;
                    break;
                }
            };
            if forward && length > 0 {
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                let mut bytes = &buffer[..length];
                while !bytes.is_empty() && !flag.load(Ordering::Acquire) {
                    let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
                    if written > 0 {
                        bytes = &bytes[written as usize..];
                        continue;
                    }
                    let error = io::Error::last_os_error();
                    if std::time::Instant::now() >= deadline
                        || (written < 0
                            && !matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ))
                    {
                        forward = false;
                        complete = false;
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
            let lines = if length == 0 {
                decoder.eof().into_iter().collect()
            } else {
                decoder.feed(&buffer[..length])
            };
            for line in lines {
                match line {
                    Line::Text(text) => {
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&text) {
                            if event.get("event").is_some()
                                && lifecycle
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .observe(&event)
                                    .is_err()
                            {
                                complete = false;
                            }
                        }
                    }
                    _ => complete = false,
                }
            }
            if length == 0 {
                break;
            }
        }
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
        complete && !flag.load(Ordering::Acquire)
    });
    Ok(openfortivpn_manager_core::supervisor::StreamWorker { join, cancelled })
}

fn register_instance(
    owner_uid: u32,
    supervisor: ProcessIdentity,
    engine: ProcessIdentity,
) -> Result<(InstanceRecord, UnixListener, PathBuf, PathBuf), String> {
    for _ in 0..8 {
        let record = InstanceRecord {
            instance_id: random_hex(INSTANCE_IDENTIFIER_BYTES)?,
            control_token: random_hex(CONTROL_TOKEN_BYTES)?,
            owner_uid,
            supervisor: supervisor.clone(),
            engine: engine.clone(),
        };
        let (listener, socket_path) = match bind_control_socket(&record) {
            Ok(value) => value,
            Err(message) if message == "实例控制套接字已存在" => continue,
            Err(message) => return Err(message),
        };
        match write_instance_record(&record) {
            Ok(record_path) => return Ok((record, listener, record_path, socket_path)),
            Err(message) if message == "安全实例标识发生冲突" => {
                let _ = fs::remove_file(&socket_path);
            }
            Err(message) => {
                let _ = fs::remove_file(&socket_path);
                return Err(message);
            }
        }
    }
    Err("无法分配唯一的安全实例标识".to_string())
}

fn stop_unregistered_child(child: &OwnedProcess) {
    let _ = child.lock().and_then(|mut child| child.kill());
    child.wait_reaped();
}

fn validate_manager_attempt(attempt: &str) -> Result<(), String> {
    if attempt.len() != 36
        || !attempt.bytes().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
    {
        return Err("无效的私有通道实例标识".into());
    }
    Ok(())
}

fn validate_control_pipe(fd: std::os::fd::RawFd) -> Result<(), String> {
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, info.as_mut_ptr()) } != 0 {
        return Err("无法验证私有输入管道".into());
    }
    if unsafe { info.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err("管理器控制输入必须是独立继承管道".into());
    }
    Ok(())
}

fn run_engine(
    config: &Path,
    attempt: Option<&str>,
    owner_attempt: Option<&str>,
) -> Result<(), String> {
    let _components = component_guard(true)?;
    if Path::new(COMPONENT_DIRECTORY).join("pending.json").exists() {
        return Err("系统组件升级未完成，请从应用包重新安装或回滚后再连接".into());
    }
    check_installation()?;
    if let Some(attempt) = attempt {
        validate_manager_attempt(attempt)?;
        validate_control_pipe(libc::STDIN_FILENO)?;
    }
    if let Some(owner) = owner_attempt {
        validate_manager_attempt(owner)?;
        if attempt.is_some_and(|control| control != owner) {
            return Err("控制通道与所有权实例不一致".into());
        }
    }
    let uid = invoking_uid()?;
    let mut config = open_runtime_config(config, uid)?;
    let mut contents = zeroize::Zeroizing::new(String::new());
    Read::by_ref(&mut config)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| format!("无法读取运行配置：{error}"))?;
    validate_config_contents(&contents)?;
    let supervisor = read_process_identity(process::id() as i32)?;
    verify_fixed_executable(&supervisor, Path::new(HELPER_PATH))?;
    if supervisor.effective_uid != 0 || supervisor.process_group <= 1 {
        return Err("helper 必须使用独立的 root 进程组".into());
    }
    let authority = openfortivpn_manager_core::network_authority::system_directory()
        .map_err(|e| e.to_string())?;
    let lease = openfortivpn_manager_core::network_authority::ExclusiveLease::acquire(
        &authority,
        openfortivpn_manager_core::network_authority::Owner {
            attempt_id: owner_attempt
                .or(attempt)
                .map(str::to_owned)
                .map(Ok)
                .unwrap_or_else(|| random_hex(16))?,
            manager: "helper".into(),
            uid,
            process_group: supervisor.process_group as u32,
            pre_spawn_gated: false,
        },
    )
    .map_err(|e| e.to_string())?;
    // Durable before spawn: a killed helper must never unlock networking merely
    // because its process lock was released, even before engine registration.
    let protected_config = match write_root_runtime_config(&contents, uid) {
        Ok(path) => path,
        Err(error) => {
            lease.finish(true, true).map_err(|e| e.to_string())?;
            return Err(error);
        }
    };
    struct ConfigCleanup(PathBuf);
    impl Drop for ConfigCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let _config_cleanup = ConfigCleanup(protected_config.clone());
    let mut command = Command::new(ENGINE_PATH);
    // An older engine must reject an explicit resolver rather than silently
    // ignoring an unknown configuration key and using system DNS.
    for line in contents.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "gateway-dns" {
                command.arg(format!("--gateway-dns={}", value.trim()));
            }
        }
    }
    if let Some(attempt) = attempt {
        // No administrative command is accepted on this pipe. The fixed engine
        // validates OFV2 attempt, outstanding nonce, action, bounds and deadline.
        command.arg(format!("--manager-control={attempt}"));
    }
    let child = match command
        .arg("--json-events")
        .arg("-c")
        .arg(&protected_config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if attempt.is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&protected_config);
            lease.finish(true, true).map_err(|e| e.to_string())?;
            return Err(format!("无法执行固定 VPN 引擎：{error}"));
        }
    };
    let child = OwnedProcess::new(child);

    let lifecycle = std::sync::Arc::new(std::sync::Mutex::new(
        attempt
            .map(|id| openfortivpn_manager_core::lifecycle::EngineLifecycle::for_attempt(id, true))
            .unwrap_or_default(),
    ));
    let mut readers = Vec::new();
    let setup = (|| {
        readers.push(relay_engine_output(
            child
                .lock()
                .map_err(|_| "引擎状态不可用")?
                .stdout
                .take()
                .ok_or("引擎输出管道缺失")?,
            libc::STDOUT_FILENO,
            lifecycle.clone(),
        )?);
        readers.push(relay_engine_output(
            child
                .lock()
                .map_err(|_| "引擎状态不可用")?
                .stderr
                .take()
                .ok_or("引擎输出管道缺失")?,
            libc::STDERR_FILENO,
            lifecycle.clone(),
        )?);
        Ok::<_, String>(())
    })();
    if let Err(error) = setup {
        stop_unregistered_child(&child);
        openfortivpn_manager_core::supervisor::drain_streams(readers, Duration::from_secs(2));
        return Err(error);
    }
    let identities = (|| {
        let supervisor = read_process_identity(process::id() as i32)?;
        let engine =
            read_process_identity(child.lock().map_err(|_| "引擎状态不可用")?.id() as i32)?;
        verify_fixed_executable(&supervisor, Path::new(HELPER_PATH))?;
        verify_fixed_executable(&engine, Path::new(ENGINE_PATH))?;
        if supervisor.effective_uid != 0
            || engine.effective_uid != 0
            || supervisor.process_group <= 1
            || engine.parent_pid != supervisor.pid
            || engine.process_group != supervisor.process_group
        {
            return Err("helper 与 VPN 引擎未形成受保护的独立进程组".to_string());
        }
        Ok((supervisor, engine))
    })();
    let (supervisor, engine) = match identities {
        Ok(identities) => identities,
        Err(message) => {
            stop_unregistered_child(&child);
            openfortivpn_manager_core::supervisor::drain_streams(readers, Duration::from_secs(2));
            let _ = fs::remove_file(&protected_config);
            return Err(message);
        }
    };

    // The engine inherited the default disposition at spawn time. The helper
    // remains alive in the same dedicated group (whose leader may be sudo) so it
    // can authenticate stop requests through its root-only socket. The recorded
    // helper and engine identities prevent a reused PID/PGID from being trusted.
    let previous_handler = unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    if previous_handler == libc::SIG_ERR {
        stop_unregistered_child(&child);
        openfortivpn_manager_core::supervisor::drain_streams(readers, Duration::from_secs(2));
        let _ = fs::remove_file(&protected_config);
        return Err(format!(
            "无法保护 VPN supervisor：{}",
            io::Error::last_os_error()
        ));
    }

    let registration = register_instance(uid, supervisor, engine);
    let (record, listener, record_path, socket_path) = match registration {
        Ok(registration) => registration,
        Err(message) => {
            stop_unregistered_child(&child);
            openfortivpn_manager_core::supervisor::drain_streams(readers, Duration::from_secs(2));
            let _ = fs::remove_file(&protected_config);
            return Err(message);
        }
    };
    let status = supervise_engine(&child, &listener, &record);
    // On a supervisor error keep ownership, request a normal group stop and
    // wait. Never unlink recovery evidence while the engine may still run.
    let status = match status {
        Ok(status) => Ok(status),
        Err(error) => {
            let _ = unsafe { libc::kill(-record.supervisor.process_group, libc::SIGTERM) };
            child.wait_reaped();
            Err(error)
        }
    };
    let output_complete =
        openfortivpn_manager_core::supervisor::drain_streams(readers, Duration::from_secs(2));
    use std::os::unix::process::ExitStatusExt;
    let cleanup = lifecycle.lock().map_err(|_| "引擎清理状态损坏")?.reaped(
        output_complete,
        status
            .as_ref()
            .map_or(true, |s| s.signal() == Some(libc::SIGKILL)),
    );
    if status.is_ok() && cleanup {
        // Delete and durably sync subordinate evidence before releasing the
        // global reservation. A failed unlink/fsync must remain recoverable.
        cleanup_instance_record(&record_path, sync_instance_directory)?;
        lease.finish(true, true).map_err(|e| e.to_string())?;
    }
    drop(listener);
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(&protected_config);
    let status = status?;
    if !cleanup {
        return Err("进程已收割，但输出或网络清理未确认；系统网络恢复记录已保留".into());
    }
    if status.success() {
        Ok(())
    } else {
        process::exit(status.code().unwrap_or(1));
    }
}

fn find_owned_instance(uid: u32, process_group: i32) -> Result<InstanceRecord, String> {
    let directory = instance_directory(uid)?;
    let mut matching = None;
    for entry in
        fs::read_dir(&directory).map_err(|error| format!("无法读取当前用户的实例记录：{error}"))?
    {
        let entry = entry.map_err(|error| format!("无法读取实例记录目录项：{error}"))?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("instance") {
            continue;
        }
        let record = read_instance_record(&entry.path())?;
        if record.owner_uid == uid
            && record.supervisor.process_group == process_group
            && matching.replace(record).is_some()
        {
            return Err("同一进程组存在多个实例记录，拒绝停止".to_string());
        }
    }
    matching.ok_or_else(|| "未找到属于当前调用用户的 VPN 实例".to_string())
}

fn verify_control_socket(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("无法检查实例控制通道：{error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("实例控制通道不是 root 专用的 0600 Unix socket".to_string());
    }
    Ok(())
}

fn request_instance_stop(record: &InstanceRecord) -> Result<(), String> {
    validate_live_instance(record)?;
    let socket_path = instance_socket_path(record.owner_uid, &record.instance_id)?;
    verify_control_socket(&socket_path)?;
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|error| format!("无法连接实例 supervisor：{error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("无法设置停止响应超时：{error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("无法设置停止请求超时：{error}"))?;
    writeln!(stream, "stop {}", record.control_token)
        .map_err(|error| format!("无法提交停止请求：{error}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| format!("无法完成停止请求：{error}"))?;
    let mut response = String::new();
    stream
        .take(CONTROL_MESSAGE_LIMIT)
        .read_to_string(&mut response)
        .map_err(|error| format!("无法读取停止响应：{error}"))?;
    if response == "ok\n" {
        Ok(())
    } else {
        Err("实例 supervisor 拒绝了停止请求".to_string())
    }
}

fn stop_engine(process_group: i32) -> Result<(), String> {
    check_installation()?;
    let uid = invoking_uid()?;
    if process_group <= 1 {
        return Err("进程组编号无效".to_string());
    }
    let record = find_owned_instance(uid, process_group)?;
    request_instance_stop(&record)
}

fn uninstall() -> Result<(), String> {
    require_root()?;
    if current_is_installed_helper() {
        return Err("免密运行中的 helper 无权卸载自身；卸载或升级需要再次管理员授权".to_string());
    }
    let uid = invoking_uid()?;
    let _guard = component_guard(false)?;
    let _network = network_maintenance_guard()?;
    refuse_unfinished_components()?;
    component_bundle(uid)?
        .recover()
        .map_err(|e| e.to_string())?;
    let _ = fs::remove_file(sudoers_path(uid));
    let _ = fs::remove_file(ENGINE_PATH);
    fs::remove_file(HELPER_PATH).map_err(|error| format!("无法删除 helper：{error}"))?;
    println!("uninstalled");
    Ok(())
}

fn rollback_components() -> Result<(), String> {
    require_root()?;
    if current_is_installed_helper() {
        return Err("免密 helper 无权回滚自身；请从应用包内以管理员身份执行回滚".into());
    }
    let uid = invoking_uid()?;
    let _guard = component_guard(false)?;
    let _network = network_maintenance_guard()?;
    refuse_unfinished_components()?;
    component_bundle(uid)?
        .rollback()
        .map_err(|e| e.to_string())?;
    println!("rolled-back");
    Ok(())
}

fn sync_instance_directory(directory: &Path) -> Result<(), String> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| "无法同步 helper 实例清理".into())
}

fn cleanup_instance_record(
    path: &Path,
    synchronize: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    fs::remove_file(path).map_err(|_| "无法删除已完成实例记录")?;
    synchronize(path.parent().ok_or("实例缺少目录")?)
}

fn group_is_absent(group: i32) -> Result<bool, String> {
    if group <= 1 {
        return Err("实例进程组无效，不能确认恢复".into());
    }
    if unsafe { libc::kill(-group, 0) } == 0 {
        return Ok(false);
    }
    if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(true)
    } else {
        Err("无法检查 VPN 进程组".into())
    }
}

fn recover_instance_records(
    directory: &Path,
    uid: u32,
    group: Option<i32>,
    mut absent: impl FnMut(i32) -> Result<bool, String>,
) -> Result<(), String> {
    // Parse and check the entire bounded batch before deleting anything. With
    // no global owner these are old interrupted subordinate deletions, but
    // only the explicitly confirming user's demonstrably dead groups qualify.
    let mut selected = Vec::new();
    for (count, entry) in fs::read_dir(directory)
        .map_err(|_| "无法读取 helper 实例目录")?
        .enumerate()
    {
        if count >= 4096 {
            return Err("helper 实例目录超过恢复上限".into());
        }
        let path = entry.map_err(|_| "无法读取 helper 实例目录项")?.path();
        if path.extension().is_some_and(|s| s == "instance") {
            let record = read_instance_record(&path)?;
            if record.owner_uid != uid
                || path.file_stem().and_then(|s| s.to_str()) != Some(&record.instance_id)
                || record.supervisor.process_group <= 1
                || record.engine.process_group != record.supervisor.process_group
            {
                return Err("helper 实例记录所有者或进程组无效".into());
            }
            if group.is_none_or(|value| value == record.supervisor.process_group) {
                selected.push((path, record));
            }
        }
    }
    for (_, record) in &selected {
        if !absent(record.supervisor.process_group)? {
            return Err("VPN 进程组仍存在；不能清理恢复记录".into());
        }
    }
    for (path, _) in &selected {
        let socket = path.with_extension("sock");
        match fs::symlink_metadata(&socket) {
            Ok(_) => verify_control_socket(&socket)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err("无法检查遗留控制通道".into()),
        }
    }
    for (path, _) in selected {
        cleanup_instance_record(&path, sync_instance_directory)?;
        let socket = path.with_extension("sock");
        match fs::symlink_metadata(&socket) {
            Ok(_) => {
                verify_control_socket(&socket)?;
                fs::remove_file(socket).map_err(|_| "无法删除遗留控制通道")?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err("无法检查遗留控制通道".into()),
        }
    }
    sync_instance_directory(directory)
}

fn acknowledge_network(attempt: &str, confirmed: &str) -> Result<(), String> {
    use openfortivpn_manager_core::{network_authority as authority, ControlError, ErrorCode};
    if confirmed != "--acknowledge-cleanup" {
        return Err("必须先恢复网络资源，再明确确认清理".into());
    }
    let uid = invoking_uid()?;
    let directory = authority::system_directory().map_err(|e| e.to_string())?;
    let Some(owner) = authority::inspect(&directory).map_err(|e| e.to_string())? else {
        let _guard = authority::maintenance_guard(&directory).map_err(|e| e.to_string())?;
        recover_instance_records(&instance_directory(uid)?, uid, None, group_is_absent)?;
        return Ok(());
    };
    if owner.manager != "helper"
        || owner.uid != uid
        || owner.attempt_id != attempt
        || owner.process_group <= 1
    {
        return Err("网络恢复记录不属于当前 helper 用户或无法确认进程组".into());
    }
    authority::acknowledge(&directory, attempt, uid, || {
        if !group_is_absent(owner.process_group as i32)
            .map_err(|e| ControlError::new(ErrorCode::RecoveryRequired, e))?
        {
            return Err(ControlError::new(
                ErrorCode::RecoveryRequired,
                "VPN 进程组仍存在；不能确认网络恢复",
            ));
        }
        let instances = instance_directory(uid)
            .map_err(|e| ControlError::new(ErrorCode::RecoveryRequired, e))?;
        recover_instance_records(
            &instances,
            uid,
            Some(owner.process_group as i32),
            group_is_absent,
        )
        .map_err(|e| ControlError::new(ErrorCode::RecoveryRequired, e))?;
        Ok(true)
    })
    .map_err(|e| e.to_string())?;
    println!("network-recovered");
    Ok(())
}

fn usage() -> ! {
    fail("用法：helper install --engine PATH | check | run CONFIG [--owner-attempt=UUID] [--manager-control=UUID] | stop PGID | recover-network ATTEMPT --acknowledge-cleanup | rollback | uninstall")
}

fn main() {
    let mut arguments = env::args_os().skip(1);
    let command = arguments.next().unwrap_or_default();
    let result = match command.to_str() {
        Some("--capabilities-json") if arguments.next().is_none() => {
            println!("{{\"version\":\"{}\",\"protocolVersion\":{},\"restrictedConfig\":true,\"ownedProcessStop\":true,\"privateControlVersion\":2}}", env!("CARGO_PKG_VERSION"), INSTANCE_RECORD_VERSION);
            Ok(())
        }
        Some("install") => {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--engine")) {
                usage();
            }
            let Some(engine) = arguments.next() else {
                usage();
            };
            if arguments.next().is_some() {
                usage();
            }
            install(Path::new(&engine))
        }
        Some("check") if arguments.next().is_none() => check_installation(),
        Some("run") => {
            let Some(config) = arguments.next() else {
                usage();
            };
            let flags: Vec<_> = arguments.take(3).collect();
            if flags.len() > 2 {
                usage();
            }
            let mut control = None;
            let mut owner = None;
            for flag in &flags {
                let Some(flag) = flag.to_str() else {
                    usage();
                };
                if let Some(value) = flag.strip_prefix("--manager-control=") {
                    if control.replace(value).is_some() {
                        usage();
                    }
                } else if let Some(value) = flag.strip_prefix("--owner-attempt=") {
                    if owner.replace(value).is_some() {
                        usage();
                    }
                } else {
                    usage();
                }
            }
            run_engine(Path::new(&config), control, owner)
        }
        Some("stop") => match (arguments.next(), arguments.next()) {
            (Some(group), None) => group
                .to_str()
                .ok_or_else(|| "进程组编号无效".to_string())
                .and_then(|group| {
                    group
                        .parse::<i32>()
                        .map_err(|_| "进程组编号无效".to_string())
                })
                .and_then(stop_engine),
            _ => usage(),
        },
        Some("rollback") if arguments.next().is_none() => rollback_components(),
        Some("recover-network") => match (arguments.next(), arguments.next(), arguments.next()) {
            (Some(attempt), Some(confirmation), None) => {
                match (attempt.to_str(), confirmation.to_str()) {
                    (Some(attempt), Some(confirmation)) => {
                        acknowledge_network(attempt, confirmation)
                    }
                    _ => usage(),
                }
            }
            _ => usage(),
        },
        Some("uninstall") if arguments.next().is_none() => uninstall(),
        _ => usage(),
    };
    if let Err(message) = result {
        if command == "run" {
            eprintln!("{message}");
            process::exit(HELPER_RUN_FAILED);
        }
        fail(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn helper_setup_or_recovery_failure_never_triggers_automatic_engine_retry() {
        assert!(!openfortivpn_manager_core::lifecycle::exit_retryable(Some(
            HELPER_RUN_FAILED
        )));
    }
    #[test]
    fn setup_failure_reaps_the_owned_child_and_joins_an_already_started_reader() {
        use std::os::fd::AsRawFd;
        let process = OwnedProcess::new(
            Command::new("/bin/sleep")
                .arg("60")
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        assert!(process.try_wait().unwrap().is_none());
        let sink = OpenOptions::new().write(true).open("/dev/null").unwrap();
        let lifecycle = std::sync::Arc::new(std::sync::Mutex::new(
            openfortivpn_manager_core::lifecycle::EngineLifecycle::default(),
        ));
        let stdout = process.lock().unwrap().stdout.take().unwrap();
        let reader = relay_engine_output(stdout, sink.as_raw_fd(), lifecycle).unwrap();
        stop_unregistered_child(&process);
        assert!(process.try_wait().unwrap().is_some());
        assert!(openfortivpn_manager_core::supervisor::drain_streams(
            vec![reader],
            Duration::from_secs(1),
        ));
    }
    #[test]
    fn upgrade_refuses_nested_owner_records_and_corrupt_directory_links() {
        let dir = tempfile::tempdir().unwrap();
        let records = dir.path().join("instances").join("501");
        fs::create_dir_all(&records).unwrap();
        assert!(refuse_records(dir.path(), 2).is_ok());
        fs::write(records.join("pre-spawn.launch"), b"synthetic").unwrap();
        assert!(refuse_records(dir.path(), 2).is_err());
        fs::remove_file(records.join("pre-spawn.launch")).unwrap();
        fs::write(records.join("live.instance"), b"synthetic").unwrap();
        assert!(refuse_records(dir.path(), 2).is_err());
        fs::remove_file(records.join("live.instance")).unwrap();
        std::os::unix::fs::symlink("/dev/null", records.join("unexpected")).unwrap();
        assert!(refuse_records(dir.path(), 2).is_err());
    }
    #[test]
    fn helper_observes_cleanup_before_releasing_its_network_authority() {
        use std::os::fd::AsRawFd;
        for (wire, expected) in [
            ("{\"protocolVersion\":2,\"seq\":1,\"event\":\"tunnel_up\"}\n{\"protocolVersion\":2,\"seq\":2,\"event\":\"cleanup_result\",\"success\":true}\n", true),
            ("{\"protocolVersion\":2,\"seq\":1,\"event\":\"tunnel_up\"}\n", false),
            ("{\"protocolVersion\":2,\"seq\":1,\"event\":\"cleanup_result\",\"success\":false}\n", false),
        ] {
            let (read, mut write) = UnixStream::pair().unwrap();
            let sink = OpenOptions::new().write(true).open("/dev/null").unwrap();
            let lifecycle = std::sync::Arc::new(std::sync::Mutex::new(openfortivpn_manager_core::lifecycle::EngineLifecycle::default()));
            let worker = relay_engine_output(read, sink.as_raw_fd(), lifecycle.clone()).unwrap();
            write.write_all(wire.as_bytes()).unwrap();
            drop(write);
            let complete = openfortivpn_manager_core::supervisor::drain_streams(vec![worker], Duration::from_secs(1));
            assert_eq!(lifecycle.lock().unwrap().reaped(complete, false), expected);
        }
    }
    #[test]
    fn control_mode_accepts_only_canonical_attempt_and_private_pipe() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        assert!(validate_manager_attempt("00000000-0000-4000-8000-000000000001").is_ok());
        for value in [
            "",
            "../../engine",
            "00000000-0000-4000-8000-00000000000G",
            "00000000-0000-4000-8000-00000000000A",
            "00000000-0000-4000-8000-000000000001\n",
        ] {
            assert!(validate_manager_attempt(value).is_err());
        }
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        assert!(validate_control_pipe(read.as_raw_fd()).is_ok());
        let (socket, _peer) = UnixStream::pair().unwrap();
        assert!(validate_control_pipe(socket.as_raw_fd()).is_err());
        let file = File::open("/dev/null").unwrap();
        assert!(validate_control_pipe(file.as_raw_fd()).is_err());
    }

    fn process_identity(pid: i32, parent_pid: i32, start: u64, inode: u64) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            parent_pid,
            process_group: if parent_pid == 1 { pid } else { parent_pid },
            effective_uid: 0,
            start_primary: start,
            start_secondary: 0,
            executable_device: 7,
            executable_inode: inode,
        }
    }

    fn synthetic_record(directory: &Path, id: &str, group: i32) -> PathBuf {
        let mut supervisor = process_identity(group, 1, 100, 200);
        supervisor.process_group = group;
        let mut engine = process_identity(group + 1, group, 101, 201);
        engine.process_group = group;
        let record = InstanceRecord {
            instance_id: id.repeat(INSTANCE_IDENTIFIER_BYTES),
            control_token: "cd".repeat(CONTROL_TOKEN_BYTES),
            owner_uid: 501,
            supervisor,
            engine,
        };
        let path = directory.join(format!("{}.instance", record.instance_id));
        openfortivpn_manager_core::atomic_file::write_private(
            &path,
            serialize_instance_record(&record).as_bytes(),
        )
        .unwrap();
        path
    }

    #[test]
    fn failed_subordinate_sync_keeps_global_authority_for_retry() {
        use openfortivpn_manager_core::network_authority::{
            self as authority, ExclusiveLease, Owner,
        };
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let lease = ExclusiveLease::acquire(
            directory.path(),
            Owner {
                attempt_id: "synthetic".into(),
                manager: "helper".into(),
                uid: 501,
                process_group: 1234,
                pre_spawn_gated: false,
            },
        )
        .unwrap();
        let path = synthetic_record(directory.path(), "ab", 1234);
        assert!(cleanup_instance_record(&path, |_| Err("injected parent fsync".into())).is_err());
        drop(lease);
        assert!(authority::inspect(directory.path()).unwrap().is_some());
        assert!(authority::maintenance_guard(directory.path()).is_err());
        recover_instance_records(directory.path(), 501, Some(1234), |_| Ok(true)).unwrap();
        authority::acknowledge(directory.path(), "synthetic", 501, || Ok(true)).unwrap();
        assert!(authority::maintenance_guard(directory.path()).is_ok());
    }

    #[test]
    fn orphan_recovery_prechecks_all_groups_and_records_before_deleting_anything() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let first = synthetic_record(directory.path(), "ab", 1200);
        let second = synthetic_record(directory.path(), "ef", 1300);
        assert!(
            recover_instance_records(directory.path(), 501, None, |group| Ok(group != 1300))
                .is_err()
        );
        assert!(first.exists() && second.exists());
        openfortivpn_manager_core::atomic_file::write_private(&second, b"corrupt").unwrap();
        assert!(recover_instance_records(directory.path(), 501, None, |_| Ok(true)).is_err());
        assert!(first.exists());
        fs::remove_file(&second).unwrap();
        recover_instance_records(directory.path(), 501, None, |_| Ok(true)).unwrap();
        assert!(!first.exists());
    }

    #[test]
    fn accepts_only_manager_generated_fields() {
        let config = "host = vpn.example.test\nport = 443\nusername = user\npassword = secret\nset-routes = 1\nset-dns = 0\npppd-use-peerdns = 0\nhalf-internet-routes = 1\n";
        assert!(validate_config_contents(config).is_ok());
    }

    #[test]
    fn gateway_dns_accepts_only_a_numeric_resolver() {
        for dns in ["223.5.5.5", "114.114.114.114", "127.0.0.1"] {
            assert!(validate_config_contents(&format!(
                "host = vpn.example.test\nport = 443\ngateway-dns = {dns}\n"
            ))
            .is_ok());
        }
        for dns in ["", "0.0.0.0", "224.0.0.1", "dns.test", "1.1.1.1:53", "::1"] {
            assert!(validate_config_contents(&format!(
                "host = vpn.example.test\nport = 443\ngateway-dns = {dns}\n"
            ))
            .is_err());
        }
    }

    #[test]
    fn rejects_root_extension_directives() {
        for directive in [
            "pppd-plugin = /tmp/evil.so",
            "pppd-call = attacker",
            "ca-file = /tmp/controlled",
        ] {
            let config = format!("host = vpn.example.test\nport = 443\n{directive}\n");
            assert!(validate_config_contents(&config).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_and_invalid_values() {
        assert!(validate_config_contents("host = one\nhost = two\nport = 443\n").is_err());
        assert!(validate_config_contents("host = one\nport = 0\n").is_err());
        assert!(validate_config_contents("host = one\nport = 443\nset-dns = yes\n").is_err());
    }

    #[test]
    fn instance_record_round_trip_binds_owner_processes_and_secret() {
        let record = InstanceRecord {
            instance_id: "ab".repeat(INSTANCE_IDENTIFIER_BYTES),
            control_token: "cd".repeat(CONTROL_TOKEN_BYTES),
            owner_uid: 501,
            supervisor: process_identity(1200, 1, 100, 200),
            engine: process_identity(1201, 1200, 101, 201),
        };
        let parsed = parse_instance_record(&serialize_instance_record(&record)).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn process_identity_detects_pid_reuse_and_executable_replacement() {
        let expected = process_identity(1200, 1, 100, 200);
        let mut reused = expected.clone();
        reused.start_primary += 1;
        assert!(!process_matches_record(&expected, &reused));
        let mut replaced = expected.clone();
        replaced.executable_inode += 1;
        assert!(!process_matches_record(&expected, &replaced));
    }

    #[test]
    fn control_tokens_require_an_exact_constant_time_match() {
        assert!(constant_time_equal(b"stop secret\n", b"stop secret\n"));
        assert!(!constant_time_equal(b"stop secret\n", b"stop other\n"));
        assert!(!constant_time_equal(b"stop secret\n", b"stop secret"));
    }

    #[test]
    fn sudo_may_lead_the_group_while_helper_owns_engine() {
        let mut supervisor = process_identity(1201, 1200, 100, 200);
        supervisor.process_group = 1200;
        let mut engine = process_identity(1202, 1201, 101, 201);
        engine.process_group = 1200;
        let record = InstanceRecord {
            instance_id: "ab".repeat(INSTANCE_IDENTIFIER_BYTES),
            control_token: "cd".repeat(CONTROL_TOKEN_BYTES),
            owner_uid: 501,
            supervisor,
            engine,
        };
        assert!(validate_instance_relationships(&record).is_ok());
    }
}
