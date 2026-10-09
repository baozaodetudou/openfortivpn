use openfortivpn_manager_headless::{model::VpnProfile, storage::Storage};
use std::path::Path;
use std::process::{Command, Stdio};

fn storage(root: &Path) -> Storage {
    Storage::new(root.join("etc"), root.join("state"), root.join("run"))
}

fn profile(id: String) -> VpnProfile {
    serde_json::from_value(
        serde_json::json!({"id":id,"name":"Test","host":"vpn.example.com","username":"synthetic"}),
    )
    .unwrap()
}

#[test]
#[ignore = "subprocess worker invoked by parent test"]
fn process_worker() {
    let root = std::env::var_os("VPN_TEST_STORE_ROOT").unwrap();
    let index: usize = std::env::var("VPN_TEST_WORKER_INDEX")
        .unwrap()
        .parse()
        .unwrap();
    let storage = storage(Path::new(&root));
    for number in 0..25 {
        storage
            .save_profile(
                profile(format!("{index}-{number}")),
                Some("synthetic-secret".into()),
                true,
            )
            .unwrap();
    }
}

#[test]
fn four_processes_preserve_all_one_hundred_successful_writes() {
    let root = tempfile::tempdir().unwrap();
    storage(root.path()).ensure_layout().unwrap();
    let mut children = Vec::new();
    for index in 0..4 {
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "process_worker"])
                .env("VPN_TEST_STORE_ROOT", root.path())
                .env("VPN_TEST_WORKER_INDEX", index.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    for child in children {
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "worker failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let storage = storage(root.path());
    assert_eq!(storage.load_profiles().unwrap().len(), 100);
    assert_eq!(storage.load_secrets().unwrap().len(), 100);
}

#[test]
fn competing_expected_revisions_never_overwrite_a_successful_commit() {
    let root = tempfile::tempdir().unwrap();
    let storage = storage(root.path());
    let first = storage
        .save_profile_expected(
            profile("shared".into()),
            Some("first-secret".into()),
            true,
            Some(0),
        )
        .unwrap();
    assert_eq!(first.profile.revision, 1);
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            storage.save_profile_expected(
                profile("shared".into()),
                Some("second-secret".into()),
                true,
                Some(1),
            )
        });
        let two = scope.spawn(|| {
            barrier.wait();
            storage.save_profile_expected(
                profile("shared".into()),
                Some("third-secret".into()),
                true,
                Some(1),
            )
        });
        [one.join().unwrap(), two.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(
        storage.load_profiles().unwrap()["shared"].revision,
        winner.profile.revision
    );
    assert_eq!(winner.profile.revision, 2);
    assert!(storage.delete_profile_expected("shared", Some(1)).is_err());
    assert!(storage.delete_profile_expected("shared", Some(2)).unwrap());
}
