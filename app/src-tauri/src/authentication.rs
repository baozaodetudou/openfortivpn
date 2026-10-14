//! Local IPC and remote HTTP share the same attempt-bound response path.
use super::*;
use openfortivpn_manager_core::control::{AuthResponse, Challenge, Command as InputCommand};
use openfortivpn_manager_http::ApiError;

pub(super) fn experimental_control() -> bool {
    env::var("OPENFORTIVPN_EXPERIMENTAL_CONTROL").as_deref() == Ok("1")
}
fn invalid(message: &str) -> ApiError {
    ApiError::new(
        axum::http::StatusCode::BAD_REQUEST,
        "INVALID_AUTH_RESPONSE",
        message,
        false,
    )
}
pub(super) fn list(store: &mut RuntimeStore) -> Vec<Challenge> {
    store
        .challenges
        .list(now_epoch().saturating_mul(1000))
        .into_iter()
        .filter(|challenge| {
            store
                .instances
                .get(&challenge.attempt_id)
                .is_some_and(|instance| {
                    instance.view.profile_id == challenge.profile_id && active(store, instance)
                })
        })
        .collect()
}
fn active(store: &RuntimeStore, instance: &ManagedInstance) -> bool {
    instance.process_running
        && !instance.user_requested_stop
        && instance.input.is_some()
        && store
            .reconnect_generations
            .get(&instance.view.profile_id)
            .copied()
            .unwrap_or_default()
            == instance.view.profile_generation
}

pub(super) fn fail_control(app: &AppHandle, attempt: &str) {
    if let Ok(mut store) = app.state::<AppState>().store.lock() {
        if let Some(instance) = store.instances.get_mut(attempt) {
            if !instance.process_running {
                return;
            }
            instance.lifecycle.require_recovery();
            instance.reconnect_blocked = true;
            instance.failure_message = Some("私有引擎通道失败，需要确认恢复".into());
            if let Some(input) = &instance.input {
                input.cancel();
            }
        } else {
            return;
        }
    }
    // Stop the exact owned instance. A delayed error must never stop a successor.
    let _ = stop_instance_impl(app.clone(), app.state(), attempt.into(), None);
    let _ = app.emit("vpn-authentication-changed", ());
}
pub(super) fn handle_event(app: &AppHandle, attempt: &str, event: &Value) -> Result<(), String> {
    let send = {
        let state = app.state::<AppState>();
        let mut store = state.store.lock().map_err(|_| "认证状态不可用")?;
        prepare_event(&mut store, attempt, event)?
    };
    if let Some((input, frame)) = send {
        input
            .send(&frame, Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
    }
    let _ = app.emit("vpn-authentication-changed", ());
    Ok(())
}
type PendingWrite = (
    Arc<openfortivpn_manager_core::private_input::PrivateInput>,
    openfortivpn_manager_core::control::SecretFrame,
);
fn prepare_event(
    store: &mut RuntimeStore,
    attempt: &str,
    event: &Value,
) -> Result<Option<PendingWrite>, String> {
    let instance = store.instances.get(attempt).ok_or("过期的认证实例")?;
    if event["attemptId"].as_str() != Some(attempt) || !active(store, instance) {
        return Err("认证实例已变化".into());
    }
    let profile = instance.view.profile_id.clone();
    let generation = instance.view.profile_generation;
    let input = instance.input.clone().ok_or("私有通道不可用")?;
    let request = event["requestId"].as_str().ok_or("缺少请求标识")?;
    Ok(match event["event"].as_str() {
        Some("auth_challenge_closed") => {
            store.challenges.close(&profile, attempt, request);
            None
        }
        Some("auth_challenge") => {
            if event["kind"].as_str() != Some("otp") {
                return Err("不支持的认证挑战".into());
            }
            let now = now_epoch().saturating_mul(1000);
            let timeout = event["timeoutMs"].as_u64().ok_or("缺少认证时限")?;
            let max = event["maxResponseBytes"]
                .as_u64()
                .filter(|n| *n <= 1024)
                .ok_or("无效的认证长度")?;
            store
                .challenges
                .register(
                    Challenge {
                        profile_id: profile,
                        attempt_id: attempt.into(),
                        request_id: request.into(),
                        prompt: event["prompt"].as_str().ok_or("无效的认证提示")?.into(),
                        expires_at_ms: now.saturating_add(timeout),
                        max_response_bytes: max as usize,
                    },
                    generation,
                    now,
                )
                .map_err(|e| e.to_string())?;
            None
        }
        Some("network_plan") => {
            let exclusive = event["exclusiveRequired"].as_bool() == Some(true);
            let available = store.starting_profiles.iter().all(|id| id == &profile)
                && store.stale_processes.is_empty()
                && store.instances.values().all(|i| {
                    i.view.id == attempt || (!i.process_running && !i.lifecycle.cleanup_failed())
                });
            let decision = if exclusive && available {
                "grant"
            } else {
                "deny"
            };
            let frame = openfortivpn_manager_core::control::frame(
                attempt,
                request,
                InputCommand::LeaseDecision,
                decision,
            )
            .map_err(|e| e.to_string())?;
            Some((input, frame))
        }
        _ => return Err("不支持的控制事件".into()),
    })
}
fn prepare_response(
    store: &mut RuntimeStore,
    response: &AuthResponse,
) -> Result<PendingWrite, ApiError> {
    let instance = store
        .instances
        .get(&response.attempt_id)
        .ok_or_else(|| invalid("认证实例已过期"))?;
    if instance.view.profile_id != response.profile_id || !active(store, instance) {
        return Err(invalid("认证实例已停止或发生变化"));
    }
    let generation = instance.view.profile_generation;
    let input = instance
        .input
        .clone()
        .ok_or_else(|| invalid("私有认证通道不可用"))?;
    let frame = store
        .challenges
        .respond(
            &response.profile_id,
            &response.attempt_id,
            generation,
            &response.request_id,
            now_epoch().saturating_mul(1000),
            &response.response,
        )
        .map_err(|_| invalid("验证码过期、已提交或不符合长度要求"))?;
    Ok((input, frame))
}
pub(super) fn respond(app: AppHandle, response: AuthResponse) -> Result<(), ApiError> {
    let (input, frame) = {
        let state = app.state::<AppState>();
        let mut store = state
            .store
            .lock()
            .map_err(|_| ApiError::from_message("认证状态不可用".into()))?;
        prepare_response(&mut store, &response)?
    };
    if input.send(&frame, Duration::from_secs(5)).is_err() {
        fail_control(&app, &response.attempt_id);
        return Err(ApiError::from_message("验证码发送失败，连接已停止".into()));
    }
    let _ = app.emit("vpn-authentication-changed", ());
    Ok(())
}
#[tauri::command]
pub(super) fn authentication_challenges(
    state: State<'_, AppState>,
) -> Result<Vec<Challenge>, String> {
    state
        .store
        .lock()
        .map(|mut store| list(&mut store))
        .map_err(|_| "认证状态不可用".into())
}
#[tauri::command]
pub(super) async fn respond_to_authentication(
    app: AppHandle,
    response: AuthResponse,
) -> Result<(), String> {
    run_profile_command(app, response.profile_id.clone(), move |app| {
        respond(app, response)
    })
    .await
    .map_err(|e| e.message)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    const ATTEMPT: &str = "00000000-0000-4000-8000-000000000001";
    const REQUEST: &str = "0123456789abcdef0123456789abcdef";
    struct Fixture(RuntimeStore);
    impl Fixture {
        fn new() -> Self {
            let mut child = Command::new("/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let input = Arc::new(
                openfortivpn_manager_core::private_input::PrivateInput::new(
                    child.stdin.take().unwrap(),
                )
                .unwrap(),
            );
            let mut store = RuntimeStore::default();
            store.reconnect_generations.insert("one".into(), 7);
            store.instances.insert(
                ATTEMPT.into(),
                ManagedInstance {
                    source_profile: serde_json::from_value(serde_json::json!({ "id": "one", "name": "Synthetic", "host": "vpn.example.test" })).unwrap(),
                    view: InstanceView {
                        id: ATTEMPT.into(),
                        profile_id: "one".into(),
                        profile_generation: 7,
                        attempt_sequence: 1,
                        profile_name: "Synthetic".into(),
                        adapter_name: "synthetic".into(),
                        status: "connecting".into(),
                        message: String::new(),
                        pid: child.id(),
                        started_at: now_epoch(),
                        ended_at: None,
                        exit_code: None,
                        revision: 1,
                    },
                    child: openfortivpn_manager_core::supervisor::OwnedProcess::new(child),
                    input: Some(input),
                    process_running: true,
                    lifecycle: openfortivpn_manager_core::lifecycle::EngineLifecycle::for_attempt(
                        ATTEMPT, true,
                    ),
                    user_requested_stop: false,
                    reconnect_blocked: false,
                    failure_message: None,
                },
            );
            Self(store)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for instance in self.0.instances.values_mut() {
                if let Some(input) = instance.input.take() {
                    input.cancel();
                }
                let mut child = instance.child.lock().unwrap();
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    fn challenge() -> Value {
        json!({"event":"auth_challenge","attemptId":ATTEMPT,"requestId":REQUEST,"kind":"otp", "prompt":"Synthetic prompt", "timeoutMs":120000,"maxResponseBytes":64})
    }
    fn response() -> AuthResponse {
        AuthResponse {
            profile_id: "one".into(),
            attempt_id: ATTEMPT.into(),
            request_id: REQUEST.into(),
            response: "synthetic-otp".into(),
        }
    }
    #[test]
    fn desktop_otp_uses_owned_pipe_once_and_does_not_change_credentials() {
        let mut fixture = Fixture::new();
        fixture
            .0
            .secrets
            .insert("one".into(), "synthetic-password".into());
        assert!(prepare_event(&mut fixture.0, ATTEMPT, &challenge())
            .unwrap()
            .is_none());
        assert_eq!(list(&mut fixture.0).len(), 1);
        let mut wrong = response();
        wrong.profile_id = "other".into();
        assert!(prepare_response(&mut fixture.0, &wrong).is_err());
        let (input, frame) = prepare_response(&mut fixture.0, &response()).unwrap();
        input.send(&frame, Duration::from_secs(1)).unwrap();
        let mut actual = vec![0; frame.as_bytes().len()];
        fixture.0.instances[ATTEMPT]
            .child
            .lock()
            .unwrap()
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut actual)
            .unwrap();
        assert_eq!(actual, frame.as_bytes());
        assert!(prepare_response(&mut fixture.0, &response()).is_err());
        assert!(list(&mut fixture.0).is_empty());
        assert_eq!(fixture.0.secrets["one"], "synthetic-password");
        assert!(prepare_event(&mut fixture.0, ATTEMPT, &challenge()).is_err());
    }
    #[test]
    fn stopped_or_obsolete_desktop_challenge_cannot_write_and_lease_requires_exclusivity() {
        let mut fixture = Fixture::new();
        prepare_event(&mut fixture.0, ATTEMPT, &challenge()).unwrap();
        fixture.0.reconnect_generations.insert("one".into(), 8);
        assert!(list(&mut fixture.0).is_empty());
        assert!(prepare_response(&mut fixture.0, &response()).is_err());
        fixture.0.reconnect_generations.insert("one".into(), 7);
        fixture
            .0
            .instances
            .get_mut(ATTEMPT)
            .unwrap()
            .user_requested_stop = true;
        assert!(prepare_response(&mut fixture.0, &response()).is_err());
        fixture
            .0
            .instances
            .get_mut(ATTEMPT)
            .unwrap()
            .user_requested_stop = false;
        let mut plan = json!({"event":"network_plan","attemptId":ATTEMPT,"requestId":REQUEST,"exclusiveRequired":true});
        let (_, grant) = prepare_event(&mut fixture.0, ATTEMPT, &plan)
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(grant.as_bytes())
            .unwrap()
            .ends_with(" Z3JhbnQ=\n"));
        fixture.0.starting_profiles.insert("other".into());
        let (_, deny) = prepare_event(&mut fixture.0, ATTEMPT, &plan)
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(deny.as_bytes())
            .unwrap()
            .ends_with(" ZGVueQ==\n"));
        plan["attemptId"] = json!("old-attempt");
        assert!(prepare_event(&mut fixture.0, ATTEMPT, &plan).is_err());
    }
}
