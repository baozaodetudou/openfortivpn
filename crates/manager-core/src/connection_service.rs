//! Shared connect admission. Adapters take their runtime lock, build these
//! facts, and reserve immediately under that same lock after `Reserve`.
//! Process handles, credentials, generation counters and cleanup stay owned
//! by their platform adapters.
use crate::{ControlError, ErrorCode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartOrigin {
    User,
    Startup,
    Automatic,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipState {
    /// An admitted, published connection intent. It may still be starting its
    /// child, but has a stable addressable instance and no stop/recovery flag.
    Healthy,
    /// A credential/start worker reserves the profile before publishing a view.
    StartingReservation,
    Stopping,
    RecoveryRequired,
}
#[derive(Clone, Copy, Debug)]
pub struct ConnectionOwner<'a> {
    pub profile_id: &'a str,
    pub instance_id: Option<&'a str>,
    pub state: OwnershipState,
}
pub struct ConnectFacts<'a> {
    pub profile_id: &'a str,
    pub profile_exists: bool,
    pub shutting_down: bool,
    pub repository_recovery_required: bool,
    pub repository_restoring: bool,
    pub profile_mutating: bool,
    /// An orphaned/unknown process or resource ledger is a machine-wide gate.
    pub orphaned_recovery: bool,
    pub owners: &'a [ConnectionOwner<'a>],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectDecision<'a> {
    Reserve,
    Reuse(&'a str),
}
pub fn admit<'a>(
    facts: &ConnectFacts<'a>,
    origin: StartOrigin,
) -> Result<ConnectDecision<'a>, ControlError> {
    let blocked = |code, message| Err(ControlError::new(code, message));
    if facts.profile_id.is_empty()
        || facts.profile_id.len() > 128
        || facts.profile_id.chars().any(char::is_control)
    {
        return blocked(
            ErrorCode::InvalidInput,
            "invalid connection profile identity",
        );
    }
    if facts.shutting_down {
        return blocked(ErrorCode::ShuttingDown, "manager is shutting down");
    }
    if facts.repository_recovery_required {
        return blocked(
            ErrorCode::RecoveryRequired,
            "profile repository requires recovery",
        );
    }
    if facts.repository_restoring || facts.profile_mutating {
        return blocked(
            ErrorCode::ProfileBusy,
            "profile repository is being modified",
        );
    }
    if !facts.profile_exists {
        return blocked(ErrorCode::ProfileNotFound, "profile was not found");
    }
    if facts.orphaned_recovery
        || facts
            .owners
            .iter()
            .any(|owner| owner.state == OwnershipState::RecoveryRequired)
    {
        return blocked(
            ErrorCode::RecoveryRequired,
            "process or network cleanup requires recovery",
        );
    }
    let mut current = facts
        .owners
        .iter()
        .filter(|owner| owner.profile_id == facts.profile_id);
    let existing = current.next();
    if current.next().is_some() {
        return blocked(
            ErrorCode::RecoveryRequired,
            "profile has conflicting connection ownership",
        );
    }
    if existing.is_some_and(|owner| owner.state == OwnershipState::Stopping) {
        return blocked(
            ErrorCode::ProfileBusy,
            "profile is stopping; wait for process exit and cleanup",
        );
    }
    if facts
        .owners
        .iter()
        .any(|owner| owner.profile_id != facts.profile_id)
    {
        return blocked(
            ErrorCode::NetworkConflict,
            "another profile owns the network; disconnect it first",
        );
    }
    if let Some(owner) = existing {
        if owner.state == OwnershipState::Healthy && origin == StartOrigin::User {
            if let Some(id) = owner.instance_id.filter(|id| !id.is_empty()) {
                return Ok(ConnectDecision::Reuse(id));
            }
        }
        return blocked(
            ErrorCode::ProfileBusy,
            "profile already has a connection or start reservation",
        );
    }
    Ok(ConnectDecision::Reserve)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn facts<'a>(owners: &'a [ConnectionOwner<'a>]) -> ConnectFacts<'a> {
        ConnectFacts {
            profile_id: "one",
            profile_exists: true,
            shutting_down: false,
            repository_recovery_required: false,
            repository_restoring: false,
            profile_mutating: false,
            orphaned_recovery: false,
            owners,
        }
    }
    fn owner(state: OwnershipState) -> ConnectionOwner<'static> {
        ConnectionOwner {
            profile_id: "one",
            instance_id: Some("attempt-one"),
            state,
        }
    }
    #[test]
    fn stopping_or_recovery_is_never_a_successful_duplicate_connect() {
        for (state, code) in [
            (OwnershipState::Stopping, ErrorCode::ProfileBusy),
            (
                OwnershipState::RecoveryRequired,
                ErrorCode::RecoveryRequired,
            ),
        ] {
            for origin in [
                StartOrigin::User,
                StartOrigin::Startup,
                StartOrigin::Automatic,
            ] {
                assert_eq!(
                    admit(&facts(&[owner(state)]), origin).unwrap_err().code,
                    code
                );
            }
        }
    }
    #[test]
    fn only_a_healthy_published_user_intent_can_be_reused() {
        let owners = [owner(OwnershipState::Healthy)];
        assert_eq!(
            admit(&facts(&owners), StartOrigin::User).unwrap(),
            ConnectDecision::Reuse("attempt-one")
        );
        for origin in [StartOrigin::Startup, StartOrigin::Automatic] {
            assert_eq!(
                admit(&facts(&owners), origin).unwrap_err().code,
                ErrorCode::ProfileBusy
            );
        }
        let mut invalid = owners;
        invalid[0].instance_id = None;
        assert_eq!(
            admit(&facts(&invalid), StartOrigin::User).unwrap_err().code,
            ErrorCode::ProfileBusy
        );
    }
    #[test]
    fn pending_start_and_other_network_owners_block_before_reservation() {
        assert_eq!(
            admit(
                &facts(&[owner(OwnershipState::StartingReservation)]),
                StartOrigin::User
            )
            .unwrap_err()
            .code,
            ErrorCode::ProfileBusy
        );
        for state in [
            OwnershipState::Healthy,
            OwnershipState::StartingReservation,
            OwnershipState::Stopping,
            OwnershipState::RecoveryRequired,
        ] {
            let other = ConnectionOwner {
                profile_id: "other",
                ..owner(state)
            };
            let expected = if state == OwnershipState::RecoveryRequired {
                ErrorCode::RecoveryRequired
            } else {
                ErrorCode::NetworkConflict
            };
            assert_eq!(
                admit(&facts(&[other]), StartOrigin::User).unwrap_err().code,
                expected
            );
        }
        assert_eq!(
            admit(&facts(&[]), StartOrigin::User).unwrap(),
            ConnectDecision::Reserve
        );
    }
    #[test]
    fn shutdown_repository_mutation_and_orphan_gates_apply_even_to_healthy_reuse() {
        let owners = [owner(OwnershipState::Healthy)];
        for gate in [
            "shutdown",
            "repository",
            "restore",
            "mutation",
            "orphan",
            "missing",
        ] {
            let mut facts = facts(&owners);
            let code = match gate {
                "shutdown" => {
                    facts.shutting_down = true;
                    ErrorCode::ShuttingDown
                }
                "repository" => {
                    facts.repository_recovery_required = true;
                    ErrorCode::RecoveryRequired
                }
                "restore" => {
                    facts.repository_restoring = true;
                    ErrorCode::ProfileBusy
                }
                "mutation" => {
                    facts.profile_mutating = true;
                    ErrorCode::ProfileBusy
                }
                "orphan" => {
                    facts.orphaned_recovery = true;
                    ErrorCode::RecoveryRequired
                }
                _ => {
                    facts.profile_exists = false;
                    ErrorCode::ProfileNotFound
                }
            };
            assert_eq!(admit(&facts, StartOrigin::User).unwrap_err().code, code);
        }
    }
    #[test]
    fn a_recovery_owner_or_duplicate_current_owner_cannot_hide_behind_healthy_reuse() {
        let owners = [
            owner(OwnershipState::Healthy),
            ConnectionOwner {
                instance_id: Some("older-attempt"),
                ..owner(OwnershipState::RecoveryRequired)
            },
        ];
        assert_eq!(
            admit(&facts(&owners), StartOrigin::User).unwrap_err().code,
            ErrorCode::RecoveryRequired
        );
        let owners = [
            owner(OwnershipState::Healthy),
            owner(OwnershipState::Healthy),
        ];
        assert_eq!(
            admit(&facts(&owners), StartOrigin::User).unwrap_err().code,
            ErrorCode::RecoveryRequired
        );
    }
}
