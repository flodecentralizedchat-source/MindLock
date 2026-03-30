/// rules.rs — The MindLock access policy engine (Phase 1 + 2).
///
/// Every .mindlock file embeds an `AccessPolicy` in its header.
/// The `RulesEngine` evaluates an `AccessContext` against the policy
/// and returns the appropriate `AccessDecision`.
///
/// Decision tree:
///   Wiped?       → Deny(FileWiped)
///   Open limit?  → Deny(OpenLimitReached) if over
///   Expired?     → Deny(FileExpired) if past expiry date
///   Time window? → Deny(TimeWindowViolation) if outside window
///   Device trust → Deny(UntrustedDevice) if unknown and policy enforced
///   → Grant

use chrono::{DateTime, NaiveTime, Utc, Datelike};
use serde::{Deserialize, Serialize};
use crate::crypto::DeviceFingerprint;

// ── Policy ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessPolicy {
    /// Maximum number of times this file may be opened (None = unlimited)
    pub max_opens: Option<u32>,

    /// Number of times the file has been opened (incremented on each unlock)
    pub open_count: u32,

    /// Hard expiry — file cannot be opened after this date
    pub expires_at: Option<DateTime<Utc>>,

    /// Allow opens only within a daily time window (UTC)
    pub time_window: Option<TimeWindow>,

    /// If true, only devices listed in `header.trusted_devices` can open
    pub enforce_device_trust: bool,

    /// Maximum failed unlock attempts before self-destruct triggers
    pub max_failed_attempts: Option<u32>,

    /// Number of failed attempts so far
    pub failed_attempts: u32,

    /// On suspicious access: trigger decoy instead of denying outright
    pub decoy_on_fail: bool,

    /// Require behavior biometrics check (Phase 3)
    pub require_behavior_auth: bool,

    /// Require token-gate check (Phase 4)
    pub require_token_gate: bool,

    /// Sensitivity classification
    pub sensitivity: SensitivityLevel,
}

impl AccessPolicy {
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }

    /// Record a successful open — increments counter.
    pub fn record_open(&mut self) {
        self.open_count += 1;
        self.failed_attempts = 0; // reset on success
    }

    /// Record a failed attempt — increments counter.
    /// Returns true if self-destruct threshold has been crossed.
    pub fn record_failed(&mut self) -> bool {
        self.failed_attempts += 1;
        if let Some(max) = self.max_failed_attempts {
            self.failed_attempts >= max
        } else {
            false
        }
    }
}

// ── Time window ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start of allowed period each day (UTC, e.g. 09:00)
    pub start: NaiveTime,
    /// End of allowed period each day (UTC, e.g. 17:00)
    pub end: NaiveTime,
    /// Allowed weekdays (Mon=0 … Sun=6). Empty = all days allowed.
    pub allowed_weekdays: Vec<u8>,
}

impl TimeWindow {
    pub fn new(start: NaiveTime, end: NaiveTime) -> Self {
        TimeWindow { start, end, allowed_weekdays: vec![] }
    }

    pub fn with_weekdays(mut self, days: Vec<u8>) -> Self {
        self.allowed_weekdays = days;
        self
    }

    pub fn is_within(&self, now: DateTime<Utc>) -> bool {
        let time = now.time();
        let in_window = if self.start <= self.end {
            time >= self.start && time <= self.end
        } else {
            // crosses midnight
            time >= self.start || time <= self.end
        };
        if !in_window { return false; }
        if self.allowed_weekdays.is_empty() { return true; }
        let weekday = now.weekday().num_days_from_monday() as u8;
        self.allowed_weekdays.contains(&weekday)
    }
}

// ── Sensitivity ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum SensitivityLevel {
    #[default]
    Public,
    Internal,
    Confidential,
    TopSecret,
}

impl SensitivityLevel {
    /// Auto-select a base policy from sensitivity tier.
    pub fn default_policy(&self) -> AccessPolicy {
        match self {
            Self::Public => AccessPolicy::default(),
            Self::Internal => PolicyBuilder::default()
                .enforce_device_trust(true)
                .build(),
            Self::Confidential => PolicyBuilder::default()
                .enforce_device_trust(true)
                .max_failed_attempts(5)
                .decoy_on_fail(true)
                .require_behavior_auth(true)
                .build(),
            Self::TopSecret => PolicyBuilder::default()
                .enforce_device_trust(true)
                .max_failed_attempts(3)
                .decoy_on_fail(true)
                .require_behavior_auth(true)
                .require_token_gate(true)
                .build(),
        }
    }
}

// ── Access context ────────────────────────────────────────────────────────────

/// Everything known about the entity attempting to open the file.
#[derive(Debug, Clone)]
pub struct AccessContext {
    pub now: DateTime<Utc>,
    pub device: DeviceFingerprint,
    pub trusted_devices: Vec<DeviceFingerprint>,
    pub behavior_ok: Option<bool>,   // None = not checked yet
    pub token_gate_ok: Option<bool>, // None = not checked yet
}

impl AccessContext {
    pub fn new(trusted_devices: Vec<DeviceFingerprint>) -> Self {
        AccessContext {
            now: Utc::now(),
            device: DeviceFingerprint::current(),
            trusted_devices,
            behavior_ok: None,
            token_gate_ok: None,
        }
    }
}

// ── Decision ──────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum AccessDecision {
    Grant,
    Decoy,
    Deny(String),
    SelfDestruct,
}

// ── Rules engine ──────────────────────────────────────────────────────────────

pub struct RulesEngine;

impl RulesEngine {
    pub fn evaluate(policy: &AccessPolicy, ctx: &AccessContext) -> AccessDecision {
        // Wiped — terminal
        if policy.open_count == u32::MAX {
            return AccessDecision::Deny("File is wiped".into());
        }

        // Open limit
        if let Some(max) = policy.max_opens {
            if policy.open_count >= max {
                return Self::deny_or_decoy(policy, "Open limit reached");
            }
        }

        // Expiry
        if let Some(expiry) = &policy.expires_at {
            if ctx.now > *expiry {
                return Self::deny_or_decoy(policy, "File has expired");
            }
        }

        // Time window
        if let Some(window) = &policy.time_window {
            if !window.is_within(ctx.now) {
                return Self::deny_or_decoy(policy, "Outside allowed time window");
            }
        }

        // Device trust
        if policy.enforce_device_trust && !ctx.trusted_devices.is_empty() {
            if !ctx.trusted_devices.contains(&ctx.device) {
                return Self::deny_or_decoy(policy, "Device not trusted");
            }
        }

        // Behavior auth (Phase 3)
        if policy.require_behavior_auth {
            match ctx.behavior_ok {
                None => return AccessDecision::Deny("Behavior check not performed".into()),
                Some(false) => return Self::deny_or_decoy(policy, "Behavioral anomaly"),
                Some(true) => {}
            }
        }

        // Token gate (Phase 4)
        if policy.require_token_gate {
            match ctx.token_gate_ok {
                None => return AccessDecision::Deny("Token gate not verified".into()),
                Some(false) => return AccessDecision::Deny("Token gate failed".into()),
                Some(true) => {}
            }
        }

        AccessDecision::Grant
    }

    fn deny_or_decoy(policy: &AccessPolicy, reason: &str) -> AccessDecision {
        if policy.decoy_on_fail {
            AccessDecision::Decoy
        } else {
            AccessDecision::Deny(reason.into())
        }
    }

    /// Check if failed attempts cross the self-destruct threshold.
    pub fn should_self_destruct(policy: &AccessPolicy) -> bool {
        if let Some(max) = policy.max_failed_attempts {
            policy.failed_attempts >= max
        } else {
            false
        }
    }
}

// ── Policy builder ────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct PolicyBuilder {
    inner: AccessPolicy,
}

impl PolicyBuilder {
    pub fn max_opens(mut self, n: u32) -> Self {
        self.inner.max_opens = Some(n);
        self
    }
    pub fn expires_at(mut self, dt: DateTime<Utc>) -> Self {
        self.inner.expires_at = Some(dt);
        self
    }
    pub fn time_window(mut self, w: TimeWindow) -> Self {
        self.inner.time_window = Some(w);
        self
    }
    pub fn enforce_device_trust(mut self, v: bool) -> Self {
        self.inner.enforce_device_trust = v;
        self
    }
    pub fn max_failed_attempts(mut self, n: u32) -> Self {
        self.inner.max_failed_attempts = Some(n);
        self
    }
    pub fn decoy_on_fail(mut self, v: bool) -> Self {
        self.inner.decoy_on_fail = v;
        self
    }
    pub fn require_behavior_auth(mut self, v: bool) -> Self {
        self.inner.require_behavior_auth = v;
        self
    }
    pub fn require_token_gate(mut self, v: bool) -> Self {
        self.inner.require_token_gate = v;
        self
    }
    pub fn sensitivity(mut self, s: SensitivityLevel) -> Self {
        self.inner.sensitivity = s;
        self
    }
    pub fn build(self) -> AccessPolicy {
        self.inner
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn ctx() -> AccessContext {
        AccessContext::new(vec![])
    }

    #[test]
    fn test_grant_default_policy() {
        let policy = AccessPolicy::default();
        assert_eq!(RulesEngine::evaluate(&policy, &ctx()), AccessDecision::Grant);
    }

    #[test]
    fn test_open_limit_deny() {
        let mut policy = PolicyBuilder::default().max_opens(3).build();
        policy.open_count = 3;
        assert_eq!(
            RulesEngine::evaluate(&policy, &ctx()),
            AccessDecision::Deny("Open limit reached".into())
        );
    }

    #[test]
    fn test_open_limit_decoy() {
        let mut policy = PolicyBuilder::default().max_opens(2).decoy_on_fail(true).build();
        policy.open_count = 2;
        assert_eq!(RulesEngine::evaluate(&policy, &ctx()), AccessDecision::Decoy);
    }

    #[test]
    fn test_expiry() {
        let past = Utc::now() - Duration::days(1);
        let policy = PolicyBuilder::default().expires_at(past).build();
        assert_eq!(
            RulesEngine::evaluate(&policy, &ctx()),
            AccessDecision::Deny("File has expired".into())
        );
    }

    #[test]
    fn test_device_trust_deny() {
        let other = DeviceFingerprint::from_system_bytes(b"other-machine");
        let policy = PolicyBuilder::default().enforce_device_trust(true).build();
        let ctx = AccessContext {
            now: Utc::now(),
            device: DeviceFingerprint::from_system_bytes(b"my-machine"),
            trusted_devices: vec![other],
            behavior_ok: None,
            token_gate_ok: None,
        };
        assert_eq!(
            RulesEngine::evaluate(&policy, &ctx),
            AccessDecision::Deny("Device not trusted".into())
        );
    }

    #[test]
    fn test_self_destruct_threshold() {
        let mut policy = PolicyBuilder::default().max_failed_attempts(3).build();
        policy.failed_attempts = 3;
        assert!(RulesEngine::should_self_destruct(&policy));
    }
}
