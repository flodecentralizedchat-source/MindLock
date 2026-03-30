/// behavior.rs — Behavioral biometrics engine (Phase 3 + 4).
///
/// Phase 3: Rule-based threshold anomaly detection.
///   • Collects keystroke inter-key timing intervals (dwell + flight times)
///   • Builds a per-user baseline (mean + std-dev per position)
///   • Flags if live sample deviates > N standard deviations
///
/// Phase 4: Lightweight on-device ML.
///   • DTW (Dynamic Time Warping) distance between sample and baseline
///   • z-score normalization
///   • Confidence score 0.0–1.0 → accept/reject threshold configurable

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use crate::{MindLockError, Result};

// ── Sample types ──────────────────────────────────────────────────────────────

/// A single keystroke event during the unlock password entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEvent {
    /// Milliseconds since unlock prompt appeared
    pub timestamp_ms: u64,
    /// Key pressed (we do NOT store which key — only timing)
    pub event: KeyEventType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyEventType {
    KeyDown,
    KeyUp,
}

/// A full password-entry session: sequence of key events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSample {
    pub events: Vec<KeyEvent>,
}

impl BehaviorSample {
    pub fn new(events: Vec<KeyEvent>) -> Self {
        BehaviorSample { events }
    }

    /// Extract inter-key intervals (flight times between consecutive key-downs).
    pub fn flight_times(&self) -> Vec<f64> {
        let downs: Vec<u64> = self.events.iter()
            .filter(|e| e.event == KeyEventType::KeyDown)
            .map(|e| e.timestamp_ms)
            .collect();
        downs.windows(2)
            .map(|w| (w[1] as f64) - (w[0] as f64))
            .collect()
    }

    /// Extract dwell times (key-down to key-up for each key).
    pub fn dwell_times(&self) -> Vec<f64> {
        let mut result = Vec::new();
        let mut last_down: Option<u64> = None;
        for ev in &self.events {
            match ev.event {
                KeyEventType::KeyDown => last_down = Some(ev.timestamp_ms),
                KeyEventType::KeyUp => {
                    if let Some(down) = last_down.take() {
                        result.push((ev.timestamp_ms as f64) - (down as f64));
                    }
                }
            }
        }
        result
    }

    /// Overall typing speed (ms per key press).
    pub fn typing_speed_ms(&self) -> Option<f64> {
        let flights = self.flight_times();
        if flights.is_empty() { return None; }
        Some(flights.iter().sum::<f64>() / flights.len() as f64)
    }
}

// ── Baseline (enrolled profile) ───────────────────────────────────────────────

/// Statistical baseline built from N enrollment samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    /// Mean flight time per position
    pub flight_means: Vec<f64>,
    /// Std-dev of flight time per position
    pub flight_stds: Vec<f64>,
    /// Mean dwell time per position
    pub dwell_means: Vec<f64>,
    /// Std-dev of dwell time per position
    pub dwell_stds: Vec<f64>,
    /// Overall mean typing speed (ms/key)
    pub speed_mean: f64,
    pub speed_std: f64,
    /// Number of samples used to build baseline
    pub sample_count: usize,
}

impl BehaviorBaseline {
    /// Build a baseline from 3+ enrollment samples.
    pub fn enroll(samples: &[BehaviorSample]) -> Result<Self> {
        if samples.len() < 3 {
            return Err(MindLockError::Other(anyhow::anyhow!(
                "Need at least 3 enrollment samples, got {}", samples.len()
            )));
        }

        let all_flights: Vec<Vec<f64>> = samples.iter().map(|s| s.flight_times()).collect();
        let all_dwells:  Vec<Vec<f64>> = samples.iter().map(|s| s.dwell_times()).collect();
        let speeds: Vec<f64> = samples.iter().filter_map(|s| s.typing_speed_ms()).collect();

        let len = all_flights.iter().map(|v| v.len()).min().unwrap_or(0);

        let (flight_means, flight_stds) = position_stats(&all_flights, len);
        let (dwell_means,  dwell_stds)  = position_stats(&all_dwells,  len);
        let (speed_mean, speed_std) = scalar_stats(&speeds);

        Ok(BehaviorBaseline {
            flight_means, flight_stds,
            dwell_means,  dwell_stds,
            speed_mean, speed_std,
            sample_count: samples.len(),
        })
    }

    /// SHA-256 fingerprint of this baseline (stored in file header).
    pub fn fingerprint(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let hash = Sha256::digest(json.as_bytes());
        hex::encode(hash)
    }
}

// ── Anomaly detector ──────────────────────────────────────────────────────────

pub struct BehaviorDetector {
    /// Reject if z-score exceeds this threshold (default: 2.5 σ)
    pub z_threshold: f64,
    /// Reject if typing speed deviates more than this fraction (e.g. 0.5 = 50%)
    pub speed_tolerance: f64,
}

impl Default for BehaviorDetector {
    fn default() -> Self {
        BehaviorDetector {
            z_threshold: 2.5,
            speed_tolerance: 0.5,
        }
    }
}

/// Result of an anomaly check.
#[derive(Debug, Clone)]
pub struct BehaviorCheckResult {
    /// Overall confidence that this is the enrolled user (0.0–1.0)
    pub confidence: f64,
    /// True if confidence meets the acceptance threshold
    pub accepted: bool,
    /// Per-position z-scores (for diagnostics)
    pub z_scores: Vec<f64>,
    /// Reason for rejection (if any)
    pub rejection_reason: Option<String>,
}

impl BehaviorDetector {
    /// Phase 3: Rule-based z-score check.
    pub fn check(&self, sample: &BehaviorSample, baseline: &BehaviorBaseline) -> BehaviorCheckResult {
        let flights = sample.flight_times();
        let len = flights.len().min(baseline.flight_means.len());

        // Per-position z-scores
        let z_scores: Vec<f64> = (0..len).map(|i| {
            let std = if baseline.flight_stds[i] < 1.0 { 1.0 } else { baseline.flight_stds[i] };
            ((flights[i] - baseline.flight_means[i]) / std).abs()
        }).collect();

        let violations = z_scores.iter().filter(|&&z| z > self.z_threshold).count();
        let violation_rate = if len > 0 { violations as f64 / len as f64 } else { 1.0 };

        // Speed check
        let speed_ok = if let Some(speed) = sample.typing_speed_ms() {
            let deviation = (speed - baseline.speed_mean).abs() / (baseline.speed_mean + 1.0);
            deviation <= self.speed_tolerance
        } else {
            true // can't measure, don't penalise
        };

        // Confidence: 1.0 minus penalty
        let z_confidence = 1.0 - violation_rate.min(1.0);
        let speed_penalty = if speed_ok { 0.0 } else { 0.25 };
        let confidence = (z_confidence - speed_penalty).max(0.0);

        let accepted = confidence >= 0.6 && speed_ok;

        let rejection_reason = if !accepted {
            if !speed_ok {
                Some(format!("Typing speed anomaly ({}% deviation)", 
                    ((sample.typing_speed_ms().unwrap_or(0.0) - baseline.speed_mean).abs() 
                     / baseline.speed_mean * 100.0) as u32))
            } else {
                Some(format!("{} position(s) exceeded {:.1}σ threshold", violations, self.z_threshold))
            }
        } else {
            None
        };

        BehaviorCheckResult { confidence, accepted, z_scores, rejection_reason }
    }

    /// Phase 4: DTW-based similarity score (more robust than per-position z-score).
    pub fn check_dtw(&self, sample: &BehaviorSample, baseline: &BehaviorBaseline) -> BehaviorCheckResult {
        let s_flights = sample.flight_times();
        let b_flights = &baseline.flight_means;

        if s_flights.is_empty() || b_flights.is_empty() {
            return BehaviorCheckResult {
                confidence: 0.0, accepted: false,
                z_scores: vec![], rejection_reason: Some("No timing data".into()),
            };
        }

        let dtw_dist = dtw_distance(&s_flights, b_flights);
        let max_possible = s_flights.len() as f64 * 500.0; // 500ms max per position
        let confidence = 1.0 - (dtw_dist / max_possible).min(1.0);
        let accepted = confidence >= 0.65;

        // Reuse z-score path for diagnostics
        let len = s_flights.len().min(baseline.flight_means.len());
        let z_scores: Vec<f64> = (0..len).map(|i| {
            let std = if baseline.flight_stds[i] < 1.0 { 1.0 } else { baseline.flight_stds[i] };
            ((s_flights[i] - baseline.flight_means[i]) / std).abs()
        }).collect();

        BehaviorCheckResult {
            confidence,
            accepted,
            z_scores,
            rejection_reason: if accepted { None } else {
                Some(format!("DTW distance {:.1} (confidence {:.0}%)", dtw_dist, confidence * 100.0))
            },
        }
    }
}

// ── DTW implementation ────────────────────────────────────────────────────────

fn dtw_distance(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len();
    let m = b.len();
    let inf = f64::INFINITY;
    let mut dtw = vec![vec![inf; m + 1]; n + 1];
    dtw[0][0] = 0.0;

    for i in 1..=n {
        for j in 1..=m {
            let cost = (a[i-1] - b[j-1]).abs();
            dtw[i][j] = cost + dtw[i-1][j].min(dtw[i][j-1]).min(dtw[i-1][j-1]);
        }
    }
    dtw[n][m]
}

// ── Statistics helpers ────────────────────────────────────────────────────────

fn scalar_stats(v: &[f64]) -> (f64, f64) {
    if v.is_empty() { return (0.0, 1.0); }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    let variance = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / v.len() as f64;
    (mean, variance.sqrt().max(1.0))
}

fn position_stats(seqs: &[Vec<f64>], len: usize) -> (Vec<f64>, Vec<f64>) {
    let mut means = vec![0.0; len];
    let mut stds  = vec![1.0; len];
    for i in 0..len {
        let vals: Vec<f64> = seqs.iter().filter_map(|s| s.get(i).copied()).collect();
        let (m, s) = scalar_stats(&vals);
        means[i] = m;
        stds[i]  = s;
    }
    (means, stds)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(times: &[u64]) -> BehaviorSample {
        let mut events = Vec::new();
        for (i, &t) in times.iter().enumerate() {
            events.push(KeyEvent { timestamp_ms: t, event: KeyEventType::KeyDown });
            events.push(KeyEvent { timestamp_ms: t + 80, event: KeyEventType::KeyUp });
        }
        BehaviorSample::new(events)
    }

    fn make_baseline() -> BehaviorBaseline {
        // Simulate 5 very consistent samples
        let samples: Vec<BehaviorSample> = (0..5).map(|jitter: u64| {
            make_sample(&[0, 120+jitter, 240+jitter, 360+jitter, 480+jitter])
        }).collect();
        BehaviorBaseline::enroll(&samples).unwrap()
    }

    #[test]
    fn test_consistent_user_accepted() {
        let baseline = make_baseline();
        let sample = make_sample(&[0, 122, 242, 362, 482]);
        let det = BehaviorDetector::default();
        let result = det.check(&sample, &baseline);
        assert!(result.accepted, "Consistent typer should be accepted, confidence={:.2}", result.confidence);
    }

    #[test]
    fn test_anomalous_user_rejected() {
        let baseline = make_baseline();
        // Very different timing pattern
        let sample = make_sample(&[0, 800, 850, 900, 1800]);
        let det = BehaviorDetector::default();
        let result = det.check(&sample, &baseline);
        assert!(!result.accepted, "Anomalous typer should be rejected, confidence={:.2}", result.confidence);
    }

    #[test]
    fn test_dtw_check() {
        let baseline = make_baseline();
        let good = make_sample(&[0, 121, 241, 361, 481]);
        let bad  = make_sample(&[0, 900, 1800, 2700, 3600]);
        let det = BehaviorDetector::default();
        assert!(det.check_dtw(&good, &baseline).accepted);
        assert!(!det.check_dtw(&bad, &baseline).accepted);
    }

    #[test]
    fn test_enrollment_requires_3_samples() {
        let samples = vec![make_sample(&[0, 100, 200])];
        assert!(BehaviorBaseline::enroll(&samples).is_err());
    }

    #[test]
    fn test_baseline_fingerprint_stable() {
        let b = make_baseline();
        assert_eq!(b.fingerprint(), b.fingerprint());
    }
}
