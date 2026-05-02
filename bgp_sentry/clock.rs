//! Simulation clock — replays BGP timestamps in real time.
//!
//! Port of `simulation_helpers/timing/shared_clock.py`.
//! Anchors the earliest BGP timestamp to wall-clock start_time.
//! Each node calls `wait_until(bgp_timestamp)` before processing an
//! observation, which sleeps until real time catches up.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::{Duration, Instant};

/// Shared simulation clock for real-time BGP replay.
#[derive(Clone)]
pub struct SimulationClock {
    inner: Arc<ClockInner>,
}

struct ClockInner {
    speed_multiplier: f64,
    anchor_bgp_ts: std::sync::Mutex<Option<f64>>,
    anchor_wall_ts: std::sync::Mutex<Option<Instant>>,
    started: AtomicBool,
    start_notify: Notify,
}

impl SimulationClock {
    /// Create a new clock with the given speed multiplier.
    /// 1.0 = real-time, 2.0 = 2x faster, etc.
    pub fn new(speed_multiplier: f64) -> Self {
        Self {
            inner: Arc::new(ClockInner {
                speed_multiplier,
                anchor_bgp_ts: std::sync::Mutex::new(None),
                anchor_wall_ts: std::sync::Mutex::new(None),
                started: AtomicBool::new(false),
                start_notify: Notify::new(),
            }),
        }
    }

    /// Set the BGP time origin (earliest timestamp in the dataset).
    /// Must be called before `start()`.
    pub fn set_epoch(&self, earliest_bgp_timestamp: f64) {
        *self.inner.anchor_bgp_ts.lock().unwrap() = Some(earliest_bgp_timestamp);
    }

    /// Start the clock — anchors BGP epoch to current wall-clock.
    pub fn start(&self) {
        *self.inner.anchor_wall_ts.lock().unwrap() = Some(Instant::now());
        self.inner.started.store(true, Ordering::Release);
        self.inner.start_notify.notify_waiters();
    }

    /// Async wait until wall-clock catches up to this BGP timestamp.
    pub async fn wait_until(&self, bgp_timestamp: f64) {
        // Wait for clock to start
        if !self.inner.started.load(Ordering::Acquire) {
            self.inner.start_notify.notified().await;
        }

        let sleep_needed = self.sleep_needed(bgp_timestamp);
        if sleep_needed > Duration::ZERO {
            tokio::time::sleep(sleep_needed).await;
        }
    }

    /// Calculate how long to sleep for a given BGP timestamp.
    fn sleep_needed(&self, bgp_timestamp: f64) -> Duration {
        let anchor_bgp = self.inner.anchor_bgp_ts.lock().unwrap().unwrap_or(0.0);
        let anchor_wall = self.inner.anchor_wall_ts.lock().unwrap().unwrap_or_else(Instant::now);

        let bgp_offset = bgp_timestamp - anchor_bgp;
        let wall_offset_secs = bgp_offset / self.inner.speed_multiplier;

        let target = anchor_wall + Duration::from_secs_f64(wall_offset_secs);
        let now = Instant::now();

        if target > now {
            target - now
        } else {
            Duration::ZERO
        }
    }

    /// Current simulation time in seconds since epoch.
    pub fn sim_time(&self) -> f64 {
        if !self.inner.started.load(Ordering::Acquire) {
            return 0.0;
        }
        let anchor_wall = self.inner.anchor_wall_ts.lock().unwrap().unwrap_or_else(Instant::now);
        let elapsed = Instant::now().duration_since(anchor_wall);
        elapsed.as_secs_f64() * self.inner.speed_multiplier
    }

    /// Check if the clock has been started.
    pub fn is_started(&self) -> bool {
        self.inner.started.load(Ordering::Acquire)
    }
}
