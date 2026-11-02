//! In-memory throttling of failed logins, keyed by client address.
//!
//! Nothing is persisted, so a restart clears every ban. Memory is bounded by
//! `max_tracked`: once full, expired entries are pruned and, failing that, the
//! least significant entry is evicted to make room.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Failed attempts allowed before an address is banned.
pub const MAX_FAILED_ATTEMPTS: u32 = 3;

/// How long a ban lasts, and how long failures are remembered.
pub const BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Default number of addresses tracked at once (well under 1 MiB of state).
pub const DEFAULT_MAX_TRACKED: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    /// When the first remembered failure happened.
    window_start: Instant,
    banned_until: Option<Instant>,
}

impl Entry {
    fn is_expired(&self, now: Instant) -> bool {
        match self.banned_until {
            Some(until) => now >= until,
            None => now.saturating_duration_since(self.window_start) >= BAN_DURATION,
        }
    }
}

/// Outcome of a login attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    Succeeded,
    /// The credentials were wrong; `remaining` more failures trigger a ban.
    Failed {
        remaining: u32,
    },
    /// The address is banned. Credentials were not checked if it already was.
    Banned {
        retry_after: Duration,
    },
}

#[derive(Debug)]
pub struct LoginRateLimiter {
    entries: Mutex<HashMap<IpAddr, Entry>>,
    max_tracked: usize,
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_TRACKED)
    }
}

impl LoginRateLimiter {
    pub fn new(max_tracked: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_tracked: max_tracked.max(1),
        }
    }

    /// Maps an address to the bucket it is counted in.
    ///
    /// An IPv6 host typically controls a whole /64, so counting single
    /// addresses would let it rotate past any limit.
    fn key(ip: IpAddr) -> IpAddr {
        match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !(u64::MAX as u128))),
            v4 => v4,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, Entry>> {
        // The map holds no invariants a panicking holder could break.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Runs `verify` for a login from `ip` unless the address is banned, and
    /// records the result.
    ///
    /// The check, the verification and the bookkeeping happen under one lock,
    /// so parallel requests cannot squeeze in extra attempts. `verify` must be
    /// cheap and must not block.
    pub fn attempt(&self, ip: IpAddr, verify: impl FnOnce() -> bool) -> Attempt {
        self.attempt_at(ip, Instant::now(), verify)
    }

    pub fn attempt_at(&self, ip: IpAddr, now: Instant, verify: impl FnOnce() -> bool) -> Attempt {
        let key = Self::key(ip);
        let mut entries = self.lock();

        if entries.get(&key).is_some_and(|entry| entry.is_expired(now)) {
            entries.remove(&key);
        }

        if let Some(until) = entries.get(&key).and_then(|entry| entry.banned_until) {
            return Attempt::Banned {
                retry_after: until.saturating_duration_since(now),
            };
        }

        if verify() {
            entries.remove(&key);
            return Attempt::Succeeded;
        }

        if !entries.contains_key(&key) && entries.len() >= self.max_tracked {
            Self::make_room(&mut entries, self.max_tracked, now);
        }

        let entry = entries.entry(key).or_insert(Entry {
            failures: 0,
            window_start: now,
            banned_until: None,
        });
        entry.failures += 1;

        if entry.failures >= MAX_FAILED_ATTEMPTS {
            entry.banned_until = Some(now + BAN_DURATION);
            Attempt::Banned {
                retry_after: BAN_DURATION,
            }
        } else {
            Attempt::Failed {
                remaining: MAX_FAILED_ATTEMPTS - entry.failures,
            }
        }
    }

    /// Number of addresses currently tracked.
    pub fn tracked(&self) -> usize {
        self.lock().len()
    }

    #[cfg(test)]
    fn is_banned_at(&self, ip: IpAddr, now: Instant) -> bool {
        self.lock()
            .get(&Self::key(ip))
            .is_some_and(|entry| !entry.is_expired(now) && entry.banned_until.is_some())
    }

    fn make_room(entries: &mut HashMap<IpAddr, Entry>, max_tracked: usize, now: Instant) {
        entries.retain(|_, entry| !entry.is_expired(now));
        if entries.len() < max_tracked {
            return;
        }

        // Evict the least significant entry: an unbanned address with the
        // oldest failures, otherwise the ban that would end soonest.
        let victim = entries
            .iter()
            .min_by_key(|(_, entry)| {
                (
                    entry.banned_until.is_some(),
                    entry.banned_until.unwrap_or(entry.window_start),
                )
            })
            .map(|(key, _)| *key);
        if let Some(victim) = victim {
            entries.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn fail(limiter: &LoginRateLimiter, ip: IpAddr, now: Instant) -> Attempt {
        limiter.attempt_at(ip, now, || false)
    }

    fn is_banned(limiter: &LoginRateLimiter, ip: IpAddr, now: Instant) -> bool {
        limiter.is_banned_at(ip, now)
    }

    #[test]
    fn test_bans_after_max_failures() {
        let limiter = LoginRateLimiter::default();
        let now = Instant::now();
        let ip = v4(1);

        for attempt in 1..MAX_FAILED_ATTEMPTS {
            assert_eq!(
                fail(&limiter, ip, now),
                Attempt::Failed {
                    remaining: MAX_FAILED_ATTEMPTS - attempt
                }
            );
        }
        assert_eq!(
            fail(&limiter, ip, now),
            Attempt::Banned {
                retry_after: BAN_DURATION
            }
        );
        assert!(is_banned(&limiter, ip, now));

        // Other addresses are unaffected.
        assert!(!is_banned(&limiter, v4(2), now));
    }

    #[test]
    fn test_banned_address_cannot_log_in_with_correct_key() {
        let limiter = LoginRateLimiter::default();
        let now = Instant::now();
        let ip = v4(1);
        for _ in 0..MAX_FAILED_ATTEMPTS {
            fail(&limiter, ip, now);
        }

        let outcome = limiter.attempt_at(ip, now, || panic!("must not verify while banned"));
        assert!(matches!(outcome, Attempt::Banned { .. }));
    }

    #[test]
    fn test_ban_expires_after_duration() {
        let limiter = LoginRateLimiter::default();
        let now = Instant::now();
        let ip = v4(1);
        for _ in 0..MAX_FAILED_ATTEMPTS {
            fail(&limiter, ip, now);
        }

        let almost = now + BAN_DURATION - Duration::from_secs(1);
        assert_eq!(
            limiter.attempt_at(ip, almost, || true),
            Attempt::Banned {
                retry_after: Duration::from_secs(1)
            }
        );
        assert_eq!(
            limiter.attempt_at(ip, now + BAN_DURATION, || true),
            Attempt::Succeeded
        );
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn test_old_failures_are_forgotten() {
        let limiter = LoginRateLimiter::default();
        let now = Instant::now();
        let ip = v4(1);
        for _ in 1..MAX_FAILED_ATTEMPTS {
            fail(&limiter, ip, now);
        }

        // The window has passed, so this counts as the first failure again.
        assert_eq!(
            fail(&limiter, ip, now + BAN_DURATION),
            Attempt::Failed {
                remaining: MAX_FAILED_ATTEMPTS - 1
            }
        );
    }

    #[test]
    fn test_success_resets_failures() {
        let limiter = LoginRateLimiter::default();
        let now = Instant::now();
        let ip = v4(1);
        for _ in 1..MAX_FAILED_ATTEMPTS {
            fail(&limiter, ip, now);
        }
        assert_eq!(limiter.attempt_at(ip, now, || true), Attempt::Succeeded);
        assert_eq!(limiter.tracked(), 0);
        assert_eq!(
            fail(&limiter, ip, now),
            Attempt::Failed {
                remaining: MAX_FAILED_ATTEMPTS - 1
            }
        );
    }

    #[test]
    fn test_ipv6_is_counted_per_64() {
        let limiter = LoginRateLimiter::default();
        let now = Instant::now();
        for host in 1..=MAX_FAILED_ATTEMPTS {
            let ip = IpAddr::from_str(&format!("2001:db8:1:2::{host}")).unwrap();
            fail(&limiter, ip, now);
        }
        let sibling = IpAddr::from_str("2001:db8:1:2:ffff::1").unwrap();
        assert!(is_banned(&limiter, sibling, now));

        let other_prefix = IpAddr::from_str("2001:db8:1:3::1").unwrap();
        assert!(!is_banned(&limiter, other_prefix, now));
    }

    #[test]
    fn test_mapped_ipv4_shares_bucket_with_ipv4() {
        let limiter = LoginRateLimiter::default();
        let now = Instant::now();
        let mapped = IpAddr::from_str("::ffff:192.0.2.1").unwrap();
        for _ in 0..MAX_FAILED_ATTEMPTS {
            fail(&limiter, mapped, now);
        }
        assert!(is_banned(&limiter, v4(1), now));
    }

    #[test]
    fn test_memory_is_bounded() {
        let limiter = LoginRateLimiter::new(16);
        let now = Instant::now();
        for i in 0..1000u32 {
            fail(&limiter, IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), now);
            assert!(limiter.tracked() <= 16);
        }
    }

    #[test]
    fn test_eviction_keeps_bans_over_unbanned_entries() {
        let limiter = LoginRateLimiter::new(2);
        let now = Instant::now();

        let banned = v4(1);
        for _ in 0..MAX_FAILED_ATTEMPTS {
            fail(&limiter, banned, now);
        }

        // A flood of single failures from other addresses must not evict the ban.
        for last in 2..100 {
            fail(&limiter, v4(last), now);
        }
        assert!(is_banned(&limiter, banned, now));
        assert_eq!(limiter.tracked(), 2);
    }

    #[test]
    fn test_full_table_prunes_expired_entries_first() {
        let limiter = LoginRateLimiter::new(2);
        let now = Instant::now();
        fail(&limiter, v4(1), now);
        fail(&limiter, v4(2), now);

        fail(&limiter, v4(3), now + BAN_DURATION);
        assert_eq!(limiter.tracked(), 1, "both stale entries are pruned");
    }
}
