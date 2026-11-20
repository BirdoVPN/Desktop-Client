//! Where a session goes when its server leaves the pool (MR-2390).
//!
//! A drained or deleted server answers the heartbeat with `server_offline`,
//! and the contract says what that means: "connect to a DIFFERENT server".
//! The backend refuses a connect to any server that is not ONLINE
//! (`server_unavailable`). The re-dial still went back to the same server:
//! ten refused connects over about five minutes, then a give-up, with the
//! always-on block held the whole time. Now the session moves ONCE, to a
//! server this rule picks. When no server qualifies, it ends at once and
//! says the location is unavailable.
//!
//! The rule is iOS's `RelayRetry.next(after:in:origin:)` (Mobile #645,
//! MR-2212), under the owner's rule of 2026-11-19:
//!   * a server the client chose ([`SelectionOrigin::Automatic`]) may move to
//!     the best other server, in any country;
//!   * a location the USER picked never leaves its country: the same city
//!     first, then another server in the same country, else nothing. The
//!     user is told, and is never moved abroad;
//!   * only servers that `/vpn/servers` lists as online and open to this
//!     plan qualify (the best-server rule's filter,
//!     `commands::vpn::pick_quick_connect_server`). A node held for a
//!     jurisdiction mismatch fails its health check and is depooled, so it is
//!     never listed as online. `/vpn/connect` checks the plan and the ONLINE
//!     status again;
//!   * ONE move per episode, from the quiet-rebuild cap
//!     (`reconnect_policy::QuietRebuilds`), which a reap's rebuild spends too;
//!   * the log gives the origin and how far the move went, never a server's
//!     id, name, city, country or address ([`log_line`]).
//!
//! A DELETED server (owner, 2026-11-19, every client) moves by the same
//! rule. It is gone from the list the move fetches, so where it was comes
//! from the lists the app fetched before ([`known_location`]): an automatic
//! pick still goes to the best server anywhere, and a user's pick only to
//! another server in its country, else nowhere (unavailable). It used to
//! move nowhere, whoever chose it.
//!
//! A Multi-Hop route is the user's own pair of locations, so it never moves.
//! A route whose server left ends like a user's pick with nowhere to go.
//!
//! The choice is pure, so the tests below pin it. `auto_reconnect` fetches
//! the list and applies the choice.
//!
//! A connect whose server never answered its FIRST handshake (MR-2514, iOS
//! `retryOnAnotherRelay` from Mobile #645) is retried ONCE on another server
//! by the same rule ([`after_no_handshake`]): the client's pick anywhere, a
//! location the user picked only within its own country (owner, 2026-11-20:
//! "Same country, like iPhone"), else that connect shows its error.
//! `commands::session` fetches the list, dials the choice and logs counts
//! only ([`no_handshake_line`], [`retry_outcome_line`]).

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::api::types::VpnServer;

/// Who chose the server a session was dialled to (MR-2390; iOS
/// `SelectionOrigin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionOrigin {
    /// The client chose it: quick connect's best-server pick when the user
    /// has no usable server of their own, or a server the UI records as the
    /// client's (its fastest-server fallback, or a quick connect's pick that
    /// Auto-Connect dials again). Nobody asked for that location, so a move
    /// may leave it.
    Automatic,
    /// The user picked it, or anything other than the client's own pick set
    /// it. The safe default: a move never takes it out of its country.
    #[default]
    User,
}

impl SelectionOrigin {
    /// The `origin` argument of `connect_vpn`, which the UI sends on every
    /// connect as it records it. Only `"automatic"` is the client's. Anything
    /// else (`"user"`), or nothing, is the user's.
    pub fn from_ipc(origin: Option<&str>) -> Self {
        match origin {
            Some("automatic") => Self::Automatic,
            _ => Self::User,
        }
    }

    /// The wire word, the one `from_ipc` reads: the log, the `relay-retry`
    /// event and the VPN status's `serverOrigin` (MR-2569) use it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::User => "user",
        }
    }
}

/// How far a move went from the server that left. This is the only thing
/// about the target that the log may say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    SameCity,
    SameCountry,
    OtherCountry,
}

impl Reach {
    /// The class's name, as the log and the UI's `relay-retry` notice get it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameCity => "same-city",
            Self::SameCountry => "same-country",
            Self::OtherCountry => "other-country",
        }
    }
}

/// Where the session moves.
#[derive(Debug, Clone)]
pub struct Choice {
    pub server: VpnServer,
    pub reach: Reach,
}

/// Where a server is: its country code and city, as `/vpn/servers` lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    pub country_code: String,
    pub city: String,
}

impl Location {
    pub fn of(server: &VpnServer) -> Self {
        Self {
            country_code: server.country_code.clone(),
            city: server.city.clone(),
        }
    }
}

/// Where each server a list has named this run is ([`remember`]). Never
/// pruned: a deleted server is gone from the next list, and its place is
/// what a move needs. In memory only, and never logged.
static KNOWN: Mutex<BTreeMap<String, Location>> = Mutex::new(BTreeMap::new());

/// Keep where each server in `list` is: every list the app fetches (the
/// UI's server list, quick connect's, a move's own).
pub fn remember(list: &[VpnServer]) {
    let mut known = KNOWN.lock().unwrap_or_else(|e| e.into_inner());
    for server in list {
        known.insert(server.id.clone(), Location::of(server));
    }
}

/// Where `id` was when a list last named it this run, if one did.
pub fn known_location(id: &str) -> Option<Location> {
    KNOWN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .cloned()
}

/// The server to move to after `left` left the pool, or `None`. The first
/// rule that applies wins:
///   1. another server in the SAME city and country;
///   2. [`SelectionOrigin::Automatic`]: the best of all the other servers, in
///      any country;
///   3. [`SelectionOrigin::User`]: the best other server in the SAME country;
///   4. nothing. The caller then says the location is unavailable.
///
/// "Best" is the best-server rule: online, open to this plan, least loaded,
/// then name and id. The server that left is never chosen.
///
/// Where `left` was: its own entry while `list` still has it (drained), else
/// `last_known` (deleted; [`known_location`]). With neither, its country is
/// unknown: a user's choice cannot be kept, so it does not move, and an
/// automatic one still goes to the best server anywhere (owner, 2026-11-19).
pub fn next(
    left: &str,
    list: &[VpnServer],
    origin: SelectionOrigin,
    last_known: Option<&Location>,
) -> Option<Choice> {
    let home = match list.iter().find(|s| s.id == left) {
        Some(listed) => Location::of(listed),
        None => last_known.cloned().unwrap_or_default(),
    };
    let others = || list.iter().filter(|s| s.id != left);
    let country = normalized(&home.country_code);
    let city = normalized(&home.city);
    if !country.is_empty() && !city.is_empty() {
        let same_city = others()
            .filter(|s| normalized(&s.country_code) == country && normalized(&s.city) == city);
        if let Some(server) = best(same_city) {
            return Some(Choice {
                server,
                reach: Reach::SameCity,
            });
        }
    }
    match origin {
        SelectionOrigin::Automatic => {
            let server = best(others())?;
            let reach = reach(&home, &server);
            Some(Choice { server, reach })
        }
        SelectionOrigin::User => {
            if country.is_empty() {
                return None;
            }
            let server = best(others().filter(|s| normalized(&s.country_code) == country))?;
            Some(Choice {
                server,
                reach: Reach::SameCountry,
            })
        }
    }
}

/// The one log line for a move decision: the origin, the count and how far
/// the move went. It takes the whole choice, so no caller needs the server
/// in hand to write a line. The tests feed it marked servers and check that
/// none of their fields comes out.
pub fn log_line(choice: Option<&Choice>, origin: SelectionOrigin) -> String {
    match choice {
        Some(choice) => format!(
            "The server left the pool: moving the session to another server (move 1 of 1, {} \
             pick, {})",
            origin.as_str(),
            choice.reach.as_str()
        ),
        None => format!(
            "The server left the pool: no other server qualifies ({} pick, move 0 of 1) — \
             ending the session as unavailable",
            origin.as_str()
        ),
    }
}

/// MR-2514: the server for the ONE automatic retry of a connect whose server
/// never answered its first handshake, or `None`: [`next`], the rule a
/// server that left the pool moves by, as iOS's `RelayRetry.next` is for both:
///   * a server the client chose: the same city first, then the best server
///     in any country;
///   * a location the user picked: the same city first, then the best server
///     in the SAME country, never abroad (owner, 2026-11-20: "Same country,
///     like iPhone"); with none, `None` and the connect shows its error.
///
/// Either way only servers online and open to this plan, never `failed`.
pub fn after_no_handshake(
    failed: &str,
    list: &[VpnServer],
    origin: SelectionOrigin,
    last_known: Option<&Location>,
) -> Option<Choice> {
    next(failed, list, origin, last_known)
}

/// The log line for the retry decision after an unanswered first handshake:
/// the origin, the count and how far the retry goes. Like [`log_line`], it
/// takes the whole choice and never names a server.
pub fn no_handshake_line(choice: Option<&Choice>, origin: SelectionOrigin) -> String {
    match choice {
        Some(choice) => format!(
            "No handshake from the server: automatic retry 1 of 1 on another server ({} pick, \
             {})",
            origin.as_str(),
            choice.reach.as_str()
        ),
        None => format!(
            "No handshake from the server: no automatic retry ({} pick, retry 0 of 1)",
            origin.as_str()
        ),
    }
}

/// This run's automatic retries after an unanswered first handshake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetryCounts {
    pub attempted: u64,
    pub connected: u64,
}

/// In memory only. The log is the only reader ([`retry_outcome_line`]).
static RETRIES: Mutex<RetryCounts> = Mutex::new(RetryCounts {
    attempted: 0,
    connected: 0,
});

/// Count one retry that ran, and whether it connected. This run's totals.
pub fn count_retry(connected: bool) -> RetryCounts {
    let mut counts = RETRIES.lock().unwrap_or_else(|e| e.into_inner());
    counts.attempted += 1;
    if connected {
        counts.connected += 1;
    }
    *counts
}

/// The log line for how the one retry ended, with this run's counts.
pub fn retry_outcome_line(connected: bool, counts: RetryCounts) -> String {
    let outcome = if connected {
        "connected"
    } else {
        "failed too, and is not retried again"
    };
    format!(
        "The automatic retry after no handshake {outcome} (this run: {} attempted, {} \
         connected)",
        counts.attempted, counts.connected
    )
}

fn best<'a>(candidates: impl Iterator<Item = &'a VpnServer>) -> Option<VpnServer> {
    crate::commands::vpn::pick_quick_connect_server(candidates.cloned().collect(), None)
}

fn reach(from: &Location, to: &VpnServer) -> Reach {
    let country = normalized(&from.country_code);
    if country.is_empty() || country != normalized(&to.country_code) {
        return Reach::OtherCountry;
    }
    let city = normalized(&from.city);
    if !city.is_empty() && city == normalized(&to.city) {
        Reach::SameCity
    } else {
        Reach::SameCountry
    }
}

fn normalized(s: &str) -> String {
    s.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server in the `/vpn/servers` wire shape.
    fn server(
        id: &str,
        cc: &str,
        city: &str,
        load: u8,
        online: bool,
        accessible: bool,
    ) -> VpnServer {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": format!("name-{id}"),
            "country": format!("country-{cc}"),
            "countryCode": cc,
            "city": city,
            "load": load,
            "isOnline": online,
            "accessible": accessible,
        }))
        .unwrap()
    }

    /// The fleet as it is today: one relay per city. `drained` is the one
    /// that left (no longer ONLINE).
    fn fleet() -> Vec<VpnServer> {
        vec![
            server("drained", "DE", "Frankfurt", 5, false, true),
            server("de-ber", "DE", "Berlin", 40, true, true),
            server("nl-ams", "NL", "Amsterdam", 10, true, true),
            server("se-sto", "SE", "Stockholm", 2, true, false),
            server("us-nyc", "US", "New York", 1, false, true),
        ]
    }

    fn picked(choice: Option<Choice>) -> Option<(String, Reach)> {
        choice.map(|c| (c.server.id, c.reach))
    }

    /// An automatic pick moves to the best server anywhere. That is the
    /// least-loaded one that is online and open to the plan: not the
    /// emptier Stockholm (outside the plan) or New York (offline), and never
    /// the server that left.
    #[test]
    fn an_automatic_pick_moves_to_the_best_server_in_any_country() {
        assert_eq!(
            picked(next("drained", &fleet(), SelectionOrigin::Automatic, None)),
            Some(("nl-ams".into(), Reach::OtherCountry))
        );
    }

    /// A user's pick never leaves its country, even when a less-loaded
    /// server waits abroad.
    #[test]
    fn a_users_pick_stays_in_its_country() {
        assert_eq!(
            picked(next("drained", &fleet(), SelectionOrigin::User, None)),
            Some(("de-ber".into(), Reach::SameCountry))
        );
    }

    /// The same city comes first for either origin, whatever the load.
    #[test]
    fn the_same_city_comes_first() {
        let mut list = fleet();
        list.push(server("de-fra-2", " de ", "FRANKFURT ", 90, true, true));
        for origin in [SelectionOrigin::Automatic, SelectionOrigin::User] {
            assert_eq!(
                picked(next("drained", &list, origin, None)),
                Some(("de-fra-2".into(), Reach::SameCity)),
                "{origin:?}"
            );
        }
    }

    /// With nothing usable left in its country, a user's pick does not move:
    /// the caller says the location is unavailable. An automatic pick still
    /// moves abroad.
    #[test]
    fn a_users_pick_with_nothing_left_at_home_goes_nowhere() {
        let list: Vec<_> = fleet()
            .into_iter()
            .map(|mut s| {
                if s.id == "de-ber" {
                    s.accessible = false;
                }
                s
            })
            .collect();
        assert!(next("drained", &list, SelectionOrigin::User, None).is_none());
        assert_eq!(
            picked(next("drained", &list, SelectionOrigin::Automatic, None)),
            Some(("nl-ams".into(), Reach::OtherCountry))
        );
        let offline_too: Vec<_> = list
            .into_iter()
            .map(|mut s| {
                s.is_online = false;
                s
            })
            .collect();
        assert!(next("drained", &offline_too, SelectionOrigin::Automatic, None).is_none());
    }

    /// Only servers online AND open to the plan qualify, and the one that
    /// left never does, even while a cached list still calls it online.
    #[test]
    fn only_online_servers_in_the_plan_qualify_and_never_the_one_that_left() {
        let list = vec![
            server("drained", "DE", "Frankfurt", 0, true, true),
            server("de-ber", "DE", "Berlin", 50, false, true),
            server("de-mun", "DE", "Munich", 50, true, false),
        ];
        for origin in [SelectionOrigin::Automatic, SelectionOrigin::User] {
            assert!(next("drained", &list, origin, None).is_none(), "{origin:?}");
        }
    }

    /// A user's pick whose country is unknown does not move: neither a
    /// deleted server no earlier list named, nor one the list names with no
    /// country. An automatic pick still goes anywhere.
    #[test]
    fn a_users_pick_whose_country_is_unknown_moves_nowhere() {
        assert!(next("deleted", &fleet(), SelectionOrigin::User, None).is_none());
        assert_eq!(
            picked(next("deleted", &fleet(), SelectionOrigin::Automatic, None)),
            Some(("nl-ams".into(), Reach::OtherCountry))
        );
        let mut list = fleet();
        list[0].country_code = "  ".into();
        assert!(next("drained", &list, SelectionOrigin::User, None).is_none());
        assert_eq!(
            picked(next("drained", &list, SelectionOrigin::Automatic, None)),
            Some(("nl-ams".into(), Reach::OtherCountry))
        );
    }

    /// A DELETED server (owner, 2026-11-19): gone from the list, so where it
    /// was comes from an earlier one. An automatic pick moves to the best
    /// server anywhere, another country when its own has none. A user's pick
    /// moves within its country, the same city first, else nowhere. The
    /// deleted server is never chosen.
    #[test]
    fn a_deleted_server_moves_by_where_it_was() {
        let frankfurt = Location {
            country_code: "DE".into(),
            city: "Frankfurt".into(),
        };
        let list: Vec<_> = fleet().into_iter().filter(|s| s.id != "drained").collect();
        assert_eq!(
            picked(next(
                "drained",
                &list,
                SelectionOrigin::User,
                Some(&frankfurt)
            )),
            Some(("de-ber".into(), Reach::SameCountry))
        );
        let abroad_only: Vec<_> = list.iter().filter(|s| s.id != "de-ber").cloned().collect();
        assert!(next(
            "drained",
            &abroad_only,
            SelectionOrigin::User,
            Some(&frankfurt)
        )
        .is_none());
        for last_known in [Some(&frankfurt), None] {
            assert_eq!(
                picked(next(
                    "drained",
                    &abroad_only,
                    SelectionOrigin::Automatic,
                    last_known
                )),
                Some(("nl-ams".into(), Reach::OtherCountry)),
                "{last_known:?}"
            );
        }
        let mut list = list;
        list.push(server("de-fra-2", "DE", "Frankfurt", 90, true, true));
        for origin in [SelectionOrigin::Automatic, SelectionOrigin::User] {
            assert_eq!(
                picked(next("drained", &list, origin, Some(&frankfurt))),
                Some(("de-fra-2".into(), Reach::SameCity)),
                "{origin:?}"
            );
        }
        // Never the deleted server, even with an earlier list naming it.
        remember(&[server("mr2390-deleted", "DE", "Frankfurt", 0, true, true)]);
        let home = known_location("mr2390-deleted");
        for origin in [SelectionOrigin::Automatic, SelectionOrigin::User] {
            let choice = next("mr2390-deleted", &list, origin, home.as_ref()).unwrap();
            assert_ne!(choice.server.id, "mr2390-deleted", "{origin:?}");
        }
    }

    /// Where a server was outlives the lists that no longer name it.
    #[test]
    fn where_a_server_was_outlives_the_lists_without_it() {
        assert_eq!(known_location("mr2390-known"), None);
        remember(&[server("mr2390-known", "DE", "Frankfurt", 5, true, true)]);
        remember(&[server("mr2390-other", "NL", "Amsterdam", 5, true, true)]);
        assert_eq!(
            known_location("mr2390-known"),
            Some(Location {
                country_code: "DE".into(),
                city: "Frankfurt".into(),
            })
        );
    }

    /// Ties follow the best-server rule (name, then id), so the answer does
    /// not depend on the order the list arrived in.
    #[test]
    fn ties_follow_the_best_server_rule_whatever_the_order() {
        let mut list = vec![
            server("drained", "DE", "Frankfurt", 0, false, true),
            server("b", "FR", "Paris", 7, true, true),
            server("a", "GB", "London", 7, true, true),
        ];
        let first = picked(next("drained", &list, SelectionOrigin::Automatic, None));
        list.reverse();
        assert_eq!(
            picked(next("drained", &list, SelectionOrigin::Automatic, None)),
            first
        );
        assert_eq!(first, Some(("a".into(), Reach::OtherCountry)));
    }

    /// Only `"automatic"` from the UI is the client's pick. Anything else is
    /// the user's, the safe default.
    #[test]
    fn only_the_uis_own_pick_is_automatic() {
        assert_eq!(
            SelectionOrigin::from_ipc(Some("automatic")),
            SelectionOrigin::Automatic
        );
        for other in [
            None,
            Some("user"),
            Some(""),
            Some("Automatic"),
            Some("auto"),
        ] {
            assert_eq!(
                SelectionOrigin::from_ipc(other),
                SelectionOrigin::User,
                "{other:?}"
            );
        }
        assert_eq!(SelectionOrigin::default(), SelectionOrigin::User);
    }

    /// The log line carries counts and a reach class only: no field of the
    /// target or of the server that left.
    #[test]
    fn the_log_line_names_no_server() {
        let list = fleet();
        for origin in [SelectionOrigin::Automatic, SelectionOrigin::User] {
            let choice = next("drained", &list, origin, None);
            let line = log_line(choice.as_ref(), origin);
            assert!(line.contains("move 1 of 1"), "{line}");
            for s in &list {
                for field in [&s.id, &s.name, &s.country, &s.country_code, &s.city] {
                    assert!(!line.contains(field.as_str()), "{line} names `{field}`");
                }
            }
        }
        let none = log_line(None, SelectionOrigin::User);
        assert!(
            none.contains("move 0 of 1") && none.contains("user pick"),
            "{none}"
        );
    }

    /// MR-2514: after an unanswered first handshake, a server the client
    /// chose is retried on the best other server, in any country: not the
    /// emptier Stockholm (outside the plan), not New York (offline, as a node
    /// held for its jurisdiction is), never the server that failed.
    #[test]
    fn an_unanswered_automatic_pick_is_retried_on_the_best_server_anywhere() {
        let mut list = fleet();
        // The server that failed is still listed online: it never answered.
        list[0].is_online = true;
        assert_eq!(
            picked(after_no_handshake(
                "drained",
                &list,
                SelectionOrigin::Automatic,
                None
            )),
            Some(("nl-ams".into(), Reach::OtherCountry))
        );
        // Only held, plan-excluded or offline servers left: no retry.
        let ineligible: Vec<_> = list
            .into_iter()
            .filter(|s| s.id != "nl-ams" && s.id != "de-ber")
            .collect();
        assert!(
            after_no_handshake("drained", &ineligible, SelectionOrigin::Automatic, None).is_none()
        );
    }

    /// Owner, 2026-11-20 ("Same country, like iPhone"): a location the user
    /// picked is retried within its own country, the same city first, as on
    /// iOS (`RelayRetry.next`, `.user`). It never leaves the country, even
    /// when the only eligible server is abroad; with nothing eligible at home
    /// there is no retry and the connect shows its error.
    #[test]
    fn an_unanswered_users_pick_stays_in_its_country() {
        let mut list = fleet();
        // The server that failed is still listed online: it never answered.
        list[0].is_online = true;
        assert_eq!(
            picked(after_no_handshake(
                "drained",
                &list,
                SelectionOrigin::User,
                None
            )),
            Some(("de-ber".into(), Reach::SameCountry)),
            "the best other server in its country, not the emptier Amsterdam"
        );
        let mut with_sibling = list.clone();
        with_sibling.push(server("de-fra-2", "DE", "Frankfurt", 90, true, true));
        assert_eq!(
            picked(after_no_handshake(
                "drained",
                &with_sibling,
                SelectionOrigin::User,
                None
            )),
            Some(("de-fra-2".into(), Reach::SameCity)),
            "the same city first"
        );
        // Only abroad is eligible: a user's pick does not move; an automatic
        // one does.
        let abroad_only: Vec<_> = list.into_iter().filter(|s| s.id != "de-ber").collect();
        assert!(after_no_handshake("drained", &abroad_only, SelectionOrigin::User, None).is_none());
        assert_eq!(
            picked(after_no_handshake(
                "drained",
                &abroad_only,
                SelectionOrigin::Automatic,
                None
            )),
            Some(("nl-ams".into(), Reach::OtherCountry))
        );
        // Gone from the list: its country from an earlier list, else nowhere.
        let frankfurt = Location {
            country_code: "DE".into(),
            city: "Frankfurt".into(),
        };
        let without: Vec<_> = fleet().into_iter().filter(|s| s.id != "drained").collect();
        assert_eq!(
            picked(after_no_handshake(
                "drained",
                &without,
                SelectionOrigin::User,
                Some(&frankfurt)
            )),
            Some(("de-ber".into(), Reach::SameCountry))
        );
        assert!(after_no_handshake("drained", &without, SelectionOrigin::User, None).is_none());
    }

    /// The retry's log lines carry the origin, counts and a reach class only.
    #[test]
    fn the_retry_lines_name_no_server() {
        let list = fleet();
        let choice = after_no_handshake("drained", &list, SelectionOrigin::Automatic, None);
        let lines = [
            no_handshake_line(choice.as_ref(), SelectionOrigin::Automatic),
            no_handshake_line(None, SelectionOrigin::User),
            no_handshake_line(None, SelectionOrigin::Automatic),
            retry_outcome_line(
                true,
                RetryCounts {
                    attempted: 3,
                    connected: 2,
                },
            ),
            retry_outcome_line(
                false,
                RetryCounts {
                    attempted: 3,
                    connected: 2,
                },
            ),
        ];
        assert!(
            lines[0].contains("retry 1 of 1") && lines[0].contains("other-country"),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains("retry 0 of 1") && lines[1].contains("user pick"),
            "{}",
            lines[1]
        );
        assert!(
            lines[3].contains("3 attempted, 2 connected"),
            "{}",
            lines[3]
        );
        assert!(lines[4].contains("not retried again"), "{}", lines[4]);
        for line in &lines {
            for s in &list {
                for field in [&s.id, &s.name, &s.country, &s.country_code, &s.city] {
                    assert!(!line.contains(field.as_str()), "{line} names `{field}`");
                }
            }
        }
    }

    /// Every retry that ran is counted, and only the ones that connected as
    /// connected. Other tests count too, so this reads a difference.
    #[test]
    fn every_retry_is_counted() {
        let before = count_retry(false);
        let after = count_retry(true);
        assert!(after.attempted > before.attempted, "{before:?} {after:?}");
        assert!(after.connected > before.connected, "{before:?} {after:?}");
    }
}
