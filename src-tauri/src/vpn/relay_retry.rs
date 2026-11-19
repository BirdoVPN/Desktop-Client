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
//! A Multi-Hop route is the user's own pair of locations, so it never moves.
//! A route whose server left ends like a user's pick with nowhere to go.
//!
//! Pure, so the tests below pin the choice. `auto_reconnect` fetches the list
//! and applies the choice.

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

    fn as_str(self) -> &'static str {
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
    fn as_str(self) -> &'static str {
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

/// The server to move to after `left` left the pool, or `None`. The first
/// rule that applies wins:
///   1. another server in the SAME city and country;
///   2. [`SelectionOrigin::Automatic`]: the best of all the other servers, in
///      any country;
///   3. [`SelectionOrigin::User`]: the best other server in the SAME country;
///   4. nothing. The caller then says the location is unavailable.
///
/// "Best" is the best-server rule: online, open to this plan, least loaded,
/// then name and id. `None` when `left` is not in `list` (a deleted server):
/// without its country a user's choice cannot be kept, so nothing moves. iOS
/// applies that to every origin, and so does this.
pub fn next(left: &str, list: &[VpnServer], origin: SelectionOrigin) -> Option<Choice> {
    let failed = list.iter().find(|s| s.id == left)?;
    let others = || list.iter().filter(|s| s.id != left);
    let country = normalized(&failed.country_code);
    let city = normalized(&failed.city);
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
            let reach = reach(failed, &server);
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

fn best<'a>(candidates: impl Iterator<Item = &'a VpnServer>) -> Option<VpnServer> {
    crate::commands::vpn::pick_quick_connect_server(candidates.cloned().collect(), None)
}

fn reach(from: &VpnServer, to: &VpnServer) -> Reach {
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
            picked(next("drained", &fleet(), SelectionOrigin::Automatic)),
            Some(("nl-ams".into(), Reach::OtherCountry))
        );
    }

    /// A user's pick never leaves its country, even when a less-loaded
    /// server waits abroad.
    #[test]
    fn a_users_pick_stays_in_its_country() {
        assert_eq!(
            picked(next("drained", &fleet(), SelectionOrigin::User)),
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
                picked(next("drained", &list, origin)),
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
        assert!(next("drained", &list, SelectionOrigin::User).is_none());
        assert_eq!(
            picked(next("drained", &list, SelectionOrigin::Automatic)),
            Some(("nl-ams".into(), Reach::OtherCountry))
        );
        let offline_too: Vec<_> = list
            .into_iter()
            .map(|mut s| {
                s.is_online = false;
                s
            })
            .collect();
        assert!(next("drained", &offline_too, SelectionOrigin::Automatic).is_none());
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
            assert!(next("drained", &list, origin).is_none(), "{origin:?}");
        }
    }

    /// A server the list no longer has (deleted) leaves no country to keep,
    /// so nothing moves, whoever chose it (iOS's rule). Nor does a user's
    /// pick whose country the list does not say.
    #[test]
    fn a_server_the_list_does_not_have_moves_nowhere() {
        for origin in [SelectionOrigin::Automatic, SelectionOrigin::User] {
            assert!(next("deleted", &fleet(), origin).is_none(), "{origin:?}");
        }
        let mut list = fleet();
        list[0].country_code = "  ".into();
        assert!(next("drained", &list, SelectionOrigin::User).is_none());
        assert_eq!(
            picked(next("drained", &list, SelectionOrigin::Automatic)),
            Some(("nl-ams".into(), Reach::OtherCountry))
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
        let first = picked(next("drained", &list, SelectionOrigin::Automatic));
        list.reverse();
        assert_eq!(
            picked(next("drained", &list, SelectionOrigin::Automatic)),
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
            let choice = next("drained", &list, origin);
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
}
