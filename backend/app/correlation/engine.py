"""Rule-based correlation of normalised events.

Every rule names the sources it links, the keys both events must share
(non-empty and equal) and a time relation. A link is only formed when all
shared keys match *and* the time relation holds, so coincidence in time alone
never links anything. Each link records the human-readable reasons.

Rules are evaluated on event time (``ts``), not arrival time, so a late
event links to the events it belongs with regardless of arrival order. The
result for a set of events does not depend on the order they were added.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Optional

from app.correlation.events import NormalizedEvent

LATE_AFTER_SECONDS = 120.0
MAX_EVENTS = 20000


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    side_a: tuple[str, ...]                # sources allowed for event A
    side_b: tuple[str, ...]
    keys: tuple[str, ...]                  # attributes that must be present and equal on both events
    window_s: float
    ordered: bool                          # True: B must happen 0..window_s after A. False: |A-B| <= window_s
    filter_a: Callable[[NormalizedEvent], bool] = lambda e: True
    filter_b: Callable[[NormalizedEvent], bool] = lambda e: True

    def describe(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "description": self.description,
                "links": f"{'/'.join(self.side_a)} -> {'/'.join(self.side_b)}", "requires_same": list(self.keys),
                "window_seconds": self.window_s, "ordered": self.ordered}


RULES: tuple[Rule, ...] = (
    Rule("failed_then_successful_login", "Failed logins, then a successful login",
         "A failed login and a later successful login by the same actor within 10 minutes.",
         ("auth",), ("auth",), ("actor",), 600, True,
         lambda e: e.outcome == "failure", lambda e: e.outcome == "success"),
    Rule("login_then_record_access", "Login, then record access",
         "A successful login and record access (application audit or database audit) by the same actor within 15 minutes after it.",
         ("auth",), ("audit", "db_audit"), ("actor",), 900, True, lambda e: e.outcome == "success"),
    Rule("same_request", "Same request across systems",
         "Events from different systems carrying the same request id within 2 minutes of each other.",
         ("app", "auth", "audit", "server", "db_audit"), ("app", "auth", "audit", "server", "db_audit"),
         ("request_id",), 120, False),
    Rule("app_error_on_host", "Application error and server fault on one host",
         "An application error and a server warning/error on the same host within 60 seconds of each other.",
         ("app",), ("server",), ("host",), 60, False,
         lambda e: e.outcome == "error", lambda e: e.outcome in ("error", "warning")),
    Rule("record_in_app_and_database", "Same record in application and database audit",
         "An application request and a database audit entry for the same exact record within 30 seconds of each other.",
         ("app",), ("db_audit",), ("resource",), 30, False),
)
RULES_BY_ID = {r.id: r for r in RULES}


def _value(event: NormalizedEvent, key: str) -> Optional[str]:
    return getattr(event, key, None) or None


def _can_be(event: NormalizedEvent, sources: tuple[str, ...], flt: Callable[[NormalizedEvent], bool]) -> bool:
    return event.source in sources and flt(event)


class CorrelationEngine:
    def __init__(self, rules: tuple[Rule, ...] = RULES, *, late_after_s: float = LATE_AFTER_SECONDS,
                 max_events: int = MAX_EVENTS) -> None:
        self.rules = rules
        self.late_after_s = late_after_s
        self.max_events = max_events
        self.events: dict[str, NormalizedEvent] = {}
        self._links: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._index: dict[tuple[str, str], list[str]] = {}   # (key, value) -> event ids

    # -- ingestion ----------------------------------------------------------

    def add(self, event: NormalizedEvent) -> list[dict[str, Any]]:
        """Add one event (idempotent by id); return the links it created."""
        if event.id in self.events:
            return []
        if len(self.events) >= self.max_events:
            oldest = min(self.events.values(), key=lambda e: e.ts)
            self._evict(oldest.id)
        self.events[event.id] = event
        created: list[dict[str, Any]] = []
        for rule in self.rules:
            created += self._link_for_rule(rule, event)
        for key in ("actor", "request_id", "host", "resource"):
            value = _value(event, key)
            if value:
                self._index.setdefault((key, value), []).append(event.id)
        return created

    def add_all(self, events: list[NormalizedEvent]) -> None:
        for event in events:
            self.add(event)

    def _evict(self, event_id: str) -> None:
        event = self.events.pop(event_id, None)
        if event is None:
            return
        for key in ("actor", "request_id", "host", "resource"):
            value = _value(event, key)
            if value and (key, value) in self._index:
                self._index[(key, value)] = [i for i in self._index[(key, value)] if i != event_id]
        for link_key in [k for k in self._links if event_id in (k[1], k[2])]:
            del self._links[link_key]

    def _link_for_rule(self, rule: Rule, event: NormalizedEvent) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        roles: list[str] = []
        if _can_be(event, rule.side_a, rule.filter_a):
            roles.append("a")
        if _can_be(event, rule.side_b, rule.filter_b):
            roles.append("b")
        for role in roles:
            if any(not _value(event, k) for k in rule.keys):
                continue  # reported through skipped_for_missing_fields(), never guessed
            pivot = rule.keys[0]
            for other_id in list(self._index.get((pivot, _value(event, pivot) or ""), [])):
                other = self.events.get(other_id)
                if other is None or other.id == event.id:
                    continue
                a, b = (event, other) if role == "a" else (other, event)
                if not (_can_be(a, rule.side_a, rule.filter_a) and _can_be(b, rule.side_b, rule.filter_b)):
                    continue
                link = self._evaluate(rule, a, b)
                if link is None:
                    continue
                key = (rule.id, a.id, b.id)
                if key not in self._links:
                    self._links[key] = link
                    out.append(link)
        return out

    def _evaluate(self, rule: Rule, a: NormalizedEvent, b: NormalizedEvent) -> Optional[dict[str, Any]]:
        reasons: list[str] = []
        for key in rule.keys:
            va, vb = _value(a, key), _value(b, key)
            if not va or not vb or va != vb:
                return None
            reasons.append(f"same {key.replace('_', ' ')} ({va})")
        gap = (b.ts - a.ts).total_seconds()
        if rule.ordered:
            if not 0 <= gap <= rule.window_s:
                return None
            reasons.append(f"{b.source} event {gap:g}s after {a.source} event (limit {rule.window_s:g}s)")
        else:
            if abs(gap) > rule.window_s:
                return None
            reasons.append(f"events {abs(gap):g}s apart (limit {rule.window_s:g}s)")
        late = [e.id for e in (a, b) if self.is_late(e)]
        return {"rule": rule.id, "title": rule.title, "a": a.id, "b": b.id, "gap_s": gap, "reasons": reasons,
                "involves_late_event": bool(late), "late_events": late}

    # -- queries ------------------------------------------------------------

    def is_late(self, event: NormalizedEvent) -> bool:
        return event.received_at is not None and (event.received_at - event.ts).total_seconds() > self.late_after_s

    def links(self) -> list[dict[str, Any]]:
        return sorted(self._links.values(), key=lambda l: (self.events[l["a"]].ts, l["rule"], l["a"], l["b"]))

    def skipped_for_missing_fields(self) -> list[dict[str, Any]]:
        """Events that no rule could use because every rule they are eligible
        for needs a field they lack. They are reported rather than matched on
        a guess. (An event missing one optional key, such as a request id, but
        carrying another a rule can use, is not reported.)"""
        out = []
        for event in sorted(self.events.values(), key=lambda e: (e.ts, e.id)):
            missing_by_rule: dict[str, list[str]] = {}
            joinable = False
            for rule in self.rules:
                if not (_can_be(event, rule.side_a, rule.filter_a) or _can_be(event, rule.side_b, rule.filter_b)):
                    continue
                missing = [k for k in rule.keys if not _value(event, k)]
                if not missing:
                    joinable = True
                    break
                missing_by_rule[rule.id] = missing
            if not joinable and missing_by_rule:
                out.append({"event_id": event.id, "source": event.source, "missing_by_rule": missing_by_rule})
        return out

    def groups(self, *, min_size: int = 2) -> list[dict[str, Any]]:
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for link in self._links.values():
            ra, rb = find(link["a"]), find(link["b"])
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)
        members: dict[str, list[str]] = {}
        for node in list(parent):
            members.setdefault(find(node), []).append(node)
        out = []
        for ids in members.values():
            if len(ids) < min_size:
                continue
            events = sorted((self.events[i] for i in ids), key=lambda e: (e.ts, e.id))
            idset = set(ids)
            links = [l for l in self.links() if l["a"] in idset]
            out.append({
                "group_id": "g-" + hashlib.sha1("|".join(sorted(ids)).encode()).hexdigest()[:10],
                "size": len(events),
                "sources": sorted({e.source for e in events}),
                "first_ts": events[0].ts.isoformat(), "last_ts": events[-1].ts.isoformat(),
                "events": [e.summary() | {"late": self.is_late(e)} for e in events],
                "links": links,
                "why": sorted({f"{l['title']}: " + "; ".join(l["reasons"]) for l in links}),
                "has_late_events": any(self.is_late(e) for e in events),
            })
        out.sort(key=lambda g: (g["first_ts"], g["group_id"]))
        return out

    def result(self, *, adapter_skipped: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
        groups = self.groups()
        linked = {e["id"] for g in groups for e in g["events"]}
        return {
            "groups": groups,
            "event_count": len(self.events),
            "linked_event_count": len(linked),
            "unlinked_event_count": len(self.events) - len(linked),
            "late_event_ids": sorted(e.id for e in self.events.values() if self.is_late(e)),
            "skipped_for_missing_fields": self.skipped_for_missing_fields(),
            "adapter_skipped": adapter_skipped or [],
            "rules": [r.describe() for r in self.rules],
            "note": "Events are linked only by the rules above, which need a shared key. Nothing is linked "
                    "because it happened at a similar time.",
        }


def correlate(events: list[NormalizedEvent], *, adapter_skipped: Optional[list[dict[str, Any]]] = None,
              rules: tuple[Rule, ...] = RULES) -> dict[str, Any]:
    engine = CorrelationEngine(rules)
    engine.add_all(events)
    return engine.result(adapter_skipped=adapter_skipped)
