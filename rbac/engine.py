"""
RBAC Engine - Enforcement Engine
----------------------------------
The single entry point for all access decisions.

Every access check goes through:
    engine.can(subject, action, resource, context) -> bool

The engine also keeps an audit log of every decision made,
which is critical for security systems — you need to know
not just what was allowed, but what was denied and why.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from rbac.models import Subject, Permission


@dataclass
class AccessDecision:
    """
    A record of a single access control decision.
    Every call to can() produces one of these.
    """
    subject:    str
    action:     str
    resource:   str
    allowed:    bool
    reason:     str
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __str__(self):
        verdict = "ALLOW" if self.allowed else "DENY"
        return f"[{self.timestamp}] {verdict} | {self.subject} → {self.action}:{self.resource} | {self.reason}"


class RBACEngine:
    """
    The enforcement engine. Holds a registry of subjects and
    evaluates access requests against their roles and permissions.

    Usage:
        engine = RBACEngine()
        engine.register(alice)
        engine.can(alice, "read", "document")
        engine.can(alice, "write", "document", context={"ip": "10.0.1.5", "time": "14:00"})
    """

    def __init__(self):
        self._subjects: dict[str, Subject] = {}
        self._audit_log: list[AccessDecision] = []

    def register(self, subject: Subject) -> None:
        """Add a subject to the engine's registry."""
        self._subjects[subject.name] = subject

    def can(self, subject: Subject, action: str, resource: str, context: dict = None) -> bool:
        """
        Core access decision function.

        Two-filter evaluation:
          1. Permission matching  — does the subject have a permission covering action + resource?
          2. Condition checking   — does that permission's conditions pass given the context?

        Returns True if at least one permission passes both filters.
        Always appends a record to the audit log with a full reason.
        """
        if context is None:
            context = {}

        permissions = subject.all_permissions()

        # Filter 1: action + resource match (supports wildcards)
        matching = [p for p in permissions if p.matches(action, resource)]

        # Filter 2: context conditions satisfied
        authorized = [p for p in matching if p.conditions_met(context)]

        if authorized:
            reason = f"matched permission(s): {', '.join(str(p) for p in authorized)}"
            decision = AccessDecision(subject.name, action, resource, True, reason)
        else:
            if matching:
                reason = f"permission exists but context conditions not met (context: {context})"
            else:
                reason = (
                    f"no permission covers {action}:{resource}. "
                    f"Subject has: {', '.join(str(p) for p in permissions) or 'none'}"
                )
            decision = AccessDecision(subject.name, action, resource, False, reason)

        self._audit_log.append(decision)
        return decision.allowed

    def audit_log(self) -> list[AccessDecision]:
        """Return a copy of the full audit log."""
        return list(self._audit_log)

    def print_audit_log(self) -> None:
        """Pretty-print the audit log to stdout."""
        if not self._audit_log:
            print("Audit log is empty.")
            return
        for entry in self._audit_log:
            print(entry)
