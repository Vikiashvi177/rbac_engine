"""
RBAC Engine - Core Data Models
-------------------------------
Defines the fundamental building blocks of the access control system:
  - Permission: a single action on a resource type
  - Role:       a named set of permissions, optionally inheriting from parent roles
  - Subject:    a user or service account assigned one or more roles
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Permission:
    """
    Represents a single allowed action on a resource type.

    Examples:
        Permission("read",   "document")
        Permission("delete", "user")
        Permission("*",      "*")          # wildcard = everything

    Conditions narrow when a permission applies:
        Permission("write", "document", conditions={"ip_prefix": "10.0.", "time_before": "17:00"})
    """
    action: str
    resource: str
    conditions: dict = field(default_factory=dict)  # empty = no restrictions

    def matches(self, action: str, resource: str) -> bool:
        """
        Check whether this permission covers the requested action + resource.
        Supports '*' as a wildcard for either field.
        Note: does NOT check conditions — that's handled separately in conditions_met().
        """
        action_match   = self.action   == "*" or self.action   == action
        resource_match = self.resource == "*" or self.resource == resource
        return action_match and resource_match

    def conditions_met(self, context: dict) -> bool:
        """
        Check whether all conditions on this permission are satisfied by the context.

        If no conditions are defined → always satisfied (no restrictions).
        If a required context key is missing → fail secure (deny).

        Supported conditions:
            ip_prefix:   context["ip"] must start with this value
            time_before: context["time"] (HH:MM) must be before this value
        """
        if not self.conditions:
            return True  # no restrictions — permission always applies

        for key, value in self.conditions.items():
            if key == "ip_prefix":
                ip = context.get("ip", "")
                if not ip.startswith(value):
                    return False
            if key == "time_before":
                time = context.get("time", "")
                if not time or time > value:
                    return False

        return True

    def __str__(self):
        if self.conditions:
            conds = ", ".join(f"{k}={v}" for k, v in self.conditions.items())
            return f"{self.action}:{self.resource} [{conds}]"
        return f"{self.action}:{self.resource}"

    def __hash__(self):
        return hash((self.action, self.resource, tuple(sorted(self.conditions.items()))))

    def __eq__(self, other):
        return (
            isinstance(other, Permission)
            and self.action == other.action
            and self.resource == other.resource
            and self.conditions == other.conditions
        )


@dataclass
class Role:
    """
    A named collection of permissions.
    Roles can inherit from a parent role — all parent permissions
    are automatically available to child roles.

    Example hierarchy:
        viewer  → [read:document]
        editor  → [write:document]  (parent: viewer)
        admin   → [delete:document] (parent: editor)

    An 'admin' therefore has: delete + write + read on document.
    """
    name: str
    permissions: set[Permission] = field(default_factory=set)
    parent: Optional["Role"]     = field(default=None, repr=False)

    def all_permissions(self, _visited=None) -> set[Permission]:
        """
        Recursively collect permissions from this role and all ancestor roles.
        This is the core of role inheritance.

        _visited tracks which roles we've already seen — detects circular inheritance.
        """
        if _visited is None:
            _visited = set()

        if self.name in _visited:
            print(f"Circular inheritance detected at role: {self.name}")
            return set()

        _visited.add(self.name)

        inherited = self.parent.all_permissions(_visited) if self.parent else set()
        return self.permissions | inherited

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, Role) and self.name == other.name


@dataclass
class Subject:
    """
    A user, service account, or any entity that requests access.
    A subject holds one or more roles.

    Example:
        alice = Subject("alice", roles={editor_role})
    """
    name: str
    roles: set[Role] = field(default_factory=set)

    def all_permissions(self) -> set[Permission]:
        """Collect every permission across all assigned roles."""
        result = set()
        for role in self.roles:
            result |= role.all_permissions()
        return result

    def __hash__(self):
        return hash(self.name)
