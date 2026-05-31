"""
RBAC Engine - Policy Loader
-----------------------------
Parses a YAML policy file into Python Role and Subject objects,
then registers all subjects into an RBACEngine instance.

This is intentionally kept simple — flat file, no database.
The point is the access control logic, not the storage layer.
"""

import yaml
from rbac.models import Permission, Role, Subject
from rbac.engine import RBACEngine


def load_policy(path: str) -> tuple:
    """
    Load a YAML policy file and return a configured RBACEngine.

    Args:
        path: path to a .yaml policy file

    Returns:
        (RBACEngine, dict[str, Role]) — engine with all subjects registered,
        and the roles dict for inspection/display.
    """
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    # --- Build roles (two-pass to handle inheritance) ---

    # First pass: create all roles without parents
    roles: dict[str, Role] = {}
    for name, config in data.get("roles", {}).items():
        permissions = set()
        for p in config.get("permissions", []):
            permissions.add(Permission(p["action"], p["resource"], p.get("conditions", {})))
        roles[name] = Role(name=name, permissions=permissions)

    # Second pass: wire up parent relationships
    # Done separately so forward references in the YAML don't cause KeyErrors
    for name, config in data.get("roles", {}).items():
        parent_name = config.get("parent")
        if parent_name:
            if parent_name not in roles:
                raise ValueError(f"Role '{name}' references unknown parent '{parent_name}'")
            roles[name].parent = roles[parent_name]

    # --- Build subjects ---
    engine = RBACEngine()

    for name, config in data.get("subjects", {}).items():
        subject_roles = set()
        for role_name in config.get("roles", []):
            if role_name not in roles:
                raise ValueError(f"Subject '{name}' references unknown role '{role_name}'")
            subject_roles.add(roles[role_name])
        subject = Subject(name=name, roles=subject_roles)
        engine.register(subject)

    return engine, roles
