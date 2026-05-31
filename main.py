"""
RBAC Engine - Demo
-------------------
Run with: python main.py

Loads the example policy and runs a set of access checks,
then prints the full audit log.
"""

from rbac.loader import load_policy


def main():
    print("=" * 60)
    print("RBAC Policy Engine — Demo")
    print("=" * 60)

    engine, roles = load_policy("policies/example.yaml")

    subjects = engine._subjects
    alice  = subjects["alice"]
    bob    = subjects["bob"]
    carol  = subjects["carol"]
    dave   = subjects["dave"]
    svc    = subjects["svc_account_reports"]
    eve    = subjects["eve"]

    # Print role hierarchy
    print("\n📋 Role hierarchy:")
    for name, role in roles.items():
        parent = f" (inherits: {role.parent.name})" if role.parent else ""
        perms  = ", ".join(str(p) for p in role.permissions)
        print(f"  {name}{parent}: [{perms}]")

    # Print subject assignments
    print("\n👤 Subject → role assignments:")
    for name, subj in subjects.items():
        role_names = ", ".join(r.name for r in subj.roles)
        print(f"  {name}: [{role_names}]")

    # Standard access checks
    print("\n🔐 Access decisions:")
    checks = [
        (carol, "read",   "document"),
        (carol, "write",  "document"),
        (bob,   "delete", "document"),
        (alice, "delete", "document"),
        (alice, "ban",    "user"),
        (dave,  "read",   "invoice"),
        (dave,  "write",  "invoice"),
        (svc,   "read",   "report"),
        (svc,   "delete", "report"),
        (eve,   "read",   "document"),
        (eve,   "flag",   "document"),
        (eve,   "hide",   "document"),
        (eve,   "write",  "document"),
    ]
    for subject, action, resource in checks:
        result = engine.can(subject, action, resource)
        verdict = "✅ ALLOW" if result else "❌ DENY "
        print(f"  {verdict}  {subject.name:6} → {action:8} {resource}")

    # ABAC context checks
    print("\n🔐 ABAC context checks (bob → write document):")
    abac_checks = [
        (bob, "write", "document", {},                                      "no context"),
        (bob, "write", "document", {"ip": "10.0.1.5", "time": "14:00"},    "good context"),
        (bob, "write", "document", {"ip": "192.168.1.5", "time": "14:00"}, "wrong ip"),
        (bob, "write", "document", {"ip": "10.0.1.5", "time": "22:00"},    "after hours"),
    ]
    for subject, action, resource, context, label in abac_checks:
        result = engine.can(subject, action, resource, context)
        verdict = "✅ ALLOW" if result else "❌ DENY "
        print(f"  {verdict}  [{label}]")

    # Full audit log
    print("\n📜 Full audit log:")
    engine.print_audit_log()


if __name__ == "__main__":
    main()
