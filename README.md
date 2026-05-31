# RBAC Policy Engine

I built this as part of my preparation for security engineering roles, specifically to get hands-on experience with access control systems

The engine answers one question: **should this person be allowed to do this, right now, from where they are?** It's not just about whether you have the right role — it also checks whether the context of your request (your IP address, the time of day) matches what the policy allows. Every decision, whether allowed or denied, gets logged with a reason.

---

## What it does

You define your access policy in a YAML file — who exists, what roles they have, what those roles can do. The engine loads that policy and enforces it. No hardcoding, no redeployment needed to change a rule.

A typical policy looks like this:

```yaml
roles:
  editor:
    parent: viewer        # editors inherit everything viewers can do
    permissions:
      - action: write
        resource: document
        conditions:
          ip_prefix: "10.0."      # corporate network only
          time_before: "17:00"    # office hours only

subjects:
  bob:
    roles:
      - editor
```

And a typical access check looks like this:

```python
engine.can(bob, "write", "document", context={"ip": "10.0.1.5", "time": "14:00"})
# → True

engine.can(bob, "write", "document", context={"ip": "192.168.1.5", "time": "14:00"})
# → False  (wrong network)
```

---

## The three building blocks

**Permissions** are the smallest unit — one action on one resource. `read:document`, `delete:report`, `*:user` (wildcard). They can optionally carry conditions that restrict when they apply, like only from a trusted IP or only during business hours.

**Roles** bundle permissions together and can form a hierarchy through inheritance. An `editor` role can inherit from `viewer`, meaning editors automatically get everything viewers can do, plus whatever the editor role adds on top. The hierarchy keeps growing — `admin` inherits from `editor`, which inherits from `viewer`, so admins get the full chain without you needing to repeat permissions.

**Subjects** are the users or service accounts making requests. They hold one or more roles, and their full set of permissions is the union of everything their roles grant, including inherited permissions all the way up the chain.

---

## How a decision gets made

Every call to `engine.can()` runs through two filters:

1. **Does the subject have a permission that covers this action and resource?** Wildcards are supported — `*:user` covers `read:user`, `delete:user`, `ban:user`, anything.

2. **If that permission has conditions, does the current context satisfy them?** If the permission requires a corporate IP and the request comes from elsewhere, it's denied even if the role would otherwise allow it.

If at least one permission passes both filters, the request is allowed. Otherwise it's denied. Either way, the decision gets written to an audit log with a full explanation — what matched, what didn't, and why.

---

## Decisions I made and why

**Deny by default.** If no permission covers what you're asking for, the answer is no. You never have to explicitly say "deny X" — absence of a rule means denial. This is the safer default for any access control system.

**Fail secure when context is missing.** If a permission has conditions but the request comes in with no context, the conditions fail and access is denied. I wanted to make sure that stripping out context headers couldn't be used to bypass restrictions.

**Union semantics for multiple roles.** If a subject has three roles and one of them covers the requested action, they're allowed — even if the other two don't cover it. Permissions are additive, not a vote.

**Two-pass YAML loading.** When building the role hierarchy from the policy file, I create all the Role objects first, then wire up the parent relationships in a second pass. This avoids the problem where a role's parent is defined later in the file — one pass would crash on that forward reference.

**Circular inheritance detection.** If role A's parent is role B and role B's parent is role A, a naive recursive implementation would loop forever. I track which roles have already been visited during recursion and bail out safely if I see a repeat, returning an empty set instead of hanging.

**Case sensitivity.** `"read"` and `"Read"` are treated as different actions. It's stricter, but predictability matters more than convenience in a security system.

---

## What this protects against — and what it doesn't

It handles unauthorized access, context bypass (the ABAC conditions), and makes every decision auditable. Role hierarchy is explicit, so there's no hidden privilege escalation through role relationships.

What it doesn't handle: if an attacker steals a valid user's credentials, the engine trusts the identity it's given and grants access normally. It also can't protect against a misconfigured policy — if someone accidentally gives the `viewer` role delete permissions, the engine will enforce that faithfully. And if an attacker can edit the YAML file directly, all bets are off. The policy file itself needs to be protected outside of this system.

---

## Running it

```bash
pip install -r requirements.txt
python main.py       # see the demo output
pytest tests/ -v     # 25 tests, all passing
```

---

## What's tested

The test suite covers the full range of expected and unexpected behavior: basic allow/deny, role inheritance chains, wildcard matching, multiple role union semantics, audit log correctness, edge cases (empty roles, no roles, duplicate role assignments, unknown actions, case sensitivity), circular inheritance safety, and all three ABAC scenarios (good context, wrong IP, and missing context entirely).

---

## Background

This project is part of a larger set of IAM-focused work I'm building toward security engineering. Related published work: *System and Method for Mitigating Cyber Attack* — Indian Patent Office, App. No. 202541075300, filed August 2025.
