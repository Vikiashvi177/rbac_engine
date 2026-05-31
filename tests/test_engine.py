"""
RBAC Engine - Test Suite
--------------------------
Run with: pytest tests/ -v

Covers:
  1.  Basic allow / deny
  2.  Role inheritance
  3.  Wildcard permissions
  4.  Multiple roles (union semantics)
  5.  Audit log correctness
  6.  Edge cases
  7.  ABAC context conditions
"""

import pytest
from rbac.models import Permission, Role, Subject
from rbac.engine import RBACEngine
from rbac.loader import load_policy


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def basic_setup():
    viewer = Role("viewer", permissions={Permission("read", "document")})
    editor = Role("editor", permissions={Permission("write", "document")}, parent=viewer)
    admin  = Role("admin",  permissions={Permission("delete", "document")}, parent=editor)

    alice = Subject("alice", roles={admin})
    bob   = Subject("bob",   roles={editor})
    carol = Subject("carol", roles={viewer})

    engine = RBACEngine()
    for s in [alice, bob, carol]:
        engine.register(s)

    return engine, alice, bob, carol


@pytest.fixture
def policy_engine():
    engine, _ = load_policy("policies/example.yaml")
    return engine


# ─── Basic allow / deny ───────────────────────────────────────────────────────

def test_viewer_can_read(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(carol, "read", "document") is True

def test_viewer_cannot_write(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(carol, "write", "document") is False

def test_editor_can_write(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(bob, "write", "document") is True

def test_editor_cannot_delete(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(bob, "delete", "document") is False


# ─── Role inheritance ────────────────────────────────────────────────────────

def test_editor_inherits_read_from_viewer(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(bob, "read", "document") is True

def test_admin_inherits_full_chain(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(alice, "read",   "document") is True
    assert engine.can(alice, "write",  "document") is True
    assert engine.can(alice, "delete", "document") is True

def test_inheritance_does_not_go_upward(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(carol, "write", "document") is False


# ─── Wildcard permissions ────────────────────────────────────────────────────

def test_wildcard_action(policy_engine):
    engine = policy_engine
    alice = engine._subjects["alice"]
    assert engine.can(alice, "read",   "user") is True
    assert engine.can(alice, "delete", "user") is True
    assert engine.can(alice, "ban",    "user") is True

def test_wildcard_resource(policy_engine):
    engine = policy_engine
    dave = engine._subjects["dave"]
    assert engine.can(dave, "read", "document") is True
    assert engine.can(dave, "read", "report")   is True
    assert engine.can(dave, "read", "invoice")  is True

def test_wildcard_does_not_grant_write(policy_engine):
    engine = policy_engine
    svc = engine._subjects["svc_account_reports"]
    assert engine.can(svc, "write", "document") is False


# ─── Multiple roles ───────────────────────────────────────────────────────────

def test_multiple_roles_union(policy_engine):
    engine = policy_engine
    dave = engine._subjects["dave"]
    assert engine.can(dave, "read", "anything") is True
    assert engine.can(dave, "write", "document") is False


# ─── Audit log ───────────────────────────────────────────────────────────────

def test_audit_log_records_decisions(basic_setup):
    engine, alice, bob, carol = basic_setup
    engine.can(carol, "read",  "document")
    engine.can(carol, "write", "document")
    assert len(engine.audit_log()) == 2

def test_audit_log_captures_allow(basic_setup):
    engine, alice, bob, carol = basic_setup
    engine.can(carol, "read", "document")
    assert engine.audit_log()[0].allowed is True

def test_audit_log_captures_deny(basic_setup):
    engine, alice, bob, carol = basic_setup
    engine.can(carol, "write", "document")
    assert engine.audit_log()[0].allowed is False

def test_audit_log_contains_reason(basic_setup):
    engine, alice, bob, carol = basic_setup
    engine.can(carol, "read",  "document")
    engine.can(carol, "write", "document")
    log = engine.audit_log()
    assert "read:document" in log[0].reason
    assert "no permission"  in log[1].reason


# ─── Edge cases ───────────────────────────────────────────────────────────────

def test_subject_with_no_roles_denied():
    engine = RBACEngine()
    subject = Subject("ghost", roles=set())
    engine.register(subject)
    assert engine.can(subject, "read", "document") is False

def test_unknown_action_is_denied(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(carol, "execute", "document") is False

def test_role_with_no_permissions_is_denied():
    engine = RBACEngine()
    empty_role = Role("empty", permissions=set())
    subject = Subject("frank", roles={empty_role})
    engine.register(subject)
    assert engine.can(subject, "read", "document") is False

def test_duplicate_roles_behave_same_as_single():
    viewer = Role("viewer", permissions={Permission("read", "document")})
    subject = Subject("frank", roles={viewer, viewer})
    engine = RBACEngine()
    engine.register(subject)
    assert engine.can(subject, "read",  "document") is True
    assert engine.can(subject, "write", "document") is False

def test_permissions_are_case_sensitive(basic_setup):
    engine, alice, bob, carol = basic_setup
    assert engine.can(carol, "Read", "document") is False

def test_permission_granted_if_any_role_covers_it():
    viewer    = Role("viewer",    permissions={Permission("read",  "document")})
    moderator = Role("moderator", permissions={Permission("flag",  "document")})
    editor    = Role("editor",    permissions={Permission("write", "document")})
    subject = Subject("tomato", roles={viewer, moderator, editor})
    engine = RBACEngine()
    engine.register(subject)
    assert engine.can(subject, "read",   "document") is True
    assert engine.can(subject, "flag",   "document") is True
    assert engine.can(subject, "write",  "document") is True
    assert engine.can(subject, "delete", "document") is False

def test_circular_inheritance_raises_or_returns_safe():
    chicken = Role("chicken", permissions={Permission("read",  "document")})
    egg     = Role("egg",     permissions={Permission("write", "document")})
    chicken.parent = egg
    egg.parent     = chicken
    result = chicken.all_permissions()
    assert isinstance(result, set)


# ─── ABAC context conditions ─────────────────────────────────────────────────

def test_abac_allow_with_good_context():
    perm    = Permission("write", "document", {"ip_prefix": "10.0.", "time_before": "17:00"})
    role    = Role("editor", permissions={perm})
    subject = Subject("bob", roles={role})
    engine  = RBACEngine()
    engine.register(subject)
    result = engine.can(subject, "write", "document", {"ip": "10.0.10.20", "time": "12:00"})
    assert result is True

def test_abac_deny_with_wrong_ip():
    perm    = Permission("write", "document", {"ip_prefix": "10.0.", "time_before": "17:00"})
    role    = Role("editor", permissions={perm})
    subject = Subject("bob", roles={role})
    engine  = RBACEngine()
    engine.register(subject)
    result = engine.can(subject, "write", "document", {"ip": "192.10.23.21", "time": "12:00"})
    assert result is False
    assert "context" in engine.audit_log()[-1].reason

def test_abac_deny_with_no_context():
    perm    = Permission("write", "document", {"ip_prefix": "10.0.", "time_before": "17:00"})
    role    = Role("editor", permissions={perm})
    subject = Subject("bob", roles={role})
    engine  = RBACEngine()
    engine.register(subject)
    result = engine.can(subject, "write", "document")
    assert result is False
    assert "context" in engine.audit_log()[-1].reason
