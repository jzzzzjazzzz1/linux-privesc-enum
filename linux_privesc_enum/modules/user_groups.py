from __future__ import annotations
import grp
import os
import pwd

from ..utils import finding
from ..watchlists import RISKY_GROUPS


def enum_current_user():
    uid = os.getuid()
    user = pwd.getpwuid(uid).pw_name
    groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
    findings = []
    risky = [g for g in groups if g.lower() in RISKY_GROUPS]
    if risky:
        findings.append(finding(
            category="group_membership",
            detail=f"User '{user}' is in privilege-relevant group(s): {', '.join(risky)}.",
            risk="HIGH",
            reference="https://gtfobins.github.io/ (search by group-relevant binary, e.g. docker)",
        ))
    return {"uid": uid, "user": user, "groups": groups}, findings
