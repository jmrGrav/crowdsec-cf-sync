"""TypedDict schemas for recurring data structures in crowdsec-cf-sync.

Pure typing — zero runtime cost, zero behavior change.
All types are structurally compatible with plain dict.
"""

from typing import TypedDict


class LocalBan(TypedDict):
    ip:       str
    scenario: str
    origin:   str
    dt:       str
    id:       str

class RecidivistEntry(TypedDict):
    count:     int
    last_seen: str

class ModsecEvent(TypedDict):
    ip:    str
    score: int
    uri:   str
    dt:    str

class ModsecStateEntry(TypedDict):
    banned_at: str
    score:     int
    uri:       str

class CidrStateEntry(TypedDict):
    banned_at: str
    ip_count:  int

class BouncerDenial(TypedDict):
    ip:     str
    dt:     str
    method: str
    path:   str
    host:   str

class BouncerCheckEntry(TypedDict):
    checked_at: str
    score:      int

class WalEntry(TypedDict):
    id:      int
    op:      str
    target:  str
    tag:     str
    ts:      str
    attempt: int
    dry_run: bool

class LuaBanEntry(TypedDict):
    score:  int
    level:  int
    ttl:    int
    reason: str
