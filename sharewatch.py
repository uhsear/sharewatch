#!/usr/bin/env python
"""Diff an ArcGIS organization's sharing posture against yesterday, and report what widened.

ArcGIS Online keeps no sharing audit log. When an internal layer turns up public,
the portal can tell you that it is public right now and nothing else: not when it
changed, not who changed it, not what else moved at the same time. The item's
modified date is the only trace, and the next edit overwrites it.

This writes a snapshot of every item's access, every item's group membership and
every group's membershipAccess, then compares two snapshots and ranks what
changed. Items going public outrank items joining a group. Nine items that one
owner pushed public in the same ten minutes are ONE event listing nine items,
because that is one mistake, not nine.

It is read-only. There is no flag that changes sharing, and the only thing it
writes is a snapshot file, which needs --apply.

The mirror mode compares two portals instead of two mornings. After a cutover a
share call can answer HTTP 200 with notSharedWith and still not have shared, and
an empty groups value shares with nothing and reports no error. Mirror reads
what each portal holds now and reports where the new one differs, widest
first. --verify-host names the host the new portal must be on, and the run is
refused if the urls, the portal's own portals/self answer or a redirect say
otherwise. Mirror writes nothing, not even with --apply.

    python sharewatch.py --self-test
    python sharewatch.py snapshot --url https://county.maps.arcgis.com --out snaps/ --apply
    python sharewatch.py diff snaps/sharewatch-20260914T060000Z.json snaps/sharewatch-20260915T060000Z.json
    python sharewatch.py watch --url https://county.maps.arcgis.com --dir snaps/ --apply
    python sharewatch.py mirror --old-url https://old.example.org --new-url https://new.example.org --verify-host new.example.org

Exit codes: 0 no differences, 1 anything to read (a narrowing or a deletion is
a difference too), 2 the portal call failed or a mirror host proof failed, 3 no
differences found but the read could not prove it (a snapshot cut short, read
without a token, or empty), 64 usage error.
"""

from __future__ import print_function

import argparse
import contextlib
import datetime
import getpass
import http.server
import io
import json
import os
import runpy
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

# =============================================================================
# CONFIGURATION. Deliberately not flags. Change here, not at the call site.
# =============================================================================

# Minutes within which changes of the same kind by the same owner collapse into
# one event. A bulk share is a handful of clicks over a couple of minutes. An
# hour is wide enough to catch a slow one, and narrow enough that two unrelated
# mistakes on the same day stay two events.
DEFAULT_WINDOW_MINUTES = 60

# The server caps num on /sharing/rest/search whatever you ask for. Asking for
# 1000 does not fail. It silently returns 100, which is how a paging loop that
# trusts its own num walks past 90 percent of an organization.
SEARCH_MAX_NUM = 100

# search reports total accurately only to 10,000. At or above that the count is
# an estimate and the tail cannot be paged to, so a snapshot that reaches it
# covers an unknown fraction of the org and has to say so.
SEARCH_CEILING = 10000

# Seconds before a portal call is abandoned.
HTTP_TIMEOUT = 60

# What replaces a secret anywhere it could otherwise be printed.
REDACTED = "[redacted]"

# Environment variable the password is read from. It is never a command line
# flag: argv is readable by every process on the box, and it lands in shell
# history, in scheduler logs and in this tool's own error messages.
SECRET_ENV = "SHAREWATCH_PASSWORD"

# The same rule for the two sides of a mirror comparison. Two portals have two
# accounts, so a single variable would sign one of them in with the other's
# password.
SECRET_ENV_OLD = "SHAREWATCH_OLD_PASSWORD"
SECRET_ENV_NEW = "SHAREWATCH_NEW_PASSWORD"

# A token has the same exposure as a password, so it can come from the
# environment as well as from --token. SSO and SAML accounts cannot use
# generateToken, and for them a token is the only way in.
TOKEN_ENV = "SHAREWATCH_TOKEN"
TOKEN_ENV_OLD = "SHAREWATCH_OLD_TOKEN"
TOKEN_ENV_NEW = "SHAREWATCH_NEW_TOKEN"

# =============================================================================
# End of CONFIGURATION.
# =============================================================================

# Sharing levels, ordered. "shared" is an item shared to groups but not to the
# organization, which the REST API reports as its own access value.
ACCESS_RANK = {"private": 0, "shared": 1, "org": 2, "public": 3}

# The keys that make a saved share answer readable. One of them has to be there.
SHARE_KEYS = ("notSharedWith", "success", "error")

# Severity per finding kind. The ordering is the point of the tool: an operator
# who reads only the top three lines must see the worst thing that happened.
SEVERITY = {
    "item-public": 100,       # an existing item became visible to anyone
    "group-public": 90,       # a group became public, taking its contents along
    "new-item-public": 85,    # an item arrived already public
    "item-org": 60,           # private or group-only became org-wide
    "group-org": 55,          # a private group became org-wide
    "item-joined-group": 40,  # an item was added to a group
    "new-item": 25,
    "item-deleted": 20,
    "item-left-group": 15,
    "item-narrowed": 10,      # sharing was reduced. Recorded, not alarming.
    "group-narrowed": 10,
    # mirror: the new portal compared with the old one. Wider than the old
    # portal is the dangerous direction, narrower is only a broken link.
    "mirror-public": 95,      # public on the new portal, not public on the old
    "mirror-notshared": 80,   # a share call came back 200 and did not share
    "mirror-wider": 65,       # wider than the old portal, short of public
    "mirror-narrower": 50,    # narrower than the old portal: users lose access
    "mirror-no-group": 48,    # the old item's group does not exist on the new portal
    "mirror-missing": 45,     # an old item with no counterpart on the new portal
    "mirror-group-lost": 45,  # in a group on the old portal, not on the new one
    "mirror-group-extra": 35,  # in a group on the new portal, not on the old one
    "mirror-new-public": 30,  # public on the new portal and not on the old at all
    "mirror-new-shared": 28,  # org or group shared on the new portal, absent on the old
    "mirror-ambiguous": 30,   # two items share a title and type, so no pairing
}

# Kinds whose timestamp is not evidence of when the change happened, so they are
# collapsed per owner without a time window. A deleted item leaves no deletion
# date behind, only the modified date it had while it existed, and adding an item
# to a group does not bump modified at all. Bucketing either one by time splits
# a single bulk action into one event per item: 60 items deleted in one go were
# reported as 60 events, dated by edits years apart. Every mirror kind is
# untimed too: two portals are compared as they are now, and the modified date
# of an item says nothing about when somebody forgot to share it.
UNTIMED_KINDS = frozenset(["item-deleted", "item-joined-group", "item-left-group",
                           "mirror-public", "mirror-notshared", "mirror-wider",
                           "mirror-narrower", "mirror-no-group", "mirror-missing",
                           "mirror-group-lost", "mirror-group-extra",
                           "mirror-new-public", "mirror-new-shared",
                           "mirror-ambiguous"])

SNAPSHOT_PREFIX = "sharewatch-"
SNAPSHOT_SUFFIX = ".json"


# ----------------------------------------------------------------- pure core

def access_rank(access):
    """Order a sharing level so two levels can be compared.

    An unknown value raises instead of sorting to zero. A portal release that
    adds a level must not make every item look private, and so look safe.
    """
    if access not in ACCESS_RANK:
        raise ValueError("unknown access level %r" % (access,))
    return ACCESS_RANK[access]


def widened(old_access, new_access):
    """True when sharing got broader. Equal or narrower is False."""
    return access_rank(new_access) > access_rank(old_access)


def clamp_num(num):
    """Clamp a page size to what the server will actually honour."""
    if num < 1:
        raise ValueError("page size must be at least 1, got %r" % (num,))
    return min(num, SEARCH_MAX_NUM)


def next_start(start, returned, total):
    """The 1-based start of the next page, or None when there is no next page.

    Paging stops at SEARCH_CEILING as well as at total, because search will not
    return results past it. Walking off the end gives None rather than a start
    the server rejects.
    """
    if start < 1:
        raise ValueError("start is 1-based, got %r" % (start,))
    if returned <= 0:
        return None
    nxt = start + returned
    if nxt > total or nxt > SEARCH_CEILING:
        return None
    return nxt


def is_truncated(total):
    """True when the reported total has reached the 10,000 ceiling.

    At the ceiling the number is an estimate and the tail is unreachable, so the
    snapshot covers an unknown fraction of the org. Narrow the query instead.
    """
    return total >= SEARCH_CEILING


def is_http_url(url):
    """True when urllib will actually open this url.

    A url typed without its scheme is the common mistake, and urllib answers it
    by raising an exception that quotes the whole url back, query string and
    token included. Refusing the url up front is what stops a token reaching a
    scheduler log.
    """
    return bool(url) and url.lower().startswith(("http://", "https://"))


def printable(text, encoding):
    """Make one line safe for a console that cannot encode it.

    ArcGIS Pro runs on Windows, where stdout is cp1252 unless somebody changed
    it, and one item whose title held a character that code page has no room
    for aborted the whole report with UnicodeEncodeError halfway down the
    findings. A replaced character loses a letter; the crash lost every finding
    under it.
    """
    if not encoding:
        return text
    try:
        text.encode(encoding)
    except UnicodeEncodeError:
        return text.encode(encoding, "replace").decode(encoding, "replace")
    except LookupError:
        return text
    return text


def truncation_warning(old, new, labels=("older", "newer")):
    """Lines warning that a snapshot in this diff is incomplete.

    A truncated snapshot holds an unknown subset of the org, so every item the
    other snapshot has and this one lacks reads as a deletion. That is the false
    clean day running backwards: instead of hiding 60 deletions it invents
    thousands. The diff still runs, because the widenings in it are real.
    A snapshot is also incomplete when paging gave back fewer items than the
    portal reported, which is not the ceiling and is worded differently.
    """
    lines = []
    for label, snapshot in zip(labels, (old, new)):
        if not snapshot.get("truncated"):
            continue
        if snapshot.get("reported_total", 0) >= SEARCH_CEILING:
            lines.append("WARNING: the %s snapshot reached the %d result "
                         "ceiling." % (label, SEARCH_CEILING))
        else:
            lines.append("WARNING: the %s snapshot holds %d of the %d item(s) "
                         "the portal reported." % (
                             label, len(snapshot.get("items", {})),
                             snapshot.get("reported_total", 0)))
    if lines:
        lines.append("It covers an unknown fraction of the org, so deletions "
                     "and new items below may")
        lines.append("be paging artefacts. Narrow --query and snapshot again.")
    return lines


def coverage_gaps(old, new, labels=("older", "newer"),
                  empty="the %s snapshot holds no items"):
    """Why a result with no findings cannot be called clean, as short phrases.

    A snapshot cut short or read without a token holds only part of the org, so
    two of them can agree and still hide a widening. "Nothing found" is not
    "nothing there" until both reads were whole. A snapshot with no items at all
    is the extreme case: a mistyped query or an account that sees nothing reads
    the same way every day and would otherwise report a quiet org forever.
    """
    gaps = []
    for label, snapshot in zip(labels, (old, new)):
        if not snapshot.get("items"):
            gaps.append(empty % label)
        if snapshot.get("truncated"):
            gaps.append("the %s snapshot is incomplete" % label)
        if snapshot.get("anonymous"):
            gaps.append("the %s snapshot was read without a token and holds "
                        "public items only" % label)
    return gaps


def verdict_text(gaps, clean):
    """The closing line when nothing was found: the clean sentence, or why not."""
    if not gaps:
        return clean
    return "Cannot tell whether anything changed: %s." % "; ".join(gaps)


def exit_code(events, incomplete=False):
    """1 when there is anything to read, 3 when there is not but the read was
    incomplete, 0 when there is nothing and the read was whole."""
    if events:
        return 1
    return 3 if incomplete else 0


def redact(text, *secrets):
    """Remove secrets from anything about to be printed or written.

    urllib repeats the request in some error messages and generateToken is a
    POST, so an unredacted traceback is a password in a log file.
    """
    out = "%s" % (text,)
    for secret in secrets:
        if secret:
            # Coerced because this runs inside an exception handler. A secret
            # that arrived as anything but a string used to raise TypeError
            # here, which threw away the redaction along with the error.
            raw = "%s" % (secret,)
            # urlencode percent-encodes + / = and the like, and urllib quotes
            # the encoded url back in a redirect or InvalidURL error.
            for form in (raw, urllib.parse.quote_plus(raw),
                         urllib.parse.quote(raw, safe="")):
                out = out.replace(form, REDACTED)
    return out


def item_record(raw):
    """Keep the sharing-relevant fields of a search result and drop the rest.

    A snapshot is a file that sits in a folder for months. It holds what the
    diff needs and nothing else: no token, no service URL with a token in it,
    no description long enough to be worth a public records request.
    """
    return {
        "id": raw.get("id"),
        "title": raw.get("title") or "",
        "owner": raw.get("owner") or "",
        "type": raw.get("type") or "",
        "access": raw.get("access") or "private",
        "modified": int(raw.get("modified") or 0),
        "groups": [],
    }


def group_record(raw):
    """Keep the sharing-relevant fields of a group.

    membershipAccess is null on a group that anyone in the org may join, which
    is the permissive case. It is stored as "org" rather than left null and read
    back later as "restricted".
    """
    return {
        "id": raw.get("id"),
        "title": raw.get("title") or "",
        "owner": raw.get("owner") or "",
        "access": raw.get("access") or "private",
        "membershipAccess": raw.get("membershipAccess") or "org",
    }


def build_snapshot(url, taken, items, groups, total, truncated, anonymous=False):
    """Assemble the snapshot document. No credential ever enters it.

    "anonymous" is written only when true, so a snapshot read with a token has
    the same bytes as before the key existed.
    """
    snapshot = {
        "sharewatch": 1,
        "url": url,
        "taken": taken,
        "reported_total": total,
        "truncated": bool(truncated),
        "items": items,
        "groups": groups,
    }
    if anonymous:
        snapshot["anonymous"] = True
    return snapshot


def items_in_group(snapshot, group_id):
    """How many items in this snapshot sit inside the given group.

    A group going public is only as serious as what is in it, so the count
    travels with the finding. "A group became public" without the count makes an
    empty staging group read like an incident.
    """
    return sum(1 for it in snapshot.get("items", {}).values()
               if group_id in (it.get("groups") or []))


def utcnow():
    """UTC now, without datetime.utcnow().

    utcnow() is deprecated from 3.12 and datetime.UTC does not exist before
    3.11, so timezone.utc is the spelling that works on ArcGIS Pro's Python and
    on a current python3 alike.
    """
    return datetime.datetime.now(datetime.timezone.utc)


def snapshot_name(when):
    """File name for a snapshot taken at this UTC time.

    The timestamp is in the name and sorts lexically, so finding yesterday's
    snapshot needs no file metadata, which copying a folder destroys.
    """
    return "%s%s%s" % (SNAPSHOT_PREFIX, when.strftime("%Y%m%dT%H%M%SZ"),
                       SNAPSHOT_SUFFIX)


def newest_snapshot(names):
    """The newest sharewatch snapshot in a list of file names, or None.

    Anything not named like a snapshot is ignored, because a folder of
    snapshots also collects the report text somebody saved next to them.
    """
    candidates = [n for n in names
                  if n.startswith(SNAPSHOT_PREFIX) and n.endswith(SNAPSHOT_SUFFIX)]
    if not candidates:
        return None
    return sorted(candidates)[-1]


class Event(object):
    """One reportable change, which may cover many items."""

    def __init__(self, kind, owner, detail, items, group=None, group_title=None,
                 item_count=None, when=0):
        self.kind = kind
        self.severity = SEVERITY[kind]
        self.owner = owner
        self.detail = detail
        self.items = items
        self.group = group
        self.group_title = group_title
        self.item_count = item_count
        self.when = when

    def __repr__(self):
        return "Event(%s, owner=%r, items=%d)" % (
            self.kind, self.owner, len(self.items))


def _finding(kind, item, detail, group=None):
    return {
        "kind": kind,
        "owner": item.get("owner", ""),
        "detail": detail,
        "item": item,
        "group": group,
        "when": int(item.get("modified") or 0),
    }


def _bucket(findings, window_ms):
    """Split findings already sharing a kind and an owner into time windows.

    Greedy from the earliest modified date. Two separate mistakes a week apart
    stay two events; nine clicks in ten minutes become one.
    """
    buckets = []
    current = []
    for f in sorted(findings, key=lambda f: f["when"]):
        if current and f["when"] - current[0]["when"] > window_ms:
            buckets.append(current)
            current = []
        current.append(f)
    if current:
        buckets.append(current)
    return buckets


def collapse(findings, window_minutes=DEFAULT_WINDOW_MINUTES):
    """Turn per-item findings into events, merging a bulk share into one.

    The merge key is kind, owner, the exact change and the group involved. Two
    owners who both went public in the same hour stay two events, because two
    people made two decisions and both need asking.
    """
    if window_minutes < 0:
        raise ValueError("--window-minutes cannot be negative")
    window_ms = window_minutes * 60 * 1000
    keyed = {}
    order = []
    for f in findings:
        key = (f["kind"], f["owner"], f["detail"], f["group"])
        if key not in keyed:
            keyed[key] = []
            order.append(key)
        keyed[key].append(f)

    events = []
    for key in order:
        kind, owner, detail, group = key
        if kind in UNTIMED_KINDS:
            buckets = [keyed[key]]
        else:
            buckets = _bucket(keyed[key], window_ms)
        for bucket in buckets:
            events.append(Event(
                kind, owner, detail,
                items=[f["item"] for f in bucket],
                group=group,
                when=bucket[0]["when"],
            ))
    return events


def diff_snapshots(old, new, window_minutes=DEFAULT_WINDOW_MINUTES):
    """Compare two snapshots and return events, worst first.

    The item loop walks the UNION of both snapshots, not the intersection. An
    early version iterated the ids present in both, which made a day with 60
    deletions and a fresh public item report perfectly clean.
    """
    old_items = old.get("items", {})
    new_items = new.get("items", {})
    old_groups = old.get("groups", {})
    new_groups = new.get("groups", {})

    findings = []

    for iid in sorted(new_items):
        new_item = new_items[iid]
        old_item = old_items.get(iid)

        if old_item is None:
            kind = ("new-item-public" if new_item.get("access") == "public"
                    else "new-item")
            findings.append(_finding(kind, new_item,
                                     "new item, shared %s"
                                     % new_item.get("access")))
            continue

        old_access = old_item.get("access", "private")
        new_access = new_item.get("access", "private")
        if old_access != new_access:
            detail = "%s -> %s" % (old_access, new_access)
            if widened(old_access, new_access):
                kind = "item-public" if new_access == "public" else "item-org"
            else:
                kind = "item-narrowed"
            findings.append(_finding(kind, new_item, detail))

        was = set(old_item.get("groups") or [])
        now = set(new_item.get("groups") or [])
        for gid in sorted(now - was):
            findings.append(_finding("item-joined-group", new_item,
                                     "joined group", group=gid))
        for gid in sorted(was - now):
            findings.append(_finding("item-left-group", new_item,
                                     "left group", group=gid))

    # The other half of the union. An id that vanished is a deletion, and a
    # deletion is not a clean day.
    for iid in sorted(old_items):
        if iid not in new_items:
            findings.append(_finding("item-deleted", old_items[iid],
                                     "deleted or transferred out of the org"))

    events = collapse(findings, window_minutes)

    # Groups are diffed separately. They are never collapsed: a group widening
    # is one decision about one container, and merging two of them would hide
    # the item count that makes each one readable.
    for gid in sorted(new_groups):
        new_group = new_groups[gid]
        old_group = old_groups.get(gid)
        if old_group is None:
            # A group created public between two snapshots widened sharing just
            # as much as one that was flipped public. Without this the items in
            # it report only as item-joined-group at severity 40, and the thing
            # that actually exposed them never appears in the report.
            if new_group.get("access") == "public":
                events.append(Event(
                    "group-public", new_group.get("owner", ""),
                    "new group, shared public", items=[], group=gid,
                    group_title=new_group.get("title", ""),
                    item_count=items_in_group(new, gid)))
            continue
        changes = []
        old_access = old_group.get("access", "private")
        new_access = new_group.get("access", "private")
        if old_access != new_access:
            if widened(old_access, new_access):
                kind = "group-public" if new_access == "public" else "group-org"
            else:
                kind = "group-narrowed"
            changes.append((kind, "group access %s -> %s"
                            % (old_access, new_access)))
        old_join = old_group.get("membershipAccess", "org")
        new_join = new_group.get("membershipAccess", "org")
        if old_join != new_join and new_join == "org":
            changes.append(("group-org", "membershipAccess %s -> %s"
                            % (old_join, new_join)))
        for kind, detail in changes:
            events.append(Event(
                kind, new_group.get("owner", ""), detail, items=[],
                group=gid, group_title=new_group.get("title", ""),
                item_count=items_in_group(new, gid),
            ))

    return rank_events(events)


def rank_events(events):
    """Sort events worst first, then by the biggest blast radius.

    The top line is the line to act on. The owner and kind tail-break only to
    keep the order stable.
    """
    events.sort(key=lambda e: (-e.severity,
                               -(e.item_count or len(e.items)),
                               e.owner, e.kind))
    return events


def describe(events, quiet="No sharing changes between the two snapshots."):
    """Render events as the lines the CLI prints."""
    if not events:
        return [quiet]
    out = []
    for ev in events:
        if ev.item_count is not None:
            out.append("[%3d] %-18s %s: %s (%d item(s) inside)"
                       % (ev.severity, ev.kind, ev.group_title or ev.group,
                          ev.detail, ev.item_count))
        else:
            out.append("[%3d] %-18s %d item(s) by %s: %s"
                       % (ev.severity, ev.kind, len(ev.items),
                          ev.owner or "(unknown)", ev.detail))
        for item in ev.items[:20]:
            out.append("        - %s (%s) %s"
                       % (item.get("title"), item.get("type"), item.get("id")))
        if len(ev.items) > 20:
            out.append("        - ... and %d more" % (len(ev.items) - 20))
    return out


# ------------------------------------------------------------ mirror: the core

def host_of(url):
    """The lower-case host name of a url, without port, or "" when it has none."""
    return urllib.parse.urlparse(url or "").hostname or ""


def check_hosts(old_url, new_url, verify_host):
    """Refuse a mirror run that could read the old portal as the new one.

    --verify-host names the host the operator believes the NEW portal is on.
    The comparison is only worth anything if the new side really is that host,
    and the old side really is another: a cutover script that was pointed at
    the old portal twice reports a perfect mirror. Returns the host, normalised.
    """
    host = (verify_host or "").strip().lower()
    if not host or "/" in host or ":" in host:
        raise ValueError("--verify-host takes a bare host name such as "
                         "gis.example.org, got %r" % (verify_host,))
    if host_of(new_url) != host:
        raise ValueError("--new-url is on host %r, not the verified host %r"
                         % (host_of(new_url), host))
    if host_of(old_url) == host:
        raise ValueError("--old-url is on the verified host %r too, so this "
                         "run would compare the new portal with itself" % host)
    return host


def declared_hosts(body):
    """The host names a portal says it has, from its own portals/self answer.

    The url that answered is only what the operator typed. The portal's
    portalHostname, or urlKey plus customBaseUrl on an organization, is what it
    says it is. A DNS alias or a reverse proxy left pointing at the old portal
    answers on the new host name and declares the old one.
    """
    hosts = set()
    name = body.get("portalHostname")
    if name:
        hosts.add(str(name).split("://")[-1].split("/")[0].split(":")[0].lower())
    if body.get("urlKey") and body.get("customBaseUrl"):
        hosts.add(("%s.%s" % (body["urlKey"], body["customBaseUrl"])).lower())
    return hosts


class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect that leaves the host this opener was pinned to.

    A 302 from the new portal to the old one would be followed silently, and
    every later answer would be the old portal's under the new portal's name.
    """

    def __init__(self, host):
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if host_of(newurl) != self.host:
            raise urllib.error.URLError(
                "redirect to %s leaves the verified host %s"
                % (newurl, self.host))
        return urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl)


def _norm(text):
    """Title text as compared across portals: trimmed, case ignored."""
    return ("%s" % (text or "")).strip().lower()


def _item_groups(snapshot, item):
    """{normalised title: title} of the groups an item is in, in this snapshot."""
    groups = snapshot.get("groups", {})
    out = {}
    for gid in item.get("groups") or []:
        title = (groups.get(gid) or {}).get("title") or gid
        out[_norm(title)] = title
    return out


def _by_key(snapshot):
    """Items grouped by (title, type), the only key two portals share.

    Item ids do not survive a copy to another portal, so the id cannot pair
    them. Two items with one title and type on a side are kept together, and
    the caller refuses to guess which is which.
    """
    keyed = {}
    for iid in sorted(snapshot.get("items", {})):
        item = snapshot["items"][iid]
        keyed.setdefault((_norm(item.get("title")), item.get("type") or ""),
                         []).append(item)
    return keyed


def mirror_diff(old, new, window_minutes=DEFAULT_WINDOW_MINUTES):
    """Compare the sharing of the old portal with the new one.

    Returns (events, stats), events worst first. Items are paired by title and
    type. Wider on the new portal is reported before narrower, because a cutover
    that exposes something is worse than one that breaks a link. Nothing is
    guessed: a title that two items share on either side is reported, not paired.
    """
    old_keyed, new_keyed = _by_key(old), _by_key(new)
    new_titles = set(_norm(g.get("title") or gid)
                     for gid, g in new.get("groups", {}).items())
    stats = {"paired": 0, "old_only": 0, "new_only": 0, "ambiguous": 0}
    findings = []
    for key in sorted(set(old_keyed) | set(new_keyed)):
        olds, news = old_keyed.get(key, []), new_keyed.get(key, [])
        if not olds:
            stats["new_only"] += len(news)
            for it in news:
                level = it.get("access", "private")
                if access_rank(level) == 0:
                    continue
                # An item the old account cannot see also has no old
                # counterpart, so a non-private one is reported, not counted.
                kind = ("mirror-new-public" if level == "public"
                        else "mirror-new-shared")
                findings.append(_finding(
                    kind, it, "%s on the new portal, not on the old one at "
                    "all (or hidden from the old account)"
                    % ("public" if level == "public" else level)))
            continue
        if not news:
            stats["old_only"] += len(olds)
            for it in olds:
                shared = it.get("access") or "private"
                findings.append(_finding(
                    "mirror-missing", it, "%s on the old portal, absent on the "
                    "new one" % (shared if shared == "private"
                                 else "shared " + shared)))
            continue
        if len(olds) > 1 or len(news) > 1:
            stats["ambiguous"] += len(news)
            for it in news:
                findings.append(_finding(
                    "mirror-ambiguous", it,
                    "%d old and %d new items share this title and type, so "
                    "none was compared" % (len(olds), len(news))))
            continue
        stats["paired"] += 1
        was, now = olds[0], news[0]
        old_access = was.get("access", "private")
        new_access = now.get("access", "private")
        if access_rank(new_access) > access_rank(old_access):
            kind = "mirror-public" if new_access == "public" else "mirror-wider"
            findings.append(_finding(kind, now, "old %s, new %s"
                                     % (old_access, new_access)))
        elif access_rank(new_access) < access_rank(old_access):
            findings.append(_finding("mirror-narrower", now, "old %s, new %s"
                                    % (old_access, new_access)))
        had, has = _item_groups(old, was), _item_groups(new, now)
        for norm in sorted(set(had) - set(has)):
            kind = ("mirror-group-lost" if norm in new_titles
                    else "mirror-no-group")
            findings.append(_finding(kind, now, "group '%s'" % had[norm]))
        for norm in sorted(set(has) - set(had)):
            findings.append(_finding("mirror-group-extra", now,
                                     "group '%s'" % has[norm]))
    events = collapse(findings, window_minutes)
    events.extend(_group_events(old, new))
    return rank_events(events), stats


def _groups_by_title(snapshot):
    """Groups of a snapshot as {normalised title: [(id, group)]}, in id order."""
    keyed = {}
    for gid in sorted(snapshot.get("groups", {})):
        group = snapshot["groups"][gid]
        keyed.setdefault(_norm(group.get("title") or gid), []).append(
            (gid, group))
    return keyed


def _group_events(old, new):
    """Events for a group whose own sharing differs between the portals.

    Items in a public group are visible to anyone, so a group that is private
    on the old portal and public on the new one exposes its contents however
    the items themselves are shared. Groups are paired by title like items, and
    a title that two groups share on either side is not guessed: it is reported
    as ambiguous, because a skip that says nothing reads as "nothing changed".
    Narrowing of membershipAccess is not reported, as in the single-portal diff.
    """
    old_by, new_by = _groups_by_title(old), _groups_by_title(new)
    events = []
    for norm in sorted(set(old_by) & set(new_by)):
        if len(old_by[norm]) > 1 or len(new_by[norm]) > 1:
            events.append(Event(
                "mirror-ambiguous", "", "%d old and %d new groups share this "
                "title, so none was compared" % (len(old_by[norm]),
                                                 len(new_by[norm])),
                items=[], group=new_by[norm][0][0],
                group_title=new_by[norm][0][1].get("title", ""),
                item_count=sum(items_in_group(new, g) for g, _ in new_by[norm])))
            continue
        was, (gid, now) = old_by[norm][0][1], new_by[norm][0]
        changes = []
        old_access = was.get("access", "private")
        new_access = now.get("access", "private")
        if access_rank(new_access) > access_rank(old_access):
            changes.append(("mirror-public" if new_access == "public"
                            else "mirror-wider",
                            "group access old %s, new %s"
                            % (old_access, new_access)))
        elif access_rank(new_access) < access_rank(old_access):
            changes.append(("mirror-narrower", "group access old %s, new %s"
                            % (old_access, new_access)))
        old_join = was.get("membershipAccess", "org")
        new_join = now.get("membershipAccess", "org")
        if old_join != new_join and new_join == "org":
            changes.append(("mirror-wider", "group membershipAccess old %s, "
                            "new %s" % (old_join, new_join)))
        for kind, detail in changes:
            events.append(Event(
                kind, now.get("owner", ""), detail, items=[], group=gid,
                group_title=now.get("title", ""),
                item_count=items_in_group(new, gid)))
    return events


def share_results(bodies):
    """Flatten saved share answers to one dict per item, or refuse them.

    A batch answer carries one object per item under "results". A top-level
    notSharedWith, success or error next to that list is read as well. An
    answer with none of the three keys, or with a success that is not a JSON
    boolean, is refused: the tool cannot tell what it means, and reading it as
    "nothing wrong" is how a bad file passed as a clean one.
    """
    results = []
    for body in bodies:
        if not isinstance(body, dict):
            raise ValueError("a share response has to be a JSON object, got %s"
                             % type(body).__name__)
        if isinstance(body.get("results"), list):
            results.extend(body["results"])
            if any(key in body for key in SHARE_KEYS):
                results.append(body)
        else:
            results.append(body)
    for res in results:
        if not isinstance(res, dict):
            raise ValueError("a share response has to be a JSON object, got %s"
                             % type(res).__name__)
        if not any(key in res for key in SHARE_KEYS):
            raise ValueError("a share response has none of %s, so it cannot "
                             "be read" % ", ".join(SHARE_KEYS))
        if "success" in res and not isinstance(res["success"], bool):
            raise ValueError("a share response 'success' has to be true or "
                             "false, got %r" % (res["success"],))
    return results


def share_response_findings(bodies, new):
    """Findings for share calls that came back 200 and did not share.

    A share call answers HTTP 200 whatever happened. The groups it could not
    share with are listed in notSharedWith, and a script that checks only the
    status counts the item done. A batch answer carries one such object per
    item under "results". An empty groups value shares with no group at all and
    reports nothing wrong, so it is invisible here and only mirror_diff sees it.
    """
    findings = []
    for res in share_results(bodies):
        iid = res.get("itemId") or ""
        item = new.get("items", {}).get(iid) or {
            "id": iid, "title": "(not in the new snapshot)", "owner": "",
            "type": "", "modified": 0}
        err = res.get("error")
        if isinstance(err, dict):
            detail = "share call failed: %s %s" % (err.get("code"),
                                                   err.get("message"))
        elif err:
            detail = "share call failed: %s" % (err,)
        elif res.get("notSharedWith"):
            skipped = res["notSharedWith"]
            if not isinstance(skipped, list):
                skipped = [skipped]
            detail = "share call returned 200 but not shared with %s" % (
                ", ".join(sorted("%s" % g for g in skipped)))
        elif res.get("success") is False:
            detail = "share call reported success false"
        else:
            continue
        findings.append(_finding("mirror-notshared", item, detail))
    return collapse(findings)


# ---------------------------------------------------------------- portal i/o

def _opener(insecure, pin_host=None):
    """Build a urllib opener, optionally without certificate verification.

    Enterprise portals behind an internal CA are the reason --insecure exists.
    It is off by default and refused together with a password, because posting
    credentials down an unverified connection is the failure it would cause.
    With pin_host the opener also refuses to follow a redirect to another host.
    """
    handlers = []
    if pin_host:
        handlers.append(_PinnedRedirect(pin_host))
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def _call(url, path, params, insecure=False, post=False, secret=None,
          pin_host=None):
    """One REST call returning parsed JSON, with the portal's own errors raised.

    The portal answers HTTP 200 with an error object in the body, so the status
    code proves nothing and the body has to be read every time.
    """
    params = dict(params)
    params["f"] = "json"
    endpoint = "%s/sharing/rest/%s" % (url.rstrip("/"), path.lstrip("/"))
    data = urllib.parse.urlencode(params).encode("utf-8")
    opener = _opener(insecure, pin_host)
    try:
        if post:
            response = opener.open(endpoint, data, timeout=HTTP_TIMEOUT)
        else:
            response = opener.open("%s?%s" % (endpoint, data.decode("utf-8")),
                                   timeout=HTTP_TIMEOUT)
        body = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        # Every credential this request carried, not only the caller's secret.
        # urllib quotes the full url back for a scheme-less --url, and that url
        # carries the token, so one typo used to print a live token to stderr.
        raise RuntimeError(redact("%s: %s" % (endpoint, exc), secret,
                                  params.get("token"), params.get("password")))
    if not isinstance(body, dict):
        raise RuntimeError(redact("%s: the answer was JSON but not an object"
                                  % endpoint, secret, params.get("token"),
                                  params.get("password")))
    if "error" in body:
        err = body["error"]
        if isinstance(err, dict):
            what = "%s %s" % (err.get("code"), err.get("message"))
        else:
            what = "%s" % (err,)
        raise RuntimeError(redact("%s: %s" % (endpoint, what), secret,
                                  params.get("token"), params.get("password")))
    return body


def read_secret(username, env=SECRET_ENV):
    """Get the password from the environment, or prompt for it.

    Never from argv. getpass keeps it off the screen, and it is passed on to
    redact() so that nothing downstream can print it back out.
    """
    secret = os.environ.get(env)
    if secret:
        return secret
    return getpass.getpass("password for %s (not echoed): " % username)


def generate_token(url, username, secret, insecure=False, pin_host=None):
    """Exchange a username and password for a short-lived token."""
    body = _call(url, "generateToken", {
        "username": username,
        "password": secret,
        "client": "referer",
        "referer": url,
        "expiration": 60,
    }, insecure=insecure, post=True, secret=secret, pin_host=pin_host)
    token = body.get("token")
    if not token:
        raise RuntimeError("generateToken returned no token")
    return token


def portal_self(url, token, insecure=False, pin_host=None):
    """The portal's own description of itself: its org id and its host names."""
    params = {"token": token} if token else {}
    return _call(url, "portals/self", params, insecure=insecure,
                 pin_host=pin_host)


def org_id(url, token, insecure=False, pin_host=None):
    return portal_self(url, token, insecure, pin_host).get("id")


def search_items(url, query, token, insecure=False, echo=None, pin_host=None):
    """Page /sharing/rest/search and return (items, reported total, truncated).

    num is clamped before it is sent, because the server clamps it silently and
    a loop that advances by its own num instead of by the rows it got back skips
    everything between.
    """
    items = {}
    start = 1
    total = 0
    while start is not None:
        params = {"q": query, "start": start, "num": clamp_num(SEARCH_MAX_NUM),
                  "sortField": "modified", "sortOrder": "desc"}
        if token:
            params["token"] = token
        body = _call(url, "search", params, insecure=insecure,
                     pin_host=pin_host)
        total = int(body.get("total") or 0)
        results = body.get("results") or []
        for raw in results:
            # A row with no id cannot be a key of the snapshot. It is left
            # out and the short-read test below calls the snapshot incomplete.
            if raw.get("id"):
                items[raw["id"]] = item_record(raw)
        if echo:
            echo("  %d of %d item(s)" % (len(items), total))
        start = next_start(start, len(results), total)
    # Fewer items than the portal counted means the paging skipped some. A live
    # portal re-sorts by modified while it is read, so an item edited mid-read
    # moves to the front and the last one falls off the end.
    short = len(items) < min(total, SEARCH_CEILING)
    return items, total, is_truncated(total) or short


def search_groups(url, query, token, insecure=False, pin_host=None):
    """Page /sharing/rest/community/groups the same way search is paged."""
    groups = {}
    start = 1
    while start is not None:
        params = {"q": query, "start": start, "num": clamp_num(SEARCH_MAX_NUM)}
        if token:
            params["token"] = token
        body = _call(url, "community/groups", params, insecure=insecure,
                     pin_host=pin_host)
        total = int(body.get("total") or 0)
        results = body.get("results") or []
        for raw in results:
            groups[raw.get("id")] = group_record(raw)
        start = next_start(start, len(results), total)
    return groups


def attach_groups(url, items, groups, token, insecure=False, echo=None,
                  pin_host=None):
    """Record which groups each item is shared to.

    Done by searching each group's contents rather than by asking each item for
    its groups. One request per group instead of one per item is the difference
    between a snapshot that finishes and one that gets rate limited.
    """
    for gid in sorted(groups):
        members, _total, _trunc = search_items(
            url, "group:%s" % gid, token, insecure=insecure, pin_host=pin_host)
        for iid in members:
            if iid in items:
                items[iid]["groups"].append(gid)
        if echo:
            echo("  group %s: %d item(s)" % (gid, len(members)))
    for item in items.values():
        item["groups"].sort()
    return items


def take_snapshot(url, query, token, insecure=False, echo=None, pin_host=None):
    """Read the whole sharing posture of one org into a snapshot document."""
    items, total, truncated = search_items(url, query, token, insecure=insecure,
                                           echo=echo, pin_host=pin_host)
    groups = search_groups(url, query, token, insecure=insecure,
                           pin_host=pin_host)
    attach_groups(url, items, groups, token, insecure=insecure, echo=echo,
                  pin_host=pin_host)
    taken = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return build_snapshot(url, taken, items, groups, total, truncated,
                          anonymous=not token)


def load_snapshot(path):
    with io.open(path, "r", encoding="utf-8") as handle:
        snapshot = json.load(handle)
    check_snapshot(snapshot, path)
    return snapshot


def check_snapshot(snapshot, path):
    """Refuse a document that is not a snapshot, before the diff reads None.

    "items" alone is too weak a test. A hand-written file carrying items under
    the right key but a timestamp under the wrong one passed this check, and the
    report then printed "None -> None" for its own header rather than refusing.
    A diff that cannot say WHEN is not evidence of anything.
    """
    if not isinstance(snapshot, dict):
        raise ValueError("%s is not a sharewatch snapshot" % path)
    for key in ("items", "groups", "taken"):
        if key not in snapshot:
            raise ValueError("%s is not a sharewatch snapshot: no %r"
                             % (path, key))
    for key in ("items", "groups"):
        # The diff indexes both by id. A file holding them as JSON lists used
        # to get that far and raise TypeError out of the sort, which reaches
        # the operator as a traceback rather than as a refusal.
        if not isinstance(snapshot[key], dict):
            raise ValueError("%s is not a sharewatch snapshot: %r is not an "
                             "object keyed by id" % (path, key))
    if not snapshot.get("taken"):
        raise ValueError("%s has an empty 'taken' timestamp" % path)
    return True


def write_snapshot(snapshot, directory, when):
    """Write the snapshot under its timestamped name and return the path."""
    if not os.path.isdir(directory):
        os.makedirs(directory)
    path = os.path.join(directory, snapshot_name(when))
    # Serialised before the file is opened, so a document that cannot be
    # serialised leaves no truncated file as the newest snapshot.
    text = json.dumps(snapshot, indent=1, sort_keys=True)
    with io.open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


# ------------------------------------------------------------------ self-test

@contextlib.contextmanager
def _scrubbed_environment(prefix="SHAREWATCH_"):
    """Hide the operator's own SHAREWATCH_* variables, then put them back.

    The README tells operators to export a token or password, and the
    self-test must not read it: with one exported, assertions about "no
    credential" failed and a mirror assertion crashed.
    """
    saved = dict((k, v) for k, v in os.environ.items() if k.startswith(prefix))
    for name in saved:
        del os.environ[name]
    try:
        yield
    finally:
        os.environ.update(saved)


def self_test():
    """Run the assertions with the operator's credentials out of the way."""
    with _scrubbed_environment():
        return _self_test()


def _self_test():
    """Assertions over the decision core. No portal, no network, no credentials."""
    passed = [0]
    failed = []

    def check(cond, label):
        if cond:
            passed[0] += 1
            print("PASS  %s" % label)
        else:
            failed.append(label)
            print("FAIL  %s" % label)

    def raises(fn, label):
        try:
            fn()
        except ValueError:
            check(True, label)
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (no error raised)" % label)

    def refuses(argv, label):
        """argparse writes its usage text to stderr, which is swallowed here so
        that a passing self-test prints only PASS lines."""
        noise, sys.stderr = sys.stderr, io.StringIO()
        try:
            _parse(argv)
        except SystemExit:
            check(True, label)
        else:
            check(False, "%s (argparse accepted it)" % label)
        finally:
            sys.stderr = noise

    print("sharewatch self-test: no portal, no network, no credentials")
    print("-" * 68)

    # ---- fixtures: one organization, two mornings apart
    day1 = 1757900000000          # epoch milliseconds
    minute = 60 * 1000

    def item(iid, owner, access, modified, groups=(), title=None, kind="Feature Service"):
        return {"id": iid, "title": title or iid, "owner": owner, "type": kind,
                "access": access, "modified": modified, "groups": list(groups)}

    def group(gid, access, membership="org", title=None):
        return {"id": gid, "title": title or gid, "owner": "gis_admin",
                "access": access, "membershipAccess": membership}

    old_items = {}
    for n in range(1, 10):                       # nine items, one owner
        old_items["bulk%d" % n] = item("bulk%d" % n, "jsmith", "org", day1,
                                       groups=["g-works"])
    old_items["addr"] = item("addr", "kpatel", "org", day1, groups=["g-works"],
                             title="Address Points with Occupants")
    old_items["gone1"] = item("gone1", "mreyes", "org", day1)
    old_items["gone2"] = item("gone2", "mreyes", "org", day1)
    old_items["stable"] = item("stable", "gis_admin", "public", day1,
                               groups=["g-works"], title="Parcel Viewer")
    OLD = build_snapshot("https://county.maps.arcgis.com", "2026-09-14T06:00:00Z",
                         old_items, {"g-works": group("g-works", "org"),
                                     "g-quiet": group("g-quiet", "private")},
                         len(old_items), False)

    new_items = {}
    for n in range(1, 10):                       # the same nine, now public
        new_items["bulk%d" % n] = item("bulk%d" % n, "jsmith", "public",
                                       day1 + n * minute, groups=["g-works"])
    new_items["addr"] = item("addr", "kpatel", "public", day1 + 400 * minute,
                             groups=["g-works"],
                             title="Address Points with Occupants")
    new_items["stable"] = item("stable", "gis_admin", "public", day1,
                               groups=["g-works", "g-quiet"],
                               title="Parcel Viewer")
    new_items["fresh"] = item("fresh", "twilson", "private", day1 + 500 * minute,
                              title="Draft Zoning")
    NEW = build_snapshot("https://county.maps.arcgis.com", "2026-09-15T06:00:00Z",
                         new_items, {"g-works": group("g-works", "public"),
                                     "g-quiet": group("g-quiet", "private")},
                         len(new_items), False)

    events = diff_snapshots(OLD, NEW)
    by_kind = {}
    for ev in events:
        by_kind.setdefault(ev.kind, []).append(ev)

    # ---- the sharing ladder
    check(access_rank("private") == 0, "private is the narrowest level")
    check(access_rank("public") == 3, "public is the widest level")
    check(access_rank("shared") < access_rank("org"),
          "group-only sharing is narrower than org-wide")
    check(widened("org", "public") is True, "org to public is a widening")
    check(widened("public", "org") is False, "public to org is not a widening")
    check(widened("org", "org") is False, "an unchanged level is not a widening")
    check(widened("private", "shared") is True, "private to group-only is a widening")
    raises(lambda: access_rank("everyone"), "an unknown access level raises")

    # ---- paging, where an org gets silently half-read
    check(clamp_num(100) == 100, "a page of 100 is sent as 100")
    check(clamp_num(1000) == 100, "a page of 1000 clamps to the server cap of 100")
    check(clamp_num(25) == 25, "a page under the cap is left alone")
    raises(lambda: clamp_num(0), "a page size of zero raises")
    check(next_start(1, 100, 250) == 101, "the second page starts at 101")
    check(next_start(101, 100, 250) == 201, "the third page starts at 201")
    check(next_start(1, 10, 250) == 11,
          "a page that came back short advances by the ten rows it got, not by "
          "the hundred it asked for  <-- pinned defect")
    check(next_start(201, 50, 250) is None,
          "a page that reaches the total terminates")
    check(next_start(300, 0, 250) is None, "a start past the end terminates")
    check(next_start(101, 100, 201) == 201,
          "an org whose last page ends one row short of the total is paged to "
          "that last row, not stopped one item early  <-- pinned defect")
    check(next_start(9901, 100, 12000) is None,
          "paging stops at the 10,000 ceiling, not at the reported total")
    check(next_start(9900, 100, 12000) == 10000,
          "the row sitting exactly on the ceiling is still asked for  "
          "<-- pinned defect")
    raises(lambda: next_start(0, 10, 100), "a zero start raises, search is 1-based")
    check(is_truncated(9999) is False, "9,999 results is a total we can prove")
    check(is_truncated(10000) is True,
          "exactly 10,000 cannot be proven complete  <-- pinned defect")
    check(is_truncated(41000) is True, "a total over the ceiling is truncated too")
    cut = build_snapshot("u", "t", {}, {}, SEARCH_CEILING, True)
    check(truncation_warning(OLD, NEW) == [],
          "two complete snapshots are diffed without a warning")
    warn = truncation_warning(OLD, cut)
    check(len(warn) == 3, "a truncated snapshot in a diff is warned about")
    check("newer" in warn[0] and "10000" in warn[0],
          "the warning names which of the two snapshots was cut short")
    check(any("artefact" in line for line in warn),
          "the warning says the deletions below may not be real  <-- pinned defect")
    check(len(truncation_warning(cut, cut)) == 4,
          "two truncated snapshots are both named")

    # ---- the secret never reaches an eye or a disk
    check(redact("token=hunter2 failed", "hunter2") == "token=%s failed" % REDACTED,
          "a secret in an error message is redacted")
    check(redact("nothing here", None) == "nothing here",
          "redaction with no secret leaves the text alone")
    check(REDACTED in redact("a hunter2 b hunter2", "hunter2"),
          "every occurrence of the secret is redacted")
    check(redact("start=1&token=T0KEN", "T0KEN") == "start=1&token=%s" % REDACTED,
          "a token is redacted the same way a password is")
    check(redact("id 12345 failed", 12345) == "id %s failed" % REDACTED,
          "a secret that is not a string is coerced, not raised on  <-- pinned defect")
    check(is_http_url("https://county.maps.arcgis.com") is True,
          "an https portal url is accepted")
    check(is_http_url("http://gis.internal/portal") is True,
          "a plain http url is accepted, for an internal portal")
    check(is_http_url("HTTPS://COUNTY.MAPS.ARCGIS.COM") is True,
          "the scheme test ignores case")
    check(is_http_url("county.maps.arcgis.com") is False,
          "a url with no scheme is refused, because urllib quotes the whole "
          "url back into its error and that url carries the token  "
          "<-- pinned defect")
    check(is_http_url("") is False, "an empty url is refused")
    check(is_http_url(None) is False, "a missing url is refused")
    snap = build_snapshot("https://x", "t", {"a": item("a", "o", "org", 1)},
                          {}, 1, False)
    blob = json.dumps(snap)
    check("token" not in blob and "password" not in blob,
          "a snapshot document holds no token and no password")
    check(set(item_record({"id": "i", "access": "org", "token": "T"}))
          == {"id", "title", "owner", "type", "access", "modified", "groups"},
          "an item record keeps only the sharing fields")
    check(item_record({"id": "i"})["access"] == "private",
          "an item with no access reported is recorded as private")
    check(group_record({"id": "g"})["membershipAccess"] == "org",
          "a null membershipAccess is recorded as org, the permissive reading")

    # ---- the headline: what widened, worst first
    check(len(events) > 0, "a day with changes produces findings")
    check(events[0].severity == SEVERITY["item-public"],
          "the worst finding is an item going public")
    check(events[0].kind == "item-public", "the top line is an item-public event")
    severities = [ev.severity for ev in events]
    check(severities == sorted(severities, reverse=True),
          "events are ordered worst first")
    check(SEVERITY["item-public"] > SEVERITY["item-joined-group"],
          "going public outranks joining a group")
    check(SEVERITY["group-public"] > SEVERITY["item-joined-group"],
          "a group going public outranks an item joining a group")
    check(SEVERITY["item-public"] > SEVERITY["group-public"],
          "an item going public outranks a group going public")

    # ---- the bulk collapse
    public_events = by_kind["item-public"]
    check(len(public_events) == 2,
          "nine bulk items and one unrelated item are two events, not ten")
    bulk = [ev for ev in public_events if ev.owner == "jsmith"]
    check(len(bulk) == 1, "one owner's bulk share collapses to a single event")
    check(len(bulk[0].items) == 9, "the collapsed event lists all nine items")
    check(bulk[0].detail == "org -> public", "the event says what the change was")
    solo = [ev for ev in public_events if ev.owner == "kpatel"]
    check(len(solo) == 1 and len(solo[0].items) == 1,
          "a second owner in the same day stays a separate event")
    check(events[0].owner == "jsmith",
          "the nine-item event outranks the one-item event at equal severity")
    # jsmith also sorts before kpatel, so the line above passes on the owner
    # tiebreak alone. These two owners are named so that alphabetical order and
    # blast radius disagree: only the item count can put the big event first.
    loud, quiet = "zzz_bulk", "aaa_single"
    before = {"one": item("one", quiet, "org", day1)}
    after = {"one": item("one", quiet, "public", day1)}
    for idx in range(9):
        iid = "many%d" % idx
        before[iid] = item(iid, loud, "org", day1 + idx * minute)
        after[iid] = item(iid, loud, "public", day1 + idx * minute)
    ranked = diff_snapshots(build_snapshot("u", "t", before, {}, 10, False),
                            build_snapshot("u", "t", after, {}, 10, False))
    check([ev.owner for ev in ranked] == [loud, quiet],
          "at equal severity the event touching nine items leads the one "
          "touching one, even when the owner names sort the other way  "
          "<-- pinned defect")
    check(len(ranked[0].items) == 9 and len(ranked[1].items) == 1,
          "the leading event is the one with the bigger blast radius")

    # ---- the window is a window, not a day
    spread = {}
    for n in range(1, 10):
        spread["s%d" % n] = item("s%d" % n, "jsmith", "public",
                                 day1 + n * 600 * minute, groups=[])
    wide_old = build_snapshot("u", "t", {k: dict(v, access="org")
                                         for k, v in spread.items()}, {}, 9, False)
    wide_new = build_snapshot("u", "t", spread, {}, 9, False)
    check(len(diff_snapshots(wide_old, wide_new)) == 9,
          "nine changes days apart stay nine events")
    check(len(diff_snapshots(wide_old, wide_new, window_minutes=100000)) == 1,
          "a wide enough --window-minutes collapses them")
    raises(lambda: collapse([], window_minutes=-1),
           "a negative --window-minutes raises")

    # ---- the group widening, reported with what is inside it
    widening = by_kind["group-public"]
    check(len(widening) == 1, "the group going public is one event")
    check(widening[0].item_count == 11,
          "the group event carries the count of items inside it")
    check(widening[0].group == "g-works", "the group event names the group")
    check("org -> public" in widening[0].detail,
          "the group event says what the access changed to")
    check(items_in_group(NEW, "g-quiet") == 1,
          "an item that joined a group counts towards that group")
    check(items_in_group(NEW, "g-none") == 0,
          "a group with nothing in it counts zero")
    born_public = diff_snapshots(
        build_snapshot("u", "t", {"a": item("a", "jsmith", "org", day1)},
                       {}, 1, False),
        build_snapshot("u", "t",
                       {"a": item("a", "jsmith", "org", day1, groups=["g-new"])},
                       {"g-new": group("g-new", "public")}, 1, False))
    born = [ev for ev in born_public if ev.kind == "group-public"]
    check(len(born) == 1,
          "a group created public is reported, not only one flipped public  "
          "<-- pinned defect")
    check(born[0].item_count == 1,
          "the new public group carries the count of what is already inside it")
    check(born_public[0].kind == "group-public",
          "the new public group outranks the item that joined it")
    check(diff_snapshots(build_snapshot("u", "t", {}, {}, 0, False),
                         build_snapshot("u", "t", {},
                                        {"g-p": group("g-p", "private")},
                                        0, False)) == [],
          "a new private group is not a finding")
    opened = diff_snapshots(
        build_snapshot("u", "t", {"a": item("a", "jsmith", "org", day1,
                                            groups=["g-j"])},
                       {"g-j": group("g-j", "org", "none")}, 1, False),
        build_snapshot("u", "t", {"a": item("a", "jsmith", "org", day1,
                                            groups=["g-j"])},
                       {"g-j": group("g-j", "org", "org")}, 1, False))
    check(len(opened) == 1 and opened[0].kind == "group-org",
          "a group that opened its membership to the whole org is reported")
    # ---- a document that is not a snapshot is refused, not rendered as None
    raises(lambda: check_snapshot({"groups": {}, "taken": "t"}, "f"),
           "a document with no items is refused")
    raises(lambda: check_snapshot({"items": {}, "taken": "t"}, "f"),
           "a document with no groups is refused")
    raises(lambda: check_snapshot({"items": {}, "groups": {}}, "f"),
           "a document with no 'taken' timestamp is refused  <-- pinned defect")
    raises(lambda: check_snapshot({"items": {}, "groups": {}, "taken": ""}, "f"),
           "an empty 'taken' timestamp is refused")
    raises(lambda: check_snapshot([], "f"),
           "a JSON list is refused")
    check(check_snapshot({"items": {}, "groups": {}, "taken": "t"}, "f") is True,
          "a well-formed snapshot passes the check")

    check("membershipAccess" in opened[0].detail,
          "the membership finding names the setting that changed")
    check(opened[0].item_count == 1,
          "the membership finding carries the item count as well")
    check(diff_snapshots(
        build_snapshot("u", "t", {}, {"g-j": group("g-j", "org", "org")},
                       0, False),
        build_snapshot("u", "t", {}, {"g-j": group("g-j", "org", "none")},
                       0, False)) == [],
          "a group that closed its membership is not a finding")

    # ---- THE PINNED DEFECT: the union, not the intersection
    deleted = by_kind.get("item-deleted", [])
    check(len(deleted) == 1,
          "items missing from the new snapshot are DELETED  <-- pinned defect")
    check(len(deleted[0].items) == 2,
          "both of that owner's deletions are in the one event")
    check({i["id"] for i in deleted[0].items} == {"gone1", "gone2"},
          "the deleted event names the items that vanished")
    scattered_old = {}
    for n in range(1, 61):                       # 60 items, edited years apart
        scattered_old["d%d" % n] = item("d%d" % n, "mreyes", "org",
                                        day1 - n * 20000 * minute)
    wiped = diff_snapshots(
        build_snapshot("u", "t", scattered_old, {}, 60, False),
        build_snapshot("u", "t", {}, {}, 0, False))
    check(len(wiped) == 1,
          "60 deletions by one owner are one event, however old the items "
          "were  <-- pinned defect")
    check(len(wiped[0].items) == 60, "the wipe event lists all 60 items")
    joined_old, joined_new = {}, {}
    for n in range(1, 10):                       # a bulk add to one group
        joined_old["j%d" % n] = item("j%d" % n, "jsmith", "org",
                                     day1 - n * 20000 * minute)
        joined_new["j%d" % n] = item("j%d" % n, "jsmith", "org",
                                     day1 - n * 20000 * minute, groups=["g-x"])
    joins = diff_snapshots(build_snapshot("u", "t", joined_old, {}, 9, False),
                           build_snapshot("u", "t", joined_new, {}, 9, False))
    check(len(joins) == 1 and len(joins[0].items) == 9,
          "a bulk add to one group is one event, because a group share does "
          "not bump modified  <-- pinned defect")
    new_only = by_kind.get("new-item", [])
    check(len(new_only) == 1 and new_only[0].items[0]["id"] == "fresh",
          "an item only in the new snapshot is NEW  <-- pinned defect")
    only_deletes_old = build_snapshot("u", "t", dict(old_items), {}, 14, False)
    only_deletes_new = build_snapshot("u", "t", {}, {}, 0, False)
    check(len(diff_snapshots(only_deletes_old, only_deletes_new)) > 0,
          "a day where everything was deleted is not a clean day  <-- pinned defect")
    check(SEVERITY["new-item-public"] > SEVERITY["new-item"],
          "an item that arrives already public outranks an ordinary new item")

    # ---- the quiet day
    quiet = diff_snapshots(OLD, OLD)
    check(quiet == [], "two identical snapshots produce zero findings")
    check(describe(quiet) == ["No sharing changes between the two snapshots."],
          "a quiet day says so in one line")
    check(diff_snapshots(NEW, NEW) == [],
          "the second snapshot against itself is also quiet")
    check(exit_code(diff_snapshots(OLD, OLD)) == 0, "a quiet day exits 0")
    check(exit_code(events) == 1, "a day with findings exits 1")

    # ---- narrowing is reported, not alarmed about
    fixed = build_snapshot("u", "t", {"addr": item("addr", "kpatel", "org", day1)},
                           {}, 1, False)
    back = diff_snapshots(NEW, fixed)
    narrowed = [ev for ev in back if ev.kind == "item-narrowed"]
    check(len(narrowed) == 1, "an item that was locked back down is reported")
    check(narrowed[0].severity < SEVERITY["item-joined-group"],
          "narrowing ranks below joining a group")

    # ---- rendering
    lines = describe(events)
    check(any("bulk1" in line for line in lines),
          "the report lists the individual items of a collapsed event")
    check(any("item(s) inside" in line for line in lines),
          "the report shows the group's item count")
    check(lines[0].startswith("[100]"), "the worst severity is printed first")
    wide = chr(0x6c34)                      # a character cp1252 cannot encode
    check(printable("Parcel Viewer", "cp1252") == "Parcel Viewer",
          "an ascii line is printed unchanged")
    check(printable(wide, "utf-8") == wide,
          "a console that can encode the title keeps it")
    check(printable(wide, "cp1252") == "?",
          "a windows console gets a replaced character, not a crash that "
          "loses every finding below it  <-- pinned defect")
    check(printable(wide, None) == wide,
          "a stream that reports no encoding is left alone")
    check(printable(wide, "not-an-encoding") == wide,
          "an unknown console encoding is left alone rather than raised on")

    # ---- snapshot files
    when = datetime.datetime(2026, 9, 15, 6, 0, 0)
    check(snapshot_name(when) == "sharewatch-20260915T060000Z.json",
          "a snapshot is named for the UTC time it was taken")
    names = ["sharewatch-20260913T060000Z.json", "sharewatch-20260915T060000Z.json",
             "sharewatch-20260914T060000Z.json", "notes.txt"]
    check(newest_snapshot(names) == "sharewatch-20260915T060000Z.json",
          "the newest snapshot in a folder is found by name")
    check(newest_snapshot(["notes.txt"]) is None,
          "a folder with no snapshot in it returns nothing")
    check(newest_snapshot([]) is None, "an empty folder returns nothing")

    # ---- argument handling
    a = _parse(["snapshot", "--url", "https://x"])
    check(a.apply is False, "--apply defaults to OFF, so nothing is written")
    check(a.insecure is False, "--insecure defaults to OFF")
    check(a.window_minutes == DEFAULT_WINDOW_MINUTES,
          "--window-minutes defaults to the configured value")
    check(a.token is None and a.username is None,
          "no credential is assumed when none is given")
    check(_parse(["snapshot", "--url", "x", "--apply"]).apply is True,
          "--apply is read")
    check(_parse(["snapshot", "--url", "x", "--insecure"]).insecure is True,
          "--insecure is read")
    check(_parse(["diff", "a.json", "b.json", "--window-minutes", "5"]
                 ).window_minutes == 5, "--window-minutes is read")
    check(_parse(["diff", "a.json", "b.json"]).paths == ["a.json", "b.json"],
          "diff reads both snapshot paths")
    check(_parse(["watch", "--url", "x", "--dir", "snaps"]).dir == "snaps",
          "--dir is read")
    check(_parse(["snapshot", "--url", "x", "--query", "orgid:AB"]).query
          == "orgid:AB", "--query is read")
    check(_parse(["snapshot", "--url", "x", "--token", "T"]).token == "T",
          "--token is read")
    check(_parse(["snapshot", "--url", "https://x"]).url == "https://x",
          "--url is read")
    check(_parse(["snapshot", "--url", "x", "--out", "snaps"]).out == "snaps",
          "--out is read")
    check(_parse(["snapshot", "--url", "x", "--username", "gis_admin"]
                 ).username == "gis_admin", "--username is read")
    check(_parse(["--self-test"]).self_test, "--self-test parses with no mode")
    refuses(["snapshot", "--url", "x", "--password", "hunter2"],
            "there is no --password flag, a secret cannot be put in argv")
    refuses(["snapshot", "--url", "x", "--unshare", "abc"],
            "there is no flag that changes sharing")
    refuses(["publish", "--url", "x"], "an unknown mode is refused")
    refuses(["snapshot", "--url", "x", "--ap"],
            "a unique prefix of --apply is refused, so the write flag is never "
            "reached by abbreviation  <-- pinned defect")
    quiet_err, sys.stderr = sys.stderr, io.StringIO()
    try:
        scheme_less = main(["snapshot", "--url", "county.maps.arcgis.com"])
        bad_window = main(["diff", "a.json", "b.json", "--window-minutes", "-1"])
    finally:
        sys.stderr = quiet_err
    check(scheme_less == 64,
          "a scheme-less --url is refused before any request is built  "
          "<-- pinned defect")
    check(bad_window == 64, "a negative --window-minutes is refused")

    # ---- the last of the pure core
    check(abs((utcnow() - datetime.datetime.now(datetime.timezone.utc))
              .total_seconds()) < 5, "the snapshot clock reads UTC now")
    check(utcnow().tzinfo is datetime.timezone.utc,
          "the snapshot clock carries UTC, not a naive local time")
    check(_bucket([], 60 * 1000) == [], "no findings make no buckets")
    shown = describe(wiped)
    check(any("and 40 more" in line for line in shown),
          "a 60-item event lists 20 items and counts the rest")
    check(len([line for line in shown if line.startswith("        - ")]) == 21,
          "the long list is cut at 20 lines plus the count")
    closed = diff_snapshots(
        build_snapshot("u", "t", {}, {"g": group("g", "public")}, 0, False),
        build_snapshot("u", "t", {}, {"g": group("g", "org")}, 0, False))
    check(len(closed) == 1 and closed[0].kind == "group-narrowed",
          "a group locked back down is recorded, not alarmed about")
    check(closed[0].severity < SEVERITY["group-org"],
          "narrowing a group ranks below widening one")
    check("item-public" in repr(events[0]) and "jsmith" in repr(events[0]),
          "an event names its kind and owner when it turns up in a traceback")
    raises(lambda: check_snapshot({"items": [{"id": "a"}], "groups": {},
                                   "taken": "t"}, "f"),
           "items as a JSON list is refused, because the diff indexes items by "
           "id and would raise TypeError instead  <-- pinned defect")
    raises(lambda: check_snapshot({"items": {}, "groups": [], "taken": "t"}, "f"),
           "groups as a JSON list is refused for the same reason")

    # ---- the portal, answered in process
    #
    # No socket is opened and no credential is real. _opener is swapped for a
    # stand-in that answers the REST paths the portal answers, including the
    # three failures that matter: a 200 carrying an error envelope, which is
    # how ArcGIS reports a dead token; an HTTP error, which is how a gateway
    # reports one; and an exception out of urllib that quotes the failing url
    # back with the token still in it.

    class FakeResponse(object):
        def __init__(self, body):
            self.body = body

        def read(self):
            return json.dumps(self.body).encode("utf-8")

    class FakePortal(object):
        """A portal that answers in process, from a list of items and groups.

        num is capped at 100 the way the real server silently caps it, so a
        paging loop that advanced by its own num instead of by the rows it got
        back would read one page here and call the whole org snapshotted.
        """

        def __init__(self, items=(), groups=(), org="ORG123", token="TESTTOKEN",
                     reported_total=None, fail_search_after=None,
                     open_error=None, cap=100, self_fields=None, password="hunter2"):
            self.password = password
            self.items = list(items)
            self.self_fields = dict(self_fields or {})   # host names, urlKey
            self.groups = list(groups)
            self.org = org
            self.token = token
            self.reported_total = reported_total
            self.fail_search_after = fail_search_after
            self.open_error = open_error      # callable(target) -> exception
            self.cap = cap                    # rows the server will really give
            self.searches = 0
            self.targets = []
            self.posted = []
            self.insecure = None
            self.pinned = []

        def __call__(self, insecure, pin_host=None):   # stands in for _opener
            self.insecure = insecure
            self.pinned.append(pin_host)
            return self

        def open(self, target, data=None, timeout=None):
            if data is None:
                path, _sep, query = target.partition("?")
            else:
                path, query = target, data.decode("utf-8")
                self.posted.append(query)
            self.targets.append(target)
            if self.open_error is not None:
                raise self.open_error(target)
            return FakeResponse(self._body(path, dict(
                urllib.parse.parse_qsl(query))))

        def _body(self, path, params):
            if path.endswith("/generateToken"):
                if params.get("password") != self.password:
                    return {"error": {"code": 400,
                                      "message": "Invalid username or password."}}
                return {"token": self.token, "expires": 9999999999999}
            if path.endswith("/portals/self"):
                described = {"id": self.org} if self.org else {}
                described.update(self.self_fields)
                return described
            if path.endswith("/community/groups"):
                return self._page(self.groups, params)
            if path.endswith("/search"):
                self.searches += 1
                if (self.fail_search_after is not None
                        and self.searches > self.fail_search_after):
                    return {"error": {"code": 498, "message": "Invalid token."}}
                rows = self.items
                query = params.get("q") or ""
                if query.startswith("group:"):
                    gid = query.split(":", 1)[1]
                    rows = [r for r in rows if gid in (r.get("_groups") or [])]
                return self._page(rows, params)
            return {"error": {"code": 400, "message": "unhandled " + path}}

        def _page(self, rows, params):
            start = int(params.get("start") or 1)
            num = min(int(params.get("num") or 10), self.cap)   # silent cap
            page = rows[start - 1:start - 1 + num]
            total = (len(rows) if self.reported_total is None
                     else self.reported_total)
            return {"total": total, "start": start, "num": len(page),
                    "results": page}

    def serving(a_portal, fn):
        """Run fn with that portal answering every call, then put _opener back."""
        saved_opener = globals()["_opener"]
        globals()["_opener"] = a_portal
        try:
            return fn()
        finally:
            globals()["_opener"] = saved_opener

    class Console(io.StringIO):
        """A stdout that reports an encoding, the way a real console does."""
        encoding = "utf-8"

    def captured(fn, encoding="utf-8"):
        """Run fn with stdout and stderr collected. Returns (result, text)."""
        console = Console()
        console.encoding = encoding
        saved_streams = (sys.stdout, sys.stderr)
        sys.stdout, sys.stderr = console, console
        try:
            result = fn()
        finally:
            sys.stdout, sys.stderr = saved_streams
        return result, console.getvalue()

    def fails(fn, label):
        """A portal call that must raise. Returns the redacted message."""
        try:
            fn()
        except RuntimeError as exc:
            check(True, label)
            return "%s" % exc
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (no error raised)" % label)
        return ""

    PORTAL = "https://county.maps.arcgis.com"
    catalog = [{"id": "p%03d" % n, "title": "Layer %d" % n, "owner": "jsmith",
                "type": "Feature Service", "access": "org", "modified": day1 + n,
                "_groups": ["g-works"] if n < 3 else []} for n in range(250)]
    portal_groups = [{"id": "g-works", "title": "Public Works",
                      "owner": "gis_admin", "access": "org",
                      "membershipAccess": None}]
    portal = FakePortal(catalog, portal_groups)

    read, reported, cut_short = serving(portal, lambda: search_items(
        PORTAL, "orgid:ORG123", "TESTTOKEN"))
    check(len(read) == 250,
          "paging reads all 250 items, not the 100 the server caps a page at  "
          "<-- pinned defect")
    check(portal.searches == 3, "250 items are read in three pages")
    check(reported == 250 and cut_short is False,
          "the reported total travels back with the items, not truncated")
    check(read["p249"]["title"] == "Layer 249",
          "the last item of the last page is in the snapshot, not lost")
    check(read["p000"]["groups"] == [],
          "an item arrives from search with no group membership yet")
    check(read["p249"]["modified"] == day1 + 249,
          "the portal's modified date is carried into the record, not zeroed  "
          "<-- pinned defect")
    # The collapse buckets on that date, so a record that lost it would merge
    # a year of unrelated changes into one event and call it one mistake.
    slow = [dict(row, modified=day1 + n * 600 * minute)
            for n, row in enumerate(catalog[:4])]
    was_narrow = serving(FakePortal(slow, []), lambda: take_snapshot(
        PORTAL, "orgid:ORG123", "TESTTOKEN"))
    went_public = serving(
        FakePortal([dict(row, access="public") for row in slow], []),
        lambda: take_snapshot(PORTAL, "orgid:ORG123", "TESTTOKEN"))
    check(len(diff_snapshots(was_narrow, went_public)) == 4,
          "four items the portal dated ten hours apart stay four events, "
          "because the date reached the collapse  <-- pinned defect")
    check(all("token=TESTTOKEN" in t for t in portal.targets),
          "the token is sent with every page")
    check(all("num=100" in t for t in portal.targets),
          "the page size is clamped to the server cap before it is sent")
    check(all("f=json" in t for t in portal.targets),
          "every call asks for f=json, or the portal answers with the html "
          "page and json.loads gets a doctype  <-- pinned defect")

    dribbling = FakePortal(catalog, portal_groups, cap=10)
    dribbled = serving(dribbling, lambda: search_items(
        PORTAL, "orgid:ORG123", "TESTTOKEN"))[0]
    check(len(dribbled) == 250,
          "a server that quietly gives back ten rows for a page of a hundred is "
          "still paged to the end of the org  <-- pinned defect")
    check(dribbling.searches == 25,
          "paging advanced by the rows that came back, twenty five times, not "
          "by the page size it asked for")

    progress = []
    serving(portal, lambda: search_items(PORTAL, "orgid:ORG123", "TESTTOKEN",
                                         echo=progress.append))
    check(len(progress) == 3 and "250 of 250" in progress[-1],
          "the progress echo counts the items read against the total")

    anonymous = FakePortal(catalog[:5], portal_groups)
    serving(anonymous, lambda: search_items(PORTAL, "orgid:ORG123", None))
    check(not any("token=" in t for t in anonymous.targets),
          "an anonymous read sends no token parameter at all")

    read_groups = serving(portal, lambda: search_groups(PORTAL, "orgid:ORG123",
                                                        "TESTTOKEN"))
    check(list(read_groups) == ["g-works"], "the org's groups are read")
    check(read_groups["g-works"]["membershipAccess"] == "org",
          "a null membershipAccess from the portal is read back as org")

    attached = serving(portal, lambda: attach_groups(PORTAL, read, read_groups,
                                                     "TESTTOKEN"))
    check(attached["p000"]["groups"] == ["g-works"],
          "an item inside a group is recorded as being inside it")
    check(attached["p200"]["groups"] == [],
          "an item in no group keeps an empty group list")
    check(sum(1 for i in attached.values() if i["groups"]) == 3,
          "only the three items that are in the group got the group")
    pair = [{"id": "both", "title": "In Two", "owner": "jsmith",
             "type": "Feature Service", "access": "org", "modified": day1,
             "_groups": ["g-zulu", "g-alpha"]}]
    two_groups = [{"id": gid, "title": gid, "owner": "gis_admin",
                   "access": "org", "membershipAccess": None}
                  for gid in ("g-zulu", "g-alpha")]
    paired = FakePortal(pair, two_groups)
    in_two = serving(paired, lambda: take_snapshot(PORTAL, "orgid:ORG123",
                                                   "TESTTOKEN"))
    check(in_two["items"]["both"]["groups"] == ["g-alpha", "g-zulu"],
          "an item in two groups gets them back in id order, so an unchanged "
          "org writes the same bytes twice  <-- pinned defect")
    stray = serving(portal, lambda: search_items(
        PORTAL, "orgid:ORG123", "TESTTOKEN"))[0]
    del stray["p001"]
    serving(portal, lambda: attach_groups(PORTAL, stray, read_groups, "TESTTOKEN"))
    check("p001" not in stray and stray["p000"]["groups"] == ["g-works"],
          "a group member the org search never returned is skipped, not "
          "invented as an item with no fields")

    whole = serving(portal, lambda: take_snapshot(PORTAL, "orgid:ORG123",
                                                  "TESTTOKEN"))
    check(len(whole["items"]) == 250 and len(whole["groups"]) == 1,
          "a snapshot holds every item and every group the portal reported")
    check("TESTTOKEN" not in json.dumps(whole),
          "the token never reaches the snapshot document  <-- pinned defect")
    check(check_snapshot(whole, "portal") is True,
          "a snapshot built from the portal passes the snapshot check")
    check(whole["url"] == PORTAL and whole["taken"].endswith("Z"),
          "the snapshot records which portal it came from and when")

    check(serving(portal, lambda: org_id(PORTAL, "TESTTOKEN")) == "ORG123",
          "the org id is read from portals/self")
    check(serving(FakePortal(org=None), lambda: org_id(PORTAL, None)) is None,
          "a portal that will not name its org gives no id, not a wrong one")
    blind = FakePortal(org=None)
    serving(blind, lambda: org_id(PORTAL, None))
    check(not any("token=" in t for t in blind.targets),
          "portals/self is asked anonymously when there is no token")

    # ---- the credential, which must never be printed, logged or stored
    check(serving(portal, lambda: generate_token(PORTAL, "gis_admin",
                                                 "hunter2")) == "TESTTOKEN",
          "a username and password are exchanged for a token")
    check(any("password=hunter2" in body for body in portal.posted),
          "the password goes in the POST body, which is where it belongs")
    check(not any("password" in t for t in portal.targets),
          "the password never appears in a url  <-- pinned defect")
    check(all("f=json" in body for body in portal.posted),
          "the POST body asks for f=json too, not only the GETs")
    refused = fails(lambda: serving(portal, lambda: generate_token(
        PORTAL, "gis_admin", "wrongpass")),
        "a rejected sign-in is raised, not returned as a token")
    check("Invalid username or password" in refused,
          "the portal's own reason survives into the error  <-- pinned defect")
    check("wrongpass" not in refused,
          "the rejected password is not quoted back in the error")
    fails(lambda: serving(FakePortal(token=None), lambda: generate_token(
        PORTAL, "gis_admin", "hunter2")),
        "a sign-in that returns no token is an error, not an anonymous read")

    # SHAREWATCH_PASSWORD is borrowed below. A value is seeded first, so that
    # putting it back is exercised here rather than only on a machine where
    # the operator happens to have one set already.
    os.environ[SECRET_ENV] = "the operator's own value"
    saved_secret = os.environ.pop(SECRET_ENV)
    try:
        os.environ[SECRET_ENV] = "from-the-environment"
        check(read_secret("gis_admin") == "from-the-environment",
              "the password is read from the environment, never from argv")
        del os.environ[SECRET_ENV]
        prompts = []

        def fake_getpass(prompt):
            prompts.append(prompt)
            return "typed-at-the-prompt"

        real_getpass, getpass.getpass = getpass.getpass, fake_getpass
        try:
            check(read_secret("gis_admin") == "typed-at-the-prompt",
                  "with nothing in the environment the password is prompted for")
        finally:
            getpass.getpass = real_getpass
        check(bool(prompts) and "gis_admin" in prompts[0]
              and "not echoed" in prompts[0],
              "the prompt names the user and says the password is not echoed")

        check(_authenticate(_parse(["snapshot", "--url", PORTAL,
                                    "--token", "T0KEN"])) == "T0KEN",
              "an existing --token is used as given, with no sign-in")
        check(_authenticate(_parse(["snapshot", "--url", PORTAL])) is None,
              "with no credential at all the read is anonymous")
        os.environ[SECRET_ENV] = "hunter2"
        signed_in = FakePortal(catalog[:5], portal_groups)
        check(serving(signed_in, lambda: _authenticate(_parse(
            ["snapshot", "--url", PORTAL, "--username", "gis_admin"])))
            == "TESTTOKEN",
            "--username signs in and returns a token  <-- pinned defect")
        check(bool(signed_in.posted)
              and "username=gis_admin" in signed_in.posted[0],
              "the sign-in names the user it was asked for")
    finally:
        os.environ[SECRET_ENV] = saved_secret
    check(os.environ.get(SECRET_ENV) == "the operator's own value",
          "the borrowed %s is put back, not eaten" % SECRET_ENV)
    del os.environ[SECRET_ENV]

    # ---- the three ways a portal call fails
    quoted = fails(lambda: serving(
        FakePortal(open_error=lambda t: ValueError("unknown url type: %r" % t)),
        lambda: search_items(PORTAL, "orgid:ORG123", "SECRETTOKEN")),
        "a url urllib cannot open is raised as an error")
    check("SECRETTOKEN" not in quoted,
          "a token in the url urllib quoted back is redacted out of the error  "
          "<-- pinned defect")
    check(REDACTED in quoted, "the redaction leaves its mark where the token was")
    gateway = fails(lambda: serving(
        FakePortal(open_error=lambda t: urllib.error.HTTPError(
            t, 500, "Internal Server Error", {}, None)),
        lambda: search_items(PORTAL, "orgid:ORG123", "TESTTOKEN")),
        "an HTTP error from the portal is raised as an error")
    check("500" in gateway, "the HTTP status is kept in the error")
    envelope = fails(lambda: serving(
        FakePortal(catalog, portal_groups, fail_search_after=1),
        lambda: search_items(PORTAL, "orgid:ORG123", "TESTTOKEN")),
        "a 200 response carrying an ArcGIS error envelope is an error, not data")
    check("498" in envelope and "Invalid token" in envelope,
          "the portal's error code and message reach the operator")
    unknown_path = fails(
        lambda: serving(portal, lambda: _call(PORTAL, "content/items/x99", {})),
        "an error envelope from any endpoint raises, not only from search")
    check("content/items/x99" in unknown_path,
          "the error names the endpoint that failed")
    expiring = FakePortal(catalog, portal_groups, fail_search_after=1)
    fails(lambda: serving(expiring, lambda: take_snapshot(
        PORTAL, "orgid:ORG123", "TESTTOKEN")),
        "a token that dies mid-paging fails the snapshot  <-- pinned defect")
    check(expiring.searches == 2,
          "the half-read org is abandoned at the failing page, not returned")

    # ---- --insecure, which is off unless it is asked for
    def verify_modes(opener):
        return [h._context.verify_mode for h in opener.handlers
                if getattr(h, "_context", None) is not None]

    check(ssl.CERT_NONE in verify_modes(_opener(True)),
          "--insecure builds an opener that does not verify the certificate")
    check(ssl.CERT_NONE not in verify_modes(_opener(False)),
          "the default opener verifies the certificate  <-- pinned defect")
    check(all(h._context.check_hostname is False
              for h in _opener(True).handlers
              if getattr(h, "_context", None) is not None),
          "--insecure stops the hostname check too, or TLS refuses first")

    # ---- the command line, end to end, against the portal that answers in
    # process. Every run is captured, so the assertions can read what an
    # operator would have seen, and prove what is not in it.
    workdir = tempfile.mkdtemp(prefix="sharewatch-selftest-")
    try:
        def put(name, snapshot):
            path = os.path.join(workdir, name)
            with io.open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(snapshot))
            return path

        def snapshots_in(directory):
            if not os.path.isdir(directory):
                return []
            return sorted(n for n in os.listdir(directory)
                          if n.startswith(SNAPSHOT_PREFIX))

        small = catalog[:5]
        live = FakePortal(small, portal_groups)
        code, seen = captured(lambda: serving(live, lambda: main(
            ["snapshot", "--url", PORTAL, "--token", "SECRETTOKEN",
             "--out", workdir])))
        check(code == 0, "a snapshot run that read the org exits 0")
        check("query: orgid:ORG123" in seen,
              "with no --query the org id is resolved and searched on")
        check("5 item(s), 1 group(s)" in seen,
              "the run says how much of the org it read")
        check("No snapshot was written" in seen,
              "without --apply nothing is written and the run says so")
        check(snapshots_in(workdir) == [],
              "a dry run leaves the directory empty  <-- pinned defect")
        check("SECRETTOKEN" not in seen,
              "the token never reaches stdout  <-- pinned defect")
        check(live.insecure is False,
              "a run without --insecure verifies the certificate")

        code, seen = captured(lambda: serving(live, lambda: main(
            ["snapshot", "--url", PORTAL, "--token", "SECRETTOKEN",
             "--out", workdir, "--apply"])))
        written = snapshots_in(workdir)
        check(code == 0 and len(written) == 1, "--apply writes one snapshot file")
        check("wrote " in seen, "the run says where it wrote the snapshot")
        with io.open(os.path.join(workdir, written[0]),
                     encoding="utf-8") as handle:
            on_disk = handle.read()
        check("SECRETTOKEN" not in on_disk and "password" not in on_disk,
              "no credential reaches the snapshot file on disk  <-- pinned defect")
        check(len(json.loads(on_disk)["items"]) == 5,
              "the file that was written holds the items that were read")

        unverified = FakePortal(small, portal_groups)
        captured(lambda: serving(unverified, lambda: main(
            ["snapshot", "--url", PORTAL, "--insecure"])))
        check(unverified.insecure is True,
              "--insecure reaches the opener, it is not only parsed")
        verified = FakePortal(small, portal_groups)
        captured(lambda: serving(verified, lambda: main(
            ["snapshot", "--url", PORTAL])))
        check(verified.insecure is False, "--insecure stays off unless asked for")

        explicit = FakePortal(small, portal_groups)
        code, seen = captured(lambda: serving(explicit, lambda: main(
            ["snapshot", "--url", PORTAL, "--query", "owner:jsmith"])))
        check(code == 0 and "query: owner:jsmith" in seen,
              "an explicit --query is used as given")
        check(not any("portals/self" in t for t in explicit.targets),
              "with --query the org is never asked to name itself")

        at_ceiling = FakePortal(catalog, portal_groups,
                                reported_total=SEARCH_CEILING)
        code, seen = captured(lambda: serving(at_ceiling, lambda: main(
            ["snapshot", "--url", PORTAL])))
        check("reached the 10000 row ceiling" in seen,
              "a snapshot that hit the ceiling warns that it is partial")
        check("Narrow --query" in seen, "the ceiling warning says what to do")

        code, seen = captured(lambda: serving(FakePortal(org=None), lambda: main(
            ["snapshot", "--url", PORTAL])))
        check(code == 2 and "pass --query" in seen,
              "a portal that will not name its org fails with advice, not a crash")
        code, seen = captured(lambda: serving(
            FakePortal(open_error=lambda t: ValueError("unknown url type: %r" % t)),
            lambda: main(["snapshot", "--url", PORTAL, "--token", "SECRETTOKEN"])))
        check(code == 2, "a portal that cannot be reached exits 2, not 0")
        check("SECRETTOKEN" not in seen,
              "the token is not in the error the failed run printed  "
              "<-- pinned defect")
        code, seen = captured(lambda: serving(
            FakePortal(catalog, portal_groups, fail_search_after=1),
            lambda: main(["snapshot", "--url", PORTAL, "--out", workdir,
                          "--apply"])))
        with io.open(os.path.join(workdir, written[0]),
                     encoding="utf-8") as handle:
            after_failure = handle.read()
        check(code == 2 and snapshots_in(workdir) == written
              and after_failure == on_disk,
              "a token that died mid-paging writes no half-read snapshot and "
              "does not overwrite the one that finished  <-- pinned defect")

        # watch: a fresh read against the newest file already in the directory
        watched = os.path.join(workdir, "watched")
        check(snapshots_in(watched) == [],
              "the watch directory holds nothing before the first run")
        code, seen = captured(lambda: serving(
            FakePortal(small, portal_groups),
            lambda: main(["watch", "--url", PORTAL, "--dir", watched, "--apply",
                          "--token", "T0KEN"])))
        check(code == 0 and "the baseline" in seen,
              "the first watch run has nothing to compare with and says so")
        check(len(snapshots_in(watched)) == 1,
              "the first watch run wrote the baseline it will compare with")
        opened_up = [dict(row, access="public") for row in small]
        code, seen = captured(lambda: serving(
            FakePortal(opened_up, portal_groups),
            lambda: main(["watch", "--url", PORTAL, "--dir", watched, "--apply",
                          "--token", "T0KEN"])))
        check(code == 1, "a watch run that found a widening exits 1")
        check("item-public" in seen and "5 item(s) by jsmith" in seen,
              "the watch report names what widened and who widened it")
        check("baseline: " in seen, "the watch report names the file it used")
        code, seen = captured(lambda: serving(
            FakePortal(opened_up, portal_groups),
            lambda: main(["watch", "--url", PORTAL, "--dir", watched,
                          "--token", "T0KEN"])))
        check(code == 0 and "No sharing changes" in seen,
              "a watch run against an unchanged org exits 0")
        check("No snapshot was written" in seen,
              "watch without --apply writes nothing either")

        empty_dir = os.path.join(workdir, "empty")
        os.makedirs(empty_dir)
        code, seen = captured(lambda: serving(
            FakePortal(small, portal_groups),
            lambda: main(["watch", "--url", PORTAL, "--dir", empty_dir])))
        check(code == 3 and "nothing was compared" in seen
              and "This one is the baseline" not in seen
              and os.listdir(empty_dir) == [],
              "watch without --apply and without a baseline compares nothing: "
              "it says so and exits 3, never 'this one is the baseline'  "
              "<-- pinned defect")
        code, seen = captured(lambda: serving(
            FakePortal(small, portal_groups),
            lambda: main(["watch", "--url", PORTAL, "--dir", empty_dir,
                          "--apply"])))
        check(code == 0 and "This one is the baseline" in seen
              and len(snapshots_in(empty_dir)) == 1,
              "a watch directory that holds no snapshot is a baseline run, "
              "not a diff against nothing")
        void_dir = os.path.join(workdir, "void")
        code, seen = captured(lambda: serving(
            FakePortal([], portal_groups),
            lambda: main(["watch", "--url", PORTAL, "--dir", void_dir,
                          "--apply"])))
        check(code == 3 and "returned no items" in seen,
              "a baseline of zero items proves nothing and exits 3  "
              "<-- pinned defect")
        code, seen = captured(lambda: serving(
            FakePortal([], portal_groups),
            lambda: main(["watch", "--url", PORTAL, "--dir", void_dir,
                          "--apply"])))
        check(code == 3 and "the older snapshot holds no items" in seen
              and "No sharing changes" not in seen,
              "two empty watch runs in a row are not a quiet org  "
              "<-- pinned defect")
        code, seen = captured(lambda: serving(
            FakePortal([], portal_groups),
            lambda: main(["snapshot", "--url", PORTAL, "--query", "orgid:typo"])))
        check(code == 3 and "returned no items" in seen,
              "a snapshot of zero items exits 3, not 0  <-- pinned defect")
        code, seen = captured(lambda: serving(
            FakePortal(open_error=lambda t: ValueError("unknown url type: %r" % t)),
            lambda: main(["watch", "--url", PORTAL, "--dir", watched,
                          "--token", "SECRETTOKEN"])))
        check(code == 2 and "SECRETTOKEN" not in seen,
              "a watch run against an unreachable portal exits 2 and prints "
              "no token  <-- pinned defect")

        # A second run inside the same second writes the baseline's own name.
        # The clock is pinned here so that collision is certain rather than
        # likely: the baseline has to be read before the new file lands on it.
        collide = os.path.join(workdir, "collide")
        os.makedirs(collide)
        pinned_clock = datetime.datetime(2026, 9, 15, 6, 0, 0,
                                         tzinfo=datetime.timezone.utc)
        real_clock = globals()["utcnow"]
        globals()["utcnow"] = lambda: pinned_clock
        try:
            with io.open(os.path.join(collide, snapshot_name(pinned_clock)), "w",
                         encoding="utf-8") as handle:
                handle.write(json.dumps(build_snapshot(
                    PORTAL, "2026-09-14T06:00:00Z",
                    {r["id"]: item(r["id"], "jsmith", "org", day1)
                     for r in small}, {}, 5, False)))
            code, seen = captured(lambda: serving(
                FakePortal(opened_up, portal_groups),
                lambda: main(["watch", "--url", PORTAL, "--dir", collide,
                              "--apply"])))
        finally:
            globals()["utcnow"] = real_clock
        check(code == 1 and "5 item(s) by jsmith" in seen,
              "watch diffs against the snapshot that was in --dir before the "
              "run, not against the file it just wrote over it  "
              "<-- pinned defect")

        corrupt = os.path.join(workdir, "corrupt")
        os.makedirs(corrupt)
        with io.open(os.path.join(corrupt, "sharewatch-20260101T000000Z.json"),
                     "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        code, seen = captured(lambda: serving(
            FakePortal(small, portal_groups),
            lambda: main(["watch", "--url", PORTAL, "--dir", corrupt, "--apply"])))
        check(code == 64 and "error:" in seen,
              "a corrupt baseline is a usage error, not a traceback")
        check(len(snapshots_in(corrupt)) == 2,
              "the org that was just read is still written when yesterday's "
              "file turns out to be corrupt  <-- pinned defect")

        # diff: two files on disk
        older = put("day1.json", OLD)
        newer = put("day2.json", NEW)
        code, seen = captured(lambda: main(["diff", older, newer]))
        check(code == 1, "a diff with findings exits 1")
        check(seen.startswith("\n2026-09-14T06:00:00Z  ->  2026-09-15T06:00:00Z"),
              "the diff header says which two mornings it compared")
        check("item-public" in seen and "9 item(s) by jsmith" in seen,
              "the collapsed bulk share is what the report leads with")
        code, seen = captured(lambda: main(["diff", older, older]))
        check(code == 0 and "No sharing changes" in seen,
              "a quiet diff exits 0 and says so in one line")
        void = put("void.json", build_snapshot(PORTAL, "2026-09-14T06:00:00Z",
                                               {}, {}, 0, False))
        code, seen = captured(lambda: main(["diff", void, void]))
        check(code == 3 and "Cannot tell" in seen
              and "the newer snapshot holds no items" in seen
              and "No sharing changes" not in seen,
              "a diff of two snapshots with no items cannot call the org "
              "quiet: it exits 3  <-- pinned defect")
        spread_old = put("spread1.json", wide_old)
        spread_new = put("spread2.json", wide_new)
        code, seen = captured(lambda: main(["diff", spread_old, spread_new]))
        check(code == 1 and seen.count("item-public") == 9,
              "nine widenings days apart print as nine events")
        code, seen = captured(lambda: main(["diff", spread_old, spread_new,
                                            "--window-minutes", "100000"]))
        check(seen.count("item-public") == 1,
              "--window-minutes reaches the collapse from the command line")
        code, seen = captured(lambda: main(
            ["diff", older, os.path.join(workdir, "no-such-file.json")]))
        check(code == 64 and "error:" in seen,
              "a missing snapshot file is a usage error, not a traceback")
        code, seen = captured(lambda: main(
            ["diff", older, put("listy.json", {"items": [{"id": "a"}],
                                               "groups": {}, "taken": "t"})]))
        check(code == 64,
              "a file whose items are a JSON list is refused before the diff "
              "indexes them by id  <-- pinned defect")
        unknown_level = put("future.json", build_snapshot(
            "u", "2026-09-16T06:00:00Z",
            {"bulk1": item("bulk1", "jsmith", "everyone", day1)}, {}, 1, False))
        code, seen = captured(lambda: main(["diff", older, unknown_level]))
        check(code == 64 and "does not know" in seen,
              "a sharing level this version has never heard of is refused, not "
              "sorted as private and called safe  <-- pinned defect")
        code, seen = captured(lambda: main(
            ["diff", put("cut.json", build_snapshot(
                "u", "2026-09-14T06:00:00Z", {}, {}, SEARCH_CEILING, True)),
             newer]))
        check("WARNING" in seen and "artefact" in seen,
              "diffing a truncated snapshot warns before the findings")

        wide_char = chr(0x6c34)
        plain = put("ascii.json", build_snapshot(
            "u", "2026-09-14T06:00:00Z",
            {"w": item("w", "kpatel", "org", day1, title=wide_char + " Basin")},
            {}, 1, False))
        widened_title = put("wide.json", build_snapshot(
            "u", "2026-09-15T06:00:00Z",
            {"w": item("w", "kpatel", "public", day1, title=wide_char + " Basin")},
            {}, 1, False))
        code, seen = captured(lambda: main(["diff", plain, widened_title]),
                              encoding="cp1252")
        check(code == 1 and wide_char not in seen and "? Basin" in seen,
              "an item title a cp1252 console cannot encode is replaced, and "
              "the finding still prints  <-- pinned defect")
        code, seen = captured(lambda: main(["diff", plain, widened_title]),
                              encoding="utf-8")
        check(wide_char in seen,
              "a console that can encode the title gets the real title")

        # the usage errors that never reach the portal
        code, seen = captured(lambda: main([]))
        check(code == 64 and "a mode is required" in seen,
              "no mode at all is a usage error that names the modes")
        code, seen = captured(lambda: main(["diff", older]))
        check(code == 64 and "exactly two" in seen,
              "diff with one file is a usage error")
        code, seen = captured(lambda: main(["snapshot"]))
        check(code == 64 and "--url is required" in seen,
              "snapshot with no --url is a usage error")
        code, seen = captured(lambda: main(
            ["snapshot", "--url", PORTAL, "--apply"]))
        check(code == 64 and "--apply needs --out" in seen,
              "--apply with nowhere to write is a usage error")
        code, seen = captured(lambda: main(["watch", "--url", PORTAL]))
        check(code == 64 and "watch needs --dir" in seen,
              "watch with no --dir is a usage error")
        code, seen = captured(lambda: main(
            ["snapshot", "--url", PORTAL, "--insecure",
             "--username", "gis_admin"]))
        check(code == 64 and "unverified connection" in seen,
              "--insecure with --username is refused, because that posts the "
              "password down an unverified connection  <-- pinned defect")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # ---- mirror: two portals compared, read-only, with the host proven
    #
    # The fixtures are one cutover in miniature. Item ids do not survive a copy,
    # so the old and the new portal hold the same titles under different ids.
    def twin(prefix, specs):
        return dict((prefix + key, item(prefix + key, owner, access, when,
                                        groups=[prefix + g for g in grp],
                                        title=title))
                    for key, title, owner, access, when, grp in specs)

    def mirror_groups(prefix, specs):
        return dict((prefix + key, group(prefix + key, "org", title=title))
                    for key, title in specs)

    far = 10000 * minute
    old_mirror_items = twin("o-", [
        ("roads", "Roads", "jsmith", "public", day1, ["g1"]),
        ("parcels", "Parcels", "jsmith", "org", day1, ["g1", "g2"]),
        ("hyd", "Hydrants", "kpatel", "org", day1, []),
        ("zone", "Zoning", "kpatel", "public", day1, ["g3"]),
        ("trail", "Trails", "kpatel", "org", day1, []),
        ("basin", "Basins", "mreyes", "public", day1, []),
        ("dup1", "Dup", "mreyes", "org", day1, []),
        ("dup2", "Dup", "mreyes", "org", day1, []),
        ("sign", "Signs", "twilson", "org", day1, []),
        ("mark", "Markers", "twilson", "org", day1, []),
        ("culv", "Culverts", "mreyes", "private", day1, [])])
    new_mirror_items = twin("n-", [
        ("roads", "Roads", "jsmith", "public", day1, ["g1"]),
        ("parcels", "Parcels", "jsmith", "org", day1, ["g1"]),
        ("hyd", "Hydrants", "kpatel", "org", day1, ["g2"]),
        ("zone", "Zoning", "kpatel", "public", day1, []),
        ("basin", "Basins", "mreyes", "org", day1, []),
        ("dup", "Dup", "mreyes", "org", day1, []),
        ("sign", "Signs", "twilson", "public", day1, []),
        ("mark", "Markers", "twilson", "public", day1 + far, []),
        ("culv", "Culverts", "mreyes", "org", day1, []),
        ("fresh", "Brand New", "gis_admin", "public", day1, []),
        ("quiet", "Quiet", "gis_admin", "private", day1, [])])
    OLD_MIRROR = build_snapshot(
        "https://old.example.org", "2026-09-15T06:00:00Z", old_mirror_items,
        mirror_groups("o-", [("g1", "Public Works"), ("g2", "Planning"),
                             ("g3", "Retired Group")]), 11, False)
    NEW_MIRROR = build_snapshot(
        "https://new.example.org", "2026-09-15T06:00:00Z", new_mirror_items,
        mirror_groups("n-", [("g1", "public works"), ("g2", "Planning")]),
        11, False)

    # ---- the host proof, in the pure core
    check(host_of("https://GIS.Example.org:7443/portal") == "gis.example.org",
          "the host is read without its port, its path or its case")
    check(host_of("") == "" and host_of(None) == "",
          "a missing url has no host, not an exception")
    check(check_hosts("https://old.example.org", "https://new.example.org",
                      " NEW.example.org ") == "new.example.org",
          "a verify host is trimmed and lower-cased")
    for bad, why in (("", "an empty"), ("https://new.example.org", "a url as"),
                     ("new.example.org:7443", "a host with a port as")):
        raises(lambda: check_hosts("https://old.example.org",
                                   "https://new.example.org", bad),
               "%s --verify-host is refused, it takes a bare host name" % why)
    raises(lambda: check_hosts("https://old.example.org",
                               "https://elsewhere.example.org",
                               "new.example.org"),
           "a --new-url on another host than --verify-host is refused  "
           "<-- pinned defect")
    raises(lambda: check_hosts("https://new.example.org:8443",
                               "https://new.example.org", "new.example.org"),
           "an --old-url on the verified host is refused, or the run compares "
           "the new portal with itself  <-- pinned defect")
    check(declared_hosts({"portalHostname": "gis.example.org:7443/arcgis"})
          == {"gis.example.org"},
          "an Enterprise portalHostname loses its port and its web adaptor")
    check(declared_hosts({"portalHostname": "https://GIS.example.org"})
          == {"gis.example.org"}, "a portalHostname that carries a scheme is read")
    check(declared_hosts({"urlKey": "Acme", "customBaseUrl": "maps.example.org"})
          == {"acme.maps.example.org"},
          "an organization declares itself as urlKey dot customBaseUrl")
    check(declared_hosts({"urlKey": "acme"}) == set()
          and declared_hosts({}) == set(),
          "a portal that declares no host declares an empty set")

    # ---- the comparison, in the pure core
    mirrored, mstats = mirror_diff(OLD_MIRROR, NEW_MIRROR)
    mkinds = dict((ev.kind, ev) for ev in mirrored)
    check(sorted(mkinds) == ["mirror-ambiguous", "mirror-group-extra",
                             "mirror-group-lost", "mirror-missing",
                             "mirror-narrower", "mirror-new-public",
                             "mirror-no-group", "mirror-public", "mirror-wider"],
          "every difference between the two portals is one of nine kinds")
    check(mstats == {"paired": 8, "old_only": 1, "new_only": 2, "ambiguous": 1},
          "the run counts what it paired, what it could not and what it skipped")
    check([ev.kind for ev in mirrored[:3]]
          == ["mirror-public", "mirror-wider", "mirror-narrower"],
          "wider on the new portal outranks narrower, public first")
    check(len(mkinds["mirror-public"].items) == 2,
          "two items made public by one owner are one event even when their "
          "dates are a week apart  <-- pinned defect")
    check(mkinds["mirror-public"].detail == "old org, new public",
          "the event says what the old portal had and what the new one has")
    check(mkinds["mirror-no-group"].detail == "group 'Retired Group'",
          "a group that does not exist on the new portal is named, because a "
          "share into it can never land")
    check(mkinds["mirror-group-lost"].detail == "group 'Planning'",
          "a group the item left behind is named")
    check(mkinds["mirror-group-extra"].detail == "group 'Planning'",
          "a group the item gained on the new portal is named")
    check(not any("ublic" in ev.detail and "orks" in ev.detail
                  for ev in mirrored),
          "a group title that differs only in case is the same group")
    check(mkinds["mirror-missing"].items[0]["title"] == "Trails",
          "an item the old portal has and the new one lacks is named")
    check([i["title"] for i in mkinds["mirror-ambiguous"].items] == ["Dup"],
          "two items with one title and type are reported, not paired by guess")
    check(mkinds["mirror-new-public"].items[0]["title"] == "Brand New",
          "a public item that exists only on the new portal is reported")
    check(not any(i["title"] == "Quiet" for ev in mirrored for i in ev.items),
          "a private item that exists only on the new portal is only counted")
    for n_old, n_new in ((1, 2), (2, 1)):
        side_old = dict(("o%d" % n, item("o%d" % n, "o", "private", day1,
                                         title="Twin")) for n in range(n_old))
        side_new = dict(("n%d" % n, item("n%d" % n, "o", "public", day1,
                                         title="Twin")) for n in range(n_new))
        twin, tstats = mirror_diff(
            build_snapshot("u", "t", side_old, {}, n_old, False),
            build_snapshot("u", "t", side_new, {}, n_new, False))
        check([ev.kind for ev in twin] == ["mirror-ambiguous"]
              and tstats["paired"] == 0 and tstats["ambiguous"] == n_new,
              "%d old against %d new items sharing a title and type are "
              "reported, never paired by guess  <-- pinned defect"
              % (n_old, n_new))
    hidden_new = dict((i["id"], i) for i in (
        item("h-org", "o", "org", day1, title="Hidden Org"),
        item("h-shr", "o", "shared", day1, title="Hidden Shared"),
        item("h-pri", "o", "private", day1, title="Hidden Private")))
    hidden, hstats = mirror_diff(
        build_snapshot("u", "t", {"x": item("x", "o", "private", day1,
                                            title="Other")}, {}, 1, False),
        build_snapshot("u", "t", hidden_new, {}, 3, False))
    check(sorted((ev.kind, i["title"]) for ev in hidden for i in ev.items
                 if ev.kind == "mirror-new-shared")
          == [("mirror-new-shared", "Hidden Org"),
              ("mirror-new-shared", "Hidden Shared")]
          and not any(i["title"] == "Hidden Private"
                      for ev in hidden for i in ev.items),
          "an org or group shared item that exists only on the new portal is "
          "reported, because the old account may simply not see it  "
          "<-- pinned defect")
    raises(lambda: mirror_diff(
        build_snapshot("u", "t", {}, {}, 0, False),
        build_snapshot("u", "t", {"x": item("x", "o", "everyone", day1)},
                       {}, 1, False)),
        "an unknown level on an item that only the new portal has is refused, "
        "as it is for a pair")
    same, sstats = mirror_diff(OLD_MIRROR, OLD_MIRROR)
    check([ev.kind for ev in same] == ["mirror-ambiguous"]
          and sstats["paired"] == 9,
          "a portal compared with itself differs only by the title it cannot "
          "pair")
    check(describe([], "none") == ["none"], "a quiet comparison has its own words")
    raises(lambda: mirror_diff(
        OLD_MIRROR, build_snapshot("u", "t", {"x": item(
            "x", "o", "everyone", day1, title="Roads")}, {}, 1, False)),
        "a sharing level this version does not know is refused in a mirror too")

    # ---- the 200 that did not share
    saved_replies = [
        {"itemId": "n-roads", "notSharedWith": ["n-g9", "n-g1"]},
        {"itemId": "n-parcels", "notSharedWith": []},
        {"results": [{"itemId": "n-hyd", "success": True, "notSharedWith": []},
                     {"itemId": "n-zone", "success": False},
                     {"itemId": "x-gone", "error": {"code": 403,
                                                    "message": "No access"}}]},
        {"itemId": "n-sign", "notSharedWith": "n-g8"}]
    unshared = share_response_findings(saved_replies, NEW_MIRROR)
    check(len(unshared) == 4 and all(ev.kind == "mirror-notshared"
                                     for ev in unshared),
          "a 200 that names groups in notSharedWith is a finding, not a "
          "success  <-- pinned defect")
    check(any("n-g1, n-g9" in ev.detail for ev in unshared),
          "the groups it could not share with are named")
    check(any(ev.detail.endswith("n-g8") for ev in unshared),
          "a notSharedWith that is a bare string is read as one group")
    check(not any(i["id"] == "n-parcels" for ev in unshared for i in ev.items),
          "an empty notSharedWith is not a finding")
    check(any(ev.items[0]["title"] == "Roads" for ev in unshared),
          "the finding names the item from the new snapshot")
    check(any("No access" in ev.detail and ev.items[0]["id"] == "x-gone"
              for ev in unshared),
          "an error object inside a batch answer is a finding, and an item the "
          "snapshot never saw is still named by id")
    check(any("success false" in ev.detail for ev in unshared),
          "success false with no error object is a finding too")
    check(share_response_findings([], NEW_MIRROR) == [],
          "no saved responses, no findings")
    raises(lambda: share_response_findings([3], NEW_MIRROR),
           "a saved response that is not an object is refused")
    raises(lambda: share_response_findings([{"results": [3]}], NEW_MIRROR),
           "a batch answer holding a non-object is refused")

    # ---- the mirror parser
    m = _parse(["mirror", "--old-url", "a", "--new-url", "b", "--verify-host", "h",
                "--old-token", "OT", "--new-token", "NT", "--old-username", "ou",
                "--new-username", "nu", "--old-query", "oq", "--new-query", "nq",
                "--responses", "r.json"])
    check((m.old_url, m.new_url, m.verify_host) == ("a", "b", "h"),
          "--old-url, --new-url and --verify-host are read")
    check((m.old_token, m.new_token, m.old_username, m.new_username)
          == ("OT", "NT", "ou", "nu"), "a credential is read per portal")
    check((m.old_query, m.new_query, m.responses) == ("oq", "nq", "r.json"),
          "--old-query, --new-query and --responses are read")
    refuses(["mirror", "--verify", "h"],
            "a prefix of --verify-host is refused  <-- pinned defect")
    refuses(["mirror", "--ap"],
            "a prefix of --apply is refused on the mirror mode too  "
            "<-- pinned defect")
    refuses(["mirror", "--old", "x"], "a prefix of --old-url is refused")

    # ---- the pin reaches every request of a read
    pinned_portal = FakePortal(catalog[:5], portal_groups)
    serving(pinned_portal, lambda: take_snapshot(
        PORTAL, "orgid:ORG123", "TESTTOKEN", pin_host="county.maps.arcgis.com"))
    check(len(pinned_portal.pinned) == 3
          and set(pinned_portal.pinned) == {"county.maps.arcgis.com"},
          "the pinned host reaches every search, group and member request")

    # ---- the same, over a real socket
    #
    # http.server on the loopback address answers with the in-process portal's
    # own bodies, so the redirect and the POST body are exercised by urllib
    # itself, not by a stand-in. The old portal is 127.0.0.2 and the new one
    # 127.0.0.1: one machine, two host names.
    class StubHandler(http.server.BaseHTTPRequestHandler):
        bounce_to = ""          # where /bounce sends the caller: another host
        bounce_all = False      # send every request there, not only /bounce

        def _answer(self, query):
            path = self.path.partition("?")[0]
            port = self.server.server_address[1]
            self.server.portal.targets.append(self.path)
            for tail, origin in (("/bounce", StubHandler.bounce_to),
                                 ("/stay", "http://127.0.0.1:%d" % port)):
                if path.endswith(tail) or (StubHandler.bounce_all
                                           and tail == "/bounce"):
                    self.send_response(302)
                    self.send_header("Location", "%s/sharing/rest/portals/self"
                                     "?%s" % (origin, query))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            body = json.dumps(self.server.portal._body(path, dict(
                urllib.parse.parse_qsl(query)))).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._answer(self.path.partition("?")[2])

        def do_POST(self):
            size = int(self.headers.get("Content-Length") or 0)
            text = self.rfile.read(size).decode("utf-8")
            self.server.portal.posted.append(text)
            self._answer(text)

        def log_message(self, *ignored):
            pass

    class StubServer(http.server.HTTPServer):
        def server_bind(self):
            # HTTPServer asks DNS for its own name here, which takes seconds on
            # a Windows machine with no resolver and is of no use to a stub.
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = self.server_address[:2]

    @contextlib.contextmanager
    def listening(*portals, **kw):
        """Serve each portal on its own loopback address. Yields the ports.

        127.0.0.2 is a second host name for the same machine, and avoids
        "localhost", which Windows tries as ::1 first and takes seconds to give
        up on for every request.
        """
        servers = []
        hosts = kw.get("hosts") or ["127.0.0.1"] * len(portals)
        try:
            for a_portal, address in zip(portals, hosts):
                server = StubServer((address, 0), StubHandler)
                server.portal = a_portal
                threading.Thread(target=server.serve_forever,
                                 kwargs={"poll_interval": 0.02}).start()
                servers.append(server)
            yield [srv.server_address[1] for srv in servers]
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()

    @contextlib.contextmanager
    def env_set(name, value):
        had, prior = name in os.environ, os.environ.get(name)
        os.environ[name] = value
        try:
            yield
        finally:
            if had:
                os.environ[name] = prior
            else:
                del os.environ[name]

    def rows_of(items_by_id):
        return [dict(it, _groups=list(it["groups"]))
                for it in items_by_id.values()]

    def mirror_pair(**new_args):
        """An old portal and a new one, holding the two fixture snapshots."""
        old_p = FakePortal(rows_of(old_mirror_items),
                           list(OLD_MIRROR["groups"].values()), org="OLDORG")
        new_kw = dict(org="NEWORG")
        new_kw.update(new_args)
        new_p = FakePortal(rows_of(new_mirror_items),
                           list(NEW_MIRROR["groups"].values()), **new_kw)
        return old_p, new_p

    def run_mirror(old_p, new_p, extra=(), verify="127.0.0.1",
                   encoding="utf-8"):
        with listening(old_p, new_p, hosts=["127.0.0.2", "127.0.0.1"]) as (
                po, pn):
            old_p.self_fields.setdefault("portalHostname", "127.0.0.2:%d" % po)
            new_p.self_fields.setdefault("portalHostname",
                                         "127.0.0.1:%d/arcgis" % pn)
            argv = ["mirror", "--old-url", "http://127.0.0.2:%d" % po,
                    "--new-url", "http://127.0.0.1:%d" % pn,
                    "--verify-host", verify] + list(extra)
            return captured(lambda: main(argv), encoding)

    # the redirect, which would swap one portal for the other halfway
    probe_portal = FakePortal(org="PROBE")
    with listening(probe_portal, probe_portal,
                   hosts=["127.0.0.1", "127.0.0.2"]) as (pp, pq):
        StubHandler.bounce_to = "http://127.0.0.2:%d" % pq
        base = "http://127.0.0.1:%d" % pp
        followed = _call(base, "bounce", {"token": "SECRETTOKEN"})
        check(followed.get("id") == "PROBE",
              "an unpinned call follows a redirect to another host without a "
              "word, which is the failure the pin exists for")
        bounced = fails(lambda: _call(base, "bounce", {"token": "SECRETTOKEN"},
                                      pin_host="127.0.0.1"),
                        "a pinned call refuses a redirect to another host  "
                        "<-- pinned defect")
        check("leaves the verified host" in bounced
              and "SECRETTOKEN" not in bounced,
              "the refusal names the problem and carries no token")
        check(_call(base, "stay", {}, pin_host="127.0.0.1").get("id") == "PROBE",
              "a pinned call still follows a redirect that stays on its host")
    # snapshot and watch read one portal, so they are pinned to it as well: a
    # redirect used to carry the token to another host and record that host's
    # answer as this portal's snapshot
    for mode_args, why in ((["--query", "orgid:x"], "a query"), ([], "no query")):
        far = FakePortal(org="FAR")
        home = FakePortal(org="HOME")
        with listening(far, home, hosts=["127.0.0.1", "127.0.0.2"]) as (
                pp, pq):
            StubHandler.bounce_to = "http://127.0.0.2:%d" % pq
            StubHandler.bounce_all = True
            try:
                for mode in (["snapshot"], ["watch", "--dir", workdir]):
                    code, seen = captured(lambda: main(
                        mode + ["--url", "http://127.0.0.1:%d" % pp,
                                "--token", "SECRETTOK"] + mode_args))
                    check(code == 2 and "leaves the verified host" in seen
                          and "SECRETTOK" not in seen and home.targets == [],
                          "%s with %s refuses a redirect to another host and "
                          "sends it no token  <-- pinned defect"
                          % (mode[0], why))
                with env_set(SECRET_ENV, "SECRETPW"):
                    code, seen = captured(lambda: main(
                        ["snapshot", "--url", "http://127.0.0.1:%d" % pp,
                         "--username", "someone"] + mode_args))
                check(code == 2 and "leaves the verified host" in seen
                      and "SECRETPW" not in seen and home.targets == []
                      and home.posted == [],
                      "the sign-in with %s is pinned too, so the password "
                      "goes to no other host  <-- pinned defect" % why)
            finally:
                StubHandler.bounce_all = False
    check(any(isinstance(h, _PinnedRedirect) and h.host == "h"
              for h in _opener(False, "h").handlers),
          "an opener built with a pin carries the redirect guard")
    check(not any(isinstance(h, _PinnedRedirect)
                  for h in _opener(False).handlers),
          "an opener built without a pin is unchanged")

    old_p, new_p = mirror_pair()
    code, seen = run_mirror(old_p, new_p, ["--old-token", "OLDT",
                                           "--new-token", "NEWT"])
    check(code == 1, "a mirror run that found differences exits 1")
    check("old portal on host 127.0.0.2" in seen
          and "new portal on host 127.0.0.1" in seen,
          "the run says which host each side was read from")
    check("verified host 127.0.0.1" in seen,
          "the header names the verified host")
    check("8 paired, 1 only on the old portal, 2 only on the new, 1 not "
          "compared" in seen, "the run says how much it compared")
    check("mirror-public" in seen and "2 item(s) by twilson" in seen,
          "the report leads with what became public")
    check(seen.index("mirror-public") < seen.index("mirror-narrower"),
          "the report prints the dangerous direction first")
    check("OLDT" not in seen and "NEWT" not in seen,
          "no token reaches stdout in a mirror run  <-- pinned defect")
    check(all("token=OLDT" in t for t in old_p.targets)
          and not any("NEWT" in t for t in old_p.targets),
          "a token for one portal is never sent to the other  <-- pinned defect")
    check(all("token=NEWT" in t for t in new_p.targets)
          and not any("OLDT" in t for t in new_p.targets),
          "the new portal gets only its own token")
    allowed = ("/search", "/community/groups", "/portals/self")
    check(len(old_p.targets) > 3 and len(new_p.targets) > 3,
          "the socket stub recorded the requests the assertions below read")
    check(all(t.partition("?")[0].endswith(allowed)
              for t in old_p.targets + new_p.targets) and not old_p.posted
          and not new_p.posted,
          "a mirror run makes only search, community/groups and portals/self "
          "calls and posts nothing")

    # the same run in process, to see which host each request was pinned to
    class Router(object):
        """Routes a request to the portal for its host and records the pin."""

        def __init__(self, portals):
            self.portals = portals
            self.seen = []
            self.pin = None

        def __call__(self, insecure, pin_host=None):
            self.pin = pin_host
            return self

        def open(self, target, data=None, timeout=None):
            host = host_of(target)
            self.seen.append((host, self.pin))
            return self.portals[host].open(target, data, timeout)

    r_old, r_new = mirror_pair()
    r_old.self_fields["portalHostname"] = "old.example.org"
    r_new.self_fields["portalHostname"] = "new.example.org:8443/arcgis"
    routed = Router({"old.example.org": r_old, "new.example.org": r_new})
    code, seen = captured(lambda: serving(routed, lambda: main(
        ["mirror", "--old-url", "https://old.example.org", "--new-url",
         "https://new.example.org:8443", "--verify-host", "NEW.example.org"])))
    check(code == 1 and len(routed.seen) > 10
          and all(host == pin for host, pin in routed.seen),
          "every request of a mirror run is pinned to the host it is sent to")
    check({host for host, _pin in routed.seen}
          == {"old.example.org", "new.example.org"},
          "both portals were read")

    mirror_dir = tempfile.mkdtemp(prefix="sharewatch-mirror-")
    try:
        here = os.getcwd()
        os.chdir(mirror_dir)
        try:
            run_mirror(*mirror_pair())
            left_behind = os.listdir(mirror_dir)
        finally:
            os.chdir(here)
        check(left_behind == [],
              "a mirror run leaves no file behind, so nothing writes but --apply")

        # the replies a migration script saved, checked against the new portal
        saved = os.path.join(mirror_dir, "replies.json")
        with io.open(saved, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"itemId": "n-roads",
                                     "notSharedWith": ["n-g9"]}))
        code, seen = run_mirror(*mirror_pair(), extra=["--responses", saved])
        check("mirror-notshared" in seen and "not shared with n-g9" in seen,
              "a saved 200 that carried notSharedWith is reported next to the "
              "live comparison")
        with io.open(saved, "w", encoding="utf-8") as handle:
            handle.write(json.dumps([saved_replies[0]]))
        code, seen = run_mirror(*mirror_pair(), extra=["--responses", saved])
        check("mirror-notshared" in seen, "a list of saved responses is read")
        with io.open(saved, "w", encoding="utf-8") as handle:
            handle.write("[3]")
        code, seen = run_mirror(*mirror_pair(), extra=["--responses", saved])
        check(code == 64 and "JSON object" in seen,
              "a saved response that is not an object is a usage error")
        code, seen = run_mirror(*mirror_pair(), extra=[
            "--responses", os.path.join(mirror_dir, "none.json")])
        check(code == 64 and "error:" in seen,
              "a missing responses file is a usage error, not a traceback")
    finally:
        shutil.rmtree(mirror_dir, ignore_errors=True)

    # identical portals are a quiet run, not a failure
    same_old = FakePortal(rows_of(old_mirror_items),
                          list(OLD_MIRROR["groups"].values()), org="OLDORG")
    clone_rows = [dict(r, id=r["id"].replace("o-", "n-"),
                       _groups=[g.replace("o-", "n-") for g in r["_groups"]])
                  for r in rows_of(old_mirror_items)]
    clone_groups = [dict(g, id=g["id"].replace("o-", "n-"))
                    for g in OLD_MIRROR["groups"].values()]
    code, seen = run_mirror(same_old, FakePortal(clone_rows, clone_groups,
                                                 org="NEWORG"))
    check(code == 1 and "2 not compared" in seen,
          "two portals that share alike still report the ambiguous title")
    quiet_old = FakePortal([r for r in rows_of(old_mirror_items)
                            if not r["id"].startswith("o-dup")],
                           list(OLD_MIRROR["groups"].values()), org="OLDORG")
    quiet_new = FakePortal([r for r in clone_rows if "dup" not in r["id"]],
                           clone_groups, org="NEWORG")
    code, seen = run_mirror(quiet_old, quiet_new, ["--old-token", "OLDT",
                                                   "--new-token", "NEWT"])
    check(code == 0 and "The new portal shares what the old one did." in seen,
          "two portals that share alike exit 0 and say so")

    # refusals before and after the first call
    code, seen = run_mirror(*mirror_pair(), verify="elsewhere.example.org")
    check(code == 64 and "not the verified host" in seen,
          "a --verify-host that is not the new url's host is refused")
    code, seen = run_mirror(*mirror_pair(), verify="127.0.0.2")
    check(code == 64, "a --verify-host naming the old host is refused")
    pre_old, pre_new = mirror_pair()
    code, seen = run_mirror(pre_old, pre_new, verify="elsewhere.example.org")
    check(not pre_old.targets and not pre_new.targets,
          "a host refusal is made before any request is sent  <-- pinned defect")

    liar_old, liar_new = mirror_pair()
    liar_new.self_fields["portalHostname"] = "old.example.org"
    code, seen = run_mirror(liar_old, liar_new)
    check(code == 2 and "declares old.example.org" in seen
          and "Refusing to compare" in seen,
          "a new url that answers but declares another host is refused, so a "
          "DNS alias left on the old portal is caught  <-- pinned defect")
    check(not liar_new.searches and not liar_old.searches,
          "nothing is searched once the new portal fails the host proof")
    mute_old, mute_new = mirror_pair()
    mute_new.self_fields["portalHostname"] = ""
    code, seen = run_mirror(mute_old, mute_new)
    check(code == 2 and "declares no host" in seen,
          "a portal that declares no host cannot be proven, so it is refused")
    twin_old, twin_new = mirror_pair()
    twin_old.self_fields["portalHostname"] = "127.0.0.1"
    code, seen = run_mirror(twin_old, twin_new)
    check(code == 2 and "old url answers as the verified host" in seen
          and not twin_old.searches and not twin_new.searches,
          "an old url that declares the verified host is refused before "
          "anything is searched  <-- pinned defect")

    nameless_old, nameless_new = mirror_pair(org=None)
    code, seen = run_mirror(nameless_old, nameless_new)
    check(code == 2 and "pass --new-query" in seen,
          "a portal that will not name its org fails with advice")
    code, seen = run_mirror(nameless_old, nameless_new,
                            extra=["--new-query", "owner:jsmith"])
    check(code == 1 and "query: owner:jsmith" in seen,
          "an explicit --new-query is used as given")
    code, seen = run_mirror(*mirror_pair(), extra=["--old-query", "owner:kpatel"])
    check("query: owner:kpatel" in seen and "query: orgid:NEWORG" in seen,
          "--old-query changes the old side only")

    down_old, down_new = mirror_pair(fail_search_after=1)
    code, seen = run_mirror(down_old, down_new, ["--new-token", "SECRETTOKEN"])
    check(code == 2 and "SECRETTOKEN" not in seen,
          "a token that dies while reading the new portal exits 2 and prints "
          "no token")

    cut_old, cut_new = mirror_pair(reported_total=SEARCH_CEILING)
    code, seen = run_mirror(cut_old, cut_new)
    check("WARNING: the new snapshot reached the 10000 result ceiling" in seen,
          "a portal read to the ceiling is warned about before the findings")

    odd_old, odd_new = mirror_pair()
    odd_new.items[0]["access"] = "everyone"
    code, seen = run_mirror(odd_old, odd_new)
    check(code == 64 and "unknown access level" in seen,
          "a sharing level this version does not know stops the mirror")

    wide_title = chr(0x6c34) + " Roads"
    jp_old, jp_new = mirror_pair()
    jp_old.items[0].update(title=wide_title, access="org")
    jp_new.items[0].update(title=wide_title, access="public")
    code, seen = run_mirror(jp_old, jp_new, encoding="cp1252")
    check(chr(0x6c34) not in seen and "? Roads" in seen,
          "a title a cp1252 console cannot encode is replaced in a mirror report")

    with env_set(SECRET_ENV_OLD, "hunter2"), env_set(SECRET_ENV_NEW, "hunter2"):
        in_old, in_new = mirror_pair()
        code, seen = run_mirror(in_old, in_new, ["--old-username", "olduser",
                                                 "--new-username", "newuser"])
        check(code == 1 and "username=olduser" in in_old.posted[0]
              and "username=newuser" in in_new.posted[0],
              "each portal is signed in with its own user and password")
        check(len(in_old.posted) == 1 and len(in_new.posted) == 1
              and all(t.partition("?")[0].endswith(allowed + ("/generateToken",))
                      for t in in_old.targets + in_new.targets),
              "with a sign-in the only extra call is one generateToken POST "
              "per portal")
        check("hunter2" not in seen and not any(
            "password" in t for t in in_old.targets + in_new.targets),
            "the password reaches neither stdout nor a url  <-- pinned defect")
    check(SECRET_ENV_OLD not in os.environ and SECRET_ENV_NEW not in os.environ,
          "the borrowed password variables are removed again")
    with env_set(SECRET_ENV_OLD, "kept"):
        with env_set(SECRET_ENV_OLD, "borrowed"):
            check(os.environ[SECRET_ENV_OLD] == "borrowed", "a value is borrowed")
        check(os.environ[SECRET_ENV_OLD] == "kept",
              "a variable the operator already had is put back, not eaten")

    # usage errors
    needed = [("--old-url", "http://a.example.org"),
              ("--new-url", "http://b.example.org"),
              ("--verify-host", "b.example.org")]
    for missing in range(3):
        flat = ["mirror"] + [x for n, kv in enumerate(needed) if n != missing
                             for x in kv]
        code, seen = captured(lambda: main(flat))
        check(code == 64 and needed[missing][0] in seen,
              "mirror without %s is a usage error that names it"
              % needed[missing][0])
    full = ["mirror"] + [x for kv in needed for x in kv]
    code, seen = captured(lambda: main(full + ["--apply"]))
    check(code == 64 and "writes nothing" in seen,
          "mirror with --apply is refused, there is nothing for it to write")
    code, seen = captured(lambda: main(
        ["mirror", "--old-url", "a.example.org", "--new-url",
         "http://b.example.org", "--verify-host", "b.example.org"]))
    check(code == 64 and "must start with https://" in seen,
          "a portal url with no scheme is refused before any request is built")
    code, seen = captured(lambda: main(full + ["--insecure", "--new-username",
                                               "u"]))
    check(code == 64 and "unverified connection" in seen,
          "--insecure with --new-username is refused too, as with --username")
    code, seen = captured(lambda: main(
        ["mirror", "--old-url", "http://a.example.org", "--new-url",
         "http://b.example.org", "--verify-host", "c.example.org"]))
    check(code == 64 and "not the verified host" in seen,
          "a verify host that is not the new host is refused in the shell too")

    # ---- a read that could not see everything is not a clean day
    #
    # Two truncated snapshots, two empty portals and two anonymous reads all
    # find nothing. That is a measurement of nothing, and used to print a clean
    # verdict and exit 0.
    cut_a = build_snapshot("u", "2026-09-14T06:00:00Z",
                           {"x": item("x", "o", "org", day1)}, {},
                           SEARCH_CEILING, True)
    cut_b = build_snapshot("u", "2026-09-15T06:00:00Z",
                           {"x": item("x", "o", "org", day1)}, {},
                           SEARCH_CEILING, True)
    anon_snap = build_snapshot("u", "2026-09-15T06:00:00Z",
                               {"x": item("x", "o", "org", day1)}, {}, 1, False,
                               anonymous=True)
    check(exit_code([]) == 0 and exit_code([], True) == 3
          and exit_code(["e"], True) == 1 and exit_code(["e"]) == 1,
          "no findings exit 3 when the read was incomplete, 0 when it was "
          "whole, and any finding exits 1")
    check(coverage_gaps(OLD, NEW) == [] and "anonymous" not in OLD,
          "two whole snapshots read with a token have no gaps")
    check(coverage_gaps(cut_a, cut_b) == ["the older snapshot is incomplete",
                                          "the newer snapshot is incomplete"],
          "each incomplete snapshot is a gap, and the gap names which one")
    check(coverage_gaps(OLD, anon_snap)
          == ["the newer snapshot was read without a token and holds public "
              "items only"] and anon_snap["anonymous"] is True,
          "a snapshot read without a token is a gap, and records that it was")
    check(verdict_text([], "fine") == "fine"
          and verdict_text(["a", "b"], "fine")
          == "Cannot tell whether anything changed: a; b.",
          "the clean sentence is printed only when there is no gap")
    check(truncation_warning(OLD, build_snapshot("u", "t", {"a": item(
        "a", "o", "org", day1)}, {}, 7, True))[0]
        == "WARNING: the newer snapshot holds 1 of the 7 item(s) the portal "
           "reported.",
        "a snapshot that paging cut short, below the ceiling, says how short")

    gap_dir = tempfile.mkdtemp(prefix="sharewatch-gaps-")
    try:
        def put_gap(name, snapshot):
            path = os.path.join(gap_dir, name)
            with io.open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(snapshot))
            return path

        cut_one, cut_two = put_gap("cut1.json", cut_a), put_gap("cut2.json", cut_b)
        code, seen = captured(lambda: main(["diff", cut_one, cut_two]))
        check(code == 3 and "Cannot tell" in seen
              and "No sharing changes" not in seen and "WARNING" in seen,
              "two truncated snapshots that agree are not a clean day: exit 3 "
              "and no clean sentence  <-- pinned defect")
        code, seen = captured(lambda: main(
            ["diff", put_gap("whole.json", OLD), put_gap("anon.json", anon_snap)]))
        check(code == 1, "findings still exit 1 when the read was incomplete")
        quiet_whole = put_gap("whole2.json", dict(OLD, taken="2026-09-15T06:00:00Z"))
        code, seen = captured(lambda: main(
            ["diff", quiet_whole, put_gap("anon2.json", dict(
                OLD, taken="2026-09-16T06:00:00Z", anonymous=True))]))
        check(code == 3 and "read without a token" in seen,
              "a quiet diff against an anonymous snapshot cannot be called "
              "clean  <-- pinned defect")

        # run as a script, which is how a scheduler runs it
        ran = subprocess.run([sys.executable, os.path.abspath(__file__), "diff",
                              put_gap("a.json", OLD), put_gap("b.json", NEW)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check(ran.returncode == 1 and b"item-public" in ran.stdout,
              "the file run as a script reads its arguments, prints the report "
              "and exits with its code  <-- pinned defect")

        # a snapshot that cannot be written must not eat the report
        not_a_dir = os.path.join(gap_dir, "plain-file")
        with io.open(not_a_dir, "w", encoding="utf-8") as handle:
            handle.write("x")
        code, seen = captured(lambda: serving(
            FakePortal(small, portal_groups), lambda: main(
                ["snapshot", "--url", PORTAL, "--token", "T0KEN", "--out",
                 not_a_dir, "--apply"])))
        check(code == 2 and "error:" in seen,
              "--out naming a file exits 2 with a message, not a traceback  "
              "<-- pinned defect")
        unsized = {"sharewatch": 1, "items": {None: {}, "a": {}}, "groups": {},
                   "taken": "t"}
        wrote_nothing = False
        try:
            write_snapshot(unsized, gap_dir, utcnow())
        except TypeError:
            wrote_nothing = not [n for n in os.listdir(gap_dir)
                                 if n.startswith(SNAPSHOT_PREFIX)]
        check(wrote_nothing,
              "a snapshot that cannot be serialised leaves no truncated file "
              "behind  <-- pinned defect")

        watch_dir = os.path.join(gap_dir, "w")
        wargs = ["watch", "--url", PORTAL, "--dir", watch_dir, "--apply",
                 "--token", "T0KEN"]
        real_write = globals()["write_snapshot"]

        def full_disk(snapshot, directory, when):
            raise OSError("disk full")

        globals()["write_snapshot"] = full_disk
        try:
            code, seen = captured(lambda: serving(
                FakePortal(small, portal_groups), lambda: main(wargs)))
        finally:
            globals()["write_snapshot"] = real_write
        check(code == 2 and "disk full" in seen and "the baseline" in seen,
              "a baseline run that cannot write exits 2, not 0")
        captured(lambda: serving(FakePortal(small, portal_groups),
                                 lambda: main(wargs)))
        globals()["write_snapshot"] = full_disk
        try:
            code, seen = captured(lambda: serving(
                FakePortal(opened_up, portal_groups), lambda: main(wargs)))
            quiet_code, quiet_seen = captured(lambda: serving(
                FakePortal(small, portal_groups), lambda: main(wargs)))
        finally:
            globals()["write_snapshot"] = real_write
        check(code == 1 and "disk full" in seen and "item-public" in seen,
              "a write failure does not hide the findings: the report prints "
              "and the exit code is still 1  <-- pinned defect")
        check(quiet_code == 2 and "disk full" in quiet_seen,
              "a write failure on a quiet day exits 2, so it is not mistaken "
              "for a clean one")

        # anonymous watch: public items only, so a quiet day proves nothing
        anon_dir = os.path.join(gap_dir, "anon")
        aargs = ["watch", "--url", PORTAL, "--dir", anon_dir, "--apply"]
        code, seen = captured(lambda: serving(
            FakePortal(small, portal_groups), lambda: main(aargs)))
        check("WARNING: no token" in seen and code == 0,
              "an anonymous read warns that it sees public items only")
        code, seen = captured(lambda: serving(
            FakePortal(small, portal_groups), lambda: main(aargs)))
        check(code == 3 and "Cannot tell" in seen,
              "an anonymous watch run with no findings exits 3, not 0  "
              "<-- pinned defect")
        code, seen = captured(lambda: serving(
            FakePortal(small, portal_groups), lambda: main(
                ["snapshot", "--url", PORTAL, "--token", "T0KEN"])))
        check("WARNING: no token" not in seen,
              "a read with a token does not warn about anonymity")
        with io.open(os.path.join(anon_dir, snapshots_in(anon_dir)[0]),
                     encoding="utf-8") as handle:
            check(json.load(handle).get("anonymous") is True,
                  "the snapshot file records that it was read anonymously")
    finally:
        shutil.rmtree(gap_dir, ignore_errors=True)

    short_portal = FakePortal(catalog[:5], portal_groups, reported_total=10)
    short_read = serving(short_portal, lambda: search_items(
        PORTAL, "orgid:ORG123", "TESTTOKEN"))
    check(len(short_read[0]) == 5 and short_read[1] == 10 and short_read[2],
          "5 items read against a reported total of 10 is a short read, "
          "marked incomplete  <-- pinned defect")
    code, seen = captured(lambda: serving(short_portal, lambda: main(
        ["snapshot", "--url", PORTAL, "--token", "T0KEN"])))
    check("5 were read" in seen and "ceiling" not in seen,
          "the run says the snapshot is short, and does not blame the ceiling")
    no_id = dict(catalog[0])
    del no_id["id"]
    nameless = serving(FakePortal([no_id], []), lambda: search_items(
        PORTAL, "orgid:ORG123", "TESTTOKEN"))
    check(nameless[0] == {} and nameless[2] is True,
          "a row with no id is left out and the snapshot is marked incomplete, "
          "not keyed by None  <-- pinned defect")
    check("anonymous" not in whole
          and serving(portal, lambda: take_snapshot(
              PORTAL, "orgid:ORG123", None)).get("anonymous") is True,
          "a snapshot read with a token carries no anonymous key, one read "
          "without carries it")

    # ---- the mirror says nothing is the same only when something was compared
    toks = ["--old-token", "OLDT", "--new-token", "NEWT"]

    def quiet_pair(**kw):
        return (FakePortal([r for r in rows_of(old_mirror_items)
                            if not r["id"].startswith("o-dup")],
                           list(OLD_MIRROR["groups"].values()), org="OLDORG",
                           **kw),
                FakePortal([r for r in clone_rows if "dup" not in r["id"]],
                           clone_groups, org="NEWORG", **kw))

    q_old, q_new = quiet_pair()
    code, seen = run_mirror(q_old, q_new, toks)
    check(code == 0, "the quiet pair is quiet when both reads are whole")
    lone = [dict(item("n-a", "o", "private", day1, title="A"), _groups=[])]
    code, seen = run_mirror(FakePortal([], [], org="OLDORG"),
                            FakePortal(lone, [], org="NEWORG"), toks)
    check(code == 3 and "the old portal returned no items" in seen
          and "shares what the old one did" not in seen,
          "an old portal that returned nothing is not a clean mirror: a "
          "mistyped query exits 3  <-- pinned defect")
    code, seen = run_mirror(FakePortal([], [], org="OLDORG"),
                            FakePortal([], [], org="NEWORG"), toks)
    check(code == 3 and "the old portal returned no items" in seen
          and "the new portal returned no items" in seen,
          "two empty portals are not a clean mirror  <-- pinned defect")
    shown = dict(item("n-h", "o", "org", day1, title="Hidden"), _groups=[])
    code, seen = run_mirror(
        FakePortal([dict(lone[0], title="Other")], [], org="OLDORG"),
        FakePortal([shown, dict(lone[0], title="Other")], [], org="NEWORG"),
        toks)
    check(code == 1 and "mirror-new-shared" in seen
          and "shares what the old one did" not in seen,
          "an org item the old account cannot see is reported, not counted "
          "and called clean  <-- pinned defect")
    with env_set(TOKEN_ENV_OLD, "operator-value"):
        with _scrubbed_environment():
            hidden_away = TOKEN_ENV_OLD not in os.environ
        kept = os.environ.get(TOKEN_ENV_OLD) == "operator-value"
    check(hidden_away and kept,
          "the self-test hides the operator's SHAREWATCH_ variables and puts "
          "them back  <-- pinned defect")
    code, seen = run_mirror(*quiet_pair())
    check(code == 3 and "read without a token" in seen
          and "WARNING: no token" in seen
          and "shares what the old one did" not in seen,
          "a mirror read without tokens sees public items only and cannot "
          "say the portals match  <-- pinned defect")
    code, seen = run_mirror(*quiet_pair(), extra=["--old-token", "OLDT"])
    check(code == 3 and "the new snapshot was read without a token" in seen,
          "one anonymous side is enough to make the verdict a gap")
    code, seen = run_mirror(*quiet_pair(reported_total=SEARCH_CEILING),
                            extra=toks)
    check(code == 3 and "Cannot tell" in seen and "WARNING" in seen
          and "shares what the old one did" not in seen,
          "two portals read to the ceiling are not a clean mirror  "
          "<-- pinned defect")
    code, seen = run_mirror(*quiet_pair(reported_total=50), extra=toks)
    check(code == 3 and "holds 9 of the 50 item(s)" in seen,
          "a mirror side that paged short is not a clean mirror either  "
          "<-- pinned defect")

    # ---- a group's own sharing, which carries its contents with it
    def group_snap(taken, groups, found=()):
        return build_snapshot("u", taken, dict((i["id"], i) for i in found),
                              dict((g["id"], g) for g in groups), len(found),
                              False)

    def mirror_groups_of(old_groups, new_groups, found=()):
        return mirror_diff(group_snap("t", old_groups),
                           group_snap("t", new_groups, found))[0]

    exposed = mirror_groups_of([group("o-g", "private", title="Staff")],
                               [group("n-g", "public", title="staff")],
                               [item("n-i", "o", "private", day1,
                                     groups=["n-g"])])
    check(len(exposed) == 1 and exposed[0].kind == "mirror-public"
          and exposed[0].detail == "group access old private, new public"
          and exposed[0].item_count == 1 and exposed[0].group_title == "staff",
          "a group private on the old portal and public on the new one is "
          "reported with what is inside it  <-- pinned defect")
    wider = mirror_groups_of([group("o-g", "private", title="Staff")],
                             [group("n-g", "org", title="Staff")])
    check([ev.kind for ev in wider] == ["mirror-wider"]
          and wider[0].item_count == 0,
          "a group widened short of public is mirror-wider")
    narrower = mirror_groups_of([group("o-g", "public", title="Staff")],
                                [group("n-g", "private", title="Staff")])
    check([ev.kind for ev in narrower] == ["mirror-narrower"],
          "a group narrowed on the new portal is mirror-narrower")
    opened = mirror_groups_of([group("o-g", "org", "owner", title="Staff")],
                              [group("n-g", "org", "org", title="Staff")])
    check([ev.kind for ev in opened] == ["mirror-wider"]
          and "membershipAccess old owner, new org" in opened[0].detail,
          "a group that anyone in the org may join on the new portal only is "
          "reported")
    check(mirror_groups_of([group("o-g", "org", "org", title="Staff")],
                           [group("n-g", "org", "owner", title="Staff")]) == []
          and mirror_groups_of([group("o-g", "org", title="Staff")],
                               [group("n-g", "org", title="Staff")]) == []
          and mirror_groups_of([group("o-g", "org", title="Old")],
                               [group("n-g", "public", title="New")]) == [],
          "an unchanged group, a narrowed membershipAccess and a group with "
          "no twin are not reported")
    dup_old = mirror_groups_of([group("o-1", "private", title="Staff"),
                                group("o-2", "private", title="Staff")],
                               [group("n-g", "public", title="Staff")],
                               [item("n-i", "o", "private", day1,
                                     groups=["n-g"])])
    check([ev.kind for ev in dup_old] == ["mirror-ambiguous"]
          and "2 old and 1 new groups share this title" in dup_old[0].detail
          and dup_old[0].item_count == 1,
          "two groups sharing a title on the old side are reported, not "
          "skipped silently: a skip that says nothing reads as clean  "
          "<-- pinned defect")
    dup_new = mirror_groups_of([group("o-g", "private", title="Staff")],
                               [group("n-1", "public", title="Staff"),
                                group("n-2", "private", title="Staff")])
    check([ev.kind for ev in dup_new] == ["mirror-ambiguous"]
          and "1 old and 2 new groups share this title" in dup_new[0].detail,
          "two groups sharing a title on the new side are reported too  "
          "<-- pinned defect")
    g_old, g_new = mirror_pair()
    g_new.groups = [dict(g, access="public") if g["id"] == "n-g1" else g
                    for g in g_new.groups]
    code, seen = run_mirror(g_old, g_new, toks)
    check("group access old org, new public" in seen
          and "(2 item(s) inside)" in seen,
          "a public group on the new portal is reported in a real mirror run")
    q_old, q_new = quiet_pair()
    q_new.groups = [dict(g, access="public") if g["title"] == "Public Works"
                    else g for g in q_new.groups]
    code, seen = run_mirror(q_old, q_new, toks)
    check(code == 1 and "shares what the old one did" not in seen,
          "a portal whose only difference is a public group is not clean  "
          "<-- pinned defect")

    # ---- pairing keys and wording the sweep showed were unpinned
    typed = mirror_diff(
        build_snapshot("u", "t", {"a": item("a", "o", "public", day1,
                                            title="Roads")}, {}, 1, False),
        build_snapshot("u", "t", {"b": item("b", "o", "private", day1,
                                            title="Roads", kind="Map Service")},
                       {}, 1, False))
    check([ev.kind for ev in typed[0]] == ["mirror-missing"]
          and typed[1]["paired"] == 0 and typed[1]["new_only"] == 1,
          "one title with two types is two items, not a narrowing  "
          "<-- pinned defect")
    absent = mirror_diff(
        build_snapshot("u", "t", {"a": item("a", "o", "private", day1,
                                            title="Hidden"),
                                  "b": item("b", "o", "org", day1,
                                            title="Seen")}, {}, 2, False),
        build_snapshot("u", "t", {}, {}, 0, False))[0]
    check(sorted(ev.detail for ev in absent)
          == ["private on the old portal, absent on the new one",
              "shared org on the old portal, absent on the new one"],
          "a private item missing from the new portal is not described as "
          "shared private")

    # ---- saved share answers that say nothing are refused, not called clean
    for bad, why in (({}, "an empty object"),
                     ({"errors": [{"code": 1}]}, "an errors key"),
                     ({"itemId": "a"}, "an answer with no outcome in it"),
                     ({"itemId": "a", "success": 0}, "success 0"),
                     ({"itemId": "a", "success": "false"}, "success 'false'"),
                     ({"itemId": "a", "success": None}, "success null")):
        raises(lambda: share_results([bad]),
               "%s is refused, not read as a success  <-- pinned defect" % why)
    check(share_results([]) == [] and share_results([{"results": []}]) == [],
          "an empty list of answers flattens to nothing, and the caller "
          "refuses nothing")
    check(len(share_results([{"results": [{"itemId": "a", "success": True}],
                              "notSharedWith": ["g"]}])) == 2,
          "a notSharedWith next to a results list is read too  "
          "<-- pinned defect")
    one_group = share_response_findings(
        [{"itemId": "n-roads", "results": [], "notSharedWith": ["n-g1"]}],
        NEW_MIRROR)
    check(len(one_group) == 1 and "not shared with n-g1" in one_group[0].detail,
          "a top-level notSharedWith is a finding")
    for reply, tail in (({"itemId": "n-roads", "error": "denied"}, "denied"),
                        ({"itemId": "n-roads", "error": True}, "True")):
        found = share_response_findings([reply], NEW_MIRROR)
        check(len(found) == 1 and found[0].detail.endswith(tail),
              "an error that is not an object (%s) is a failed share, not a "
              "success  <-- pinned defect" % tail)
    flagged = share_response_findings(
        [{"itemId": "n-roads", "success": True},
         {"itemId": "n-zone", "success": False}], NEW_MIRROR)
    check(len(flagged) == 1 and flagged[0].items[0]["id"] == "n-zone",
          "success false is flagged and success true is not  "
          "<-- pinned defect")

    reply_dir = tempfile.mkdtemp(prefix="sharewatch-replies-")
    try:
        def reply_file(name, raw):
            path = os.path.join(reply_dir, name)
            with io.open(path, "wb") as handle:
                handle.write(raw)
            return path

        for name, raw, why in (
                ("empty-list.json", b"[]", "an empty list"),
                ("empty-object.json", b"{}", "an empty object"),
                ("no-results.json", b'{"results": []}', "an empty batch"),
                ("null.json", b"null", "a JSON null"),
                ("number.json", b"5", "a bare number"),
                ("success-string.json", b'{"success": "false"}', "success 'false'")):
            pre_old, pre_new = mirror_pair()
            code, seen = run_mirror(pre_old, pre_new, extra=[
                "--responses", reply_file(name, raw)])
            check(code == 64 and "error:" in seen and not pre_old.targets,
                  "--responses holding %s is a usage error before any portal "
                  "is read  <-- pinned defect" % why)
        code, seen = run_mirror(*mirror_pair(), extra=["--responses", reply_file(
            "bom.json", b"\xef\xbb\xbf" + json.dumps(
                {"itemId": "n-roads", "notSharedWith": ["n-g9"]}).encode(
                    "utf-8"))])
        check("not shared with n-g9" in seen,
              "a responses file saved with a byte order mark is read")
    finally:
        shutil.rmtree(reply_dir, ignore_errors=True)

    # ---- a credential in its url-encoded form is redacted too
    check(redact("a ab%2Bcd%2Fef%3Dgh b ab+cd/ef=gh c", "ab+cd/ef=gh")
          == "a [redacted] b [redacted] c" and redact("x ab+cd y", "ab+cd")
          == "x [redacted] y",
          "a secret is removed in its raw form and in its percent-encoded and "
          "plus-encoded forms  <-- pinned defect")
    probe_portal = FakePortal(org="PROBE")
    with listening(probe_portal, probe_portal,
                   hosts=["127.0.0.1", "127.0.0.2"]) as (pp, pq):
        StubHandler.bounce_to = "http://127.0.0.2:%d" % pq
        encoded = fails(lambda: _call("http://127.0.0.1:%d" % pp, "bounce",
                                      {"token": "ab+cd/ef=gh"},
                                      pin_host="127.0.0.1"),
                        "a redirect off the verified host is refused")
    check("leaves the verified host" in encoded and REDACTED in encoded
          and "ab%2Bcd" not in encoded and "ef%3Dgh" not in encoded
          and "ab+cd" not in encoded,
          "the redirect error quotes the Location url, and the encoded token "
          "in it is redacted  <-- pinned defect")
    spaced = fails(lambda: _call("http://127.0.0.1:9/a b", "search",
                                 {"token": "tk=en/ab+cd"}),
                   "a url http.client rejects is raised as an error")
    check("tk%3Den" not in spaced and "ab%2Bcd" not in spaced
          and "tk=en" not in spaced and REDACTED in spaced,
          "an InvalidURL error that quotes the request path carries no token  "
          "<-- pinned defect")

    # ---- a portal that answers something that is not an object
    class Canned(object):
        """An opener that answers every call with one fixed body."""

        def __init__(self, body=None, raising=None):
            self.body, self.raising = body, raising

        def __call__(self, insecure, pin_host=None):
            return self

        def open(self, target, data=None, timeout=None):
            if self.raising is not None:
                raise self.raising
            return FakeResponse(self.body)

    for body, why in (([1, 2], "a JSON list"), (None, "a JSON null"),
                      (5, "a bare number")):
        said = fails(lambda: serving(Canned(body), lambda: _call(
            PORTAL, "portals/self", {"token": "SECRETTOKEN"})),
            "%s from the portal is an error" % why)
        check("not an object" in said and "SECRETTOKEN" not in said,
              "%s is named in the error and carries no token  "
              "<-- pinned defect" % why)
    said = fails(lambda: serving(Canned({"error": "denied"}), lambda: _call(
        PORTAL, "search", {})), "an error that is a bare string is raised")
    check(said.endswith("denied"), "the bare error text reaches the operator")
    code, seen = captured(lambda: serving(Canned([]), lambda: main(
        ["snapshot", "--url", PORTAL, "--token", "T0KEN"])))
    check(code == 2 and "error:" in seen,
          "a portal answering a JSON list exits 2, not with a traceback  "
          "<-- pinned defect")
    code, seen = captured(lambda: serving(
        Canned({"total": 1, "results": "x"}), lambda: main(
            ["snapshot", "--url", PORTAL, "--token", "T0KEN", "--query", "q"])))
    check(code == 2 and "unexpected AttributeError" in seen,
          "any other surprise ends as exit 2 with a message, because exit 1 "
          "means findings  <-- pinned defect")
    code, seen = captured(lambda: serving(
        Canned(raising=KeyboardInterrupt()), lambda: main(
            ["snapshot", "--url", PORTAL, "--token", "T0KEN"])))
    check(code == 130 and "interrupted" in seen and "Traceback" not in seen,
          "Ctrl+C ends with one line and exit 130")

    def usage_code(argv):
        saved_err, sys.stderr = sys.stderr, io.StringIO()
        exit_status = None
        try:
            _parse(argv)
        except SystemExit as exc:
            exit_status = exc.code
        finally:
            sys.stderr = saved_err
        return exit_status

    check(usage_code(["bogus"]) == 64 and usage_code(["snapshot", "--ap"]) == 64
          and usage_code(["diff", "--window-minutes", "x"]) == 64
          and usage_code(["snapshot", "--apply=1"]) == 64
          and usage_code(["snapshot", "--a"]) == 64,
          "an unknown mode, a refused prefix and a bad number all exit 64, "
          "not argparse's 2, which here means the portal failed  "
          "<-- pinned defect")

    # ---- a token from the environment, so it need not sit in argv
    with env_set(TOKEN_ENV, "ENVTOKEN"):
        check(_authenticate(_parse(["snapshot", "--url", PORTAL]))
              == "ENVTOKEN",
              "a token is read from %s when there is no flag" % TOKEN_ENV)
        check(_authenticate(_parse(["snapshot", "--url", PORTAL, "--token",
                                    "FLAGTOKEN"])) == "FLAGTOKEN",
              "a --token flag wins over the environment")
    check(TOKEN_ENV not in os.environ,
          "the borrowed token variable is removed again")
    with env_set(TOKEN_ENV_OLD, "OLDENV"), env_set(TOKEN_ENV_NEW, "NEWENV"):
        e_old, e_new = mirror_pair()
        code, seen = run_mirror(e_old, e_new)
        check(code == 1 and all("token=OLDENV" in t for t in e_old.targets)
              and all("token=NEWENV" in t for t in e_new.targets)
              and "OLDENV" not in seen and "NEWENV" not in seen,
              "each mirror side reads its own token variable and prints "
              "neither  <-- pinned defect")
    with env_set(SECRET_ENV_OLD, "old-pass"), env_set(SECRET_ENV_NEW,
                                                      "new-pass"):
        p_old, p_new = mirror_pair()
        p_old.password, p_new.password = "old-pass", "new-pass"
        code, seen = run_mirror(p_old, p_new, ["--old-username", "ou",
                                               "--new-username", "nu"])
        check(code == 1 and "password=old-pass" in p_old.posted[0]
              and "password=new-pass" in p_new.posted[0],
              "the old portal is signed in with the old password and the new "
              "portal with the new one  <-- pinned defect")

    # ---- pure-core controls the mutation sweep showed could not fail
    left = diff_snapshots(
        build_snapshot("u", "t", {"a": item("a", "o", "org", day1,
                                            groups=["g"])}, {}, 1, False),
        build_snapshot("u", "t", {"a": item("a", "o", "org", day1)}, {}, 1,
                       False))
    check([ev.kind for ev in left] == ["item-left-group"]
          and left[0].group == "g",
          "an item that left a group is reported, with the group  "
          "<-- pinned defect")
    spread = [{"when": n * minute, "item": {"id": str(n)}} for n in (0, 2, 4)]
    check([len(b) for b in _bucket(spread, minute)] == [1, 1, 1],
          "each time bucket holds only its own findings, not the ones before "
          "it  <-- pinned defect")
    edge = [{"when": 0}, {"when": 60 * minute}]
    check(len(_bucket(edge, 60 * minute)) == 1
          and len(_bucket([{"when": 0}, {"when": 60 * minute + 1}],
                          60 * minute)) == 2,
          "two findings exactly one window apart are one event, one "
          "millisecond more are two")
    check(len(_bucket([{"when": 5}, {"when": 5}], 0)) == 1
          and len(_bucket([{"when": 5}, {"when": 6}], 0)) == 2
          and len(collapse([], 0)) == 0,
          "a window of zero merges findings with the same timestamp only")
    twenty = Event("new-item", "o", "d", [{"id": str(n)} for n in range(20)])
    check(len(describe([twenty])) == 21 and not any(
        "more" in line for line in describe([twenty])),
        "exactly 20 items are all listed with no 'and more' line")
    check(clamp_num(1) == 1, "a page size of one is allowed")
    check(newest_snapshot(["sharewatch-report.txt", "other.json",
                           "sharewatch-20260101T000000Z.json"])
          == "sharewatch-20260101T000000Z.json"
          and newest_snapshot(["sharewatch-report.txt", "other.json"]) is None,
          "a saved report next to the snapshots is never the baseline  "
          "<-- pinned defect")
    public_group = FakePortal([], [{"id": "gp", "title": "Open", "owner": "o",
                                    "access": "public",
                                    "membershipAccess": None}])
    check(serving(public_group, lambda: search_groups(
        PORTAL, "orgid:ORG123", "TESTTOKEN"))["gp"]["access"] == "public",
        "a group's access is read from the portal, not forced to private  "
        "<-- pinned defect")
    many_groups = FakePortal([], [{"id": "g%03d" % n, "title": "G", "owner": "o",
                                   "access": "org", "membershipAccess": None}
                                  for n in range(150)])
    check(len(serving(many_groups, lambda: search_groups(
        PORTAL, "orgid:ORG123", "TESTTOKEN"))) == 150,
        "150 groups are read across two pages  <-- pinned defect")
    real_self_test = globals()["self_test"]
    globals()["self_test"] = lambda: 7
    try:
        self_code = main(["--self-test"])
    finally:
        globals()["self_test"] = real_self_test
    check(self_code == 7,
          "main hands back the self-test's own exit code  <-- pinned defect")

    # ---- the harness itself, which has to be able to report red
    #
    # A self-test whose failure path is never exercised is not a control: it
    # reports green because nothing ever calls the other branch. The harness is
    # run here against six deliberate failures, with its output swallowed and
    # its tally put back, so that a green run has still proven it can go red.
    def probe():
        check(False, "a false check must be recorded as a failure")
        raises(lambda: None, "a function that raises nothing must fail")
        raises(lambda: 1 / 0, "a function that raises the wrong thing must fail")
        refuses(["--self-test"], "an argv argparse accepts must fail")
        return [fails(lambda: None, "a call that does not raise must fail"),
                fails(lambda: 1 / 0, "a call that raises the wrong thing must fail")]

    kept_passed, kept_failed = passed[0], list(failed)
    returned, noise = captured(probe)
    probe_passed, probe_failed = passed[0], list(failed)
    passed[0], failed[:] = kept_passed, kept_failed
    check(len(probe_failed) - len(kept_failed) == 6,
          "the harness records a false check, a missing exception, a wrong "
          "exception, an argv argparse accepted and two failed portal calls "
          "as six failures, so a broken tool turns this self-test red  "
          "<-- pinned defect")
    check(probe_passed == kept_passed,
          "not one of those six was counted as a pass")
    check(noise.count("FAIL  ") == 6,
          "every recorded failure prints a FAIL line the operator can see")
    check(returned == ["", ""],
          "a portal call that did not raise yields no message to assert on")

    # The verdict is pure, so its red branch is exercised here with a made-up
    # failure instead of being reachable only when the tool is already broken.
    check(_verdict(5, []) == (["5 assertions, 0 failed"], 0),
          "a clean tally prints one line and exits 0")
    check(_verdict(2, ["x"]) == (["3 assertions, 1 failed", "  FAILED: x"], 1),
          "a failed tally lists the failure and exits 1  <-- pinned defect")
    modules = runpy.run_path(os.path.abspath(__file__), run_name="sharewatch_import")
    check(callable(modules["main"]),
          "importing the file runs nothing and does not exit")

    print("-" * 68)
    lines, code = _verdict(passed[0], failed)
    for line in lines:
        print(line)
    return code


def _verdict(passed, failed):
    """The closing lines of the self-test and its exit code."""
    total = passed + len(failed)
    if failed:
        return (["%d assertions, %d failed" % (total, len(failed))]
                + ["  FAILED: %s" % f for f in failed]), 1
    return ["%d assertions, 0 failed" % total], 0


# ----------------------------------------------------------------------- cli

class _Parser(argparse.ArgumentParser):
    """An argument parser whose usage errors exit 64, like every other usage error.

    argparse exits 2 on its own, and 2 here means the portal call failed. A
    scheduler that alerts on 2 would read a typo as a portal outage.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(64, "%s: error: %s\n" % (self.prog, message))


def _parse(argv):
    ap = _Parser(
        prog="sharewatch.py",
        allow_abbrev=False,
        description="Diff an ArcGIS organization's sharing posture against "
                    "yesterday, because the platform keeps no audit log.",
        epilog="Read-only. There is no flag that changes sharing. The password "
               "is never a flag: export %s or answer the prompt." % SECRET_ENV,
    )
    ap.add_argument("mode", nargs="?", choices=["snapshot", "diff", "watch", "mirror"],
                    help="snapshot writes one, diff compares two, watch takes a "
                         "fresh one and compares it with the newest in --dir, "
                         "mirror compares two portals and writes nothing")
    ap.add_argument("paths", nargs="*", default=[],
                    help="for diff: the older snapshot then the newer one")
    ap.add_argument("--url", help="portal url, e.g. https://county.maps.arcgis.com")
    ap.add_argument("--query",
                    help="search query (default: orgid of the signed-in org)")
    ap.add_argument("--token",
                    help="an existing portal token. A flag is readable in argv "
                         "and shell history, so prefer %s." % TOKEN_ENV)
    ap.add_argument("--username",
                    help="generate a token for this user. The password comes "
                         "from %s or an unechoed prompt, never from argv."
                         % SECRET_ENV)
    ap.add_argument("--old-url", dest="old_url",
                    help="mirror: the portal being left, including https://")
    ap.add_argument("--new-url", dest="new_url",
                    help="mirror: the portal being checked, including https://")
    ap.add_argument("--verify-host", dest="verify_host",
                    help="mirror: the bare host name the new portal must be on. "
                         "The run is refused if --new-url is another host, if "
                         "--old-url is this host, if the new portal declares a "
                         "different host, or if a redirect leaves the host.")
    ap.add_argument("--old-token", dest="old_token",
                    help="mirror: an existing token for the old portal (or "
                         "%s)" % TOKEN_ENV_OLD)
    ap.add_argument("--new-token", dest="new_token",
                    help="mirror: an existing token for the new portal (or "
                         "%s)" % TOKEN_ENV_NEW)
    ap.add_argument("--old-username", dest="old_username",
                    help="mirror: generate a token on the old portal. The "
                         "password comes from %s or a prompt." % SECRET_ENV_OLD)
    ap.add_argument("--new-username", dest="new_username",
                    help="mirror: generate a token on the new portal. The "
                         "password comes from %s or a prompt." % SECRET_ENV_NEW)
    ap.add_argument("--old-query", dest="old_query",
                    help="mirror: search query on the old portal (default: "
                         "its org id)")
    ap.add_argument("--new-query", dest="new_query",
                    help="mirror: search query on the new portal (default: "
                         "its org id)")
    ap.add_argument("--responses",
                    help="mirror: a JSON file of share-call responses saved by "
                         "the migration script, checked for notSharedWith")
    ap.add_argument("--out", help="directory to write the snapshot into")
    ap.add_argument("--dir", help="directory of snapshots, for watch")
    ap.add_argument("--window-minutes", dest="window_minutes", type=int,
                    default=DEFAULT_WINDOW_MINUTES,
                    help="minutes within which one owner's changes collapse "
                         "into one event (default %d)" % DEFAULT_WINDOW_MINUTES)
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification, for an Enterprise "
                         "portal behind an internal CA. Refused together with "
                         "--username.")
    ap.add_argument("--apply", action="store_true",
                    help="write the snapshot file. Without this the org is read "
                         "and reported on, and nothing is written.")
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="run the offline assertions and exit")
    return ap.parse_args(argv)


def _sign_in(url, token, username, insecure, env=SECRET_ENV, pin_host=None,
             token_env=TOKEN_ENV):
    """Return a token, or None for an anonymous read.

    A token comes from the flag, else from the environment variable, so that it
    need not sit in argv.
    """
    token = token or os.environ.get(token_env)
    if token:
        return token
    if not username:
        return None
    secret = read_secret(username, env)
    return generate_token(url, username, secret, insecure, pin_host)


def _authenticate(args):
    """Return a token, or None for an anonymous read."""
    return _sign_in(args.url, args.token, args.username, args.insecure,
                    pin_host=host_of(args.url))


def _snapshot(args):
    """Take a snapshot and print what it covers. Returns (snapshot, path)."""
    token = _authenticate(args)
    # Pinned like mirror: a redirect to another host would carry the token there
    # and record that host's answer as this portal's snapshot.
    pin = host_of(args.url)
    query = args.query
    if not query:
        oid = org_id(args.url, token, args.insecure, pin)
        if not oid:
            raise RuntimeError("could not read the org id, pass --query")
        query = "orgid:%s" % oid
    return _read(args.url, token, query, args.insecure, pin)


def _read(url, token, query, insecure, pin_host=None):
    """Read one org into a snapshot and print what it covers."""
    print("reading %s" % url)
    print("query: %s" % query)
    snapshot = take_snapshot(url, query, token, insecure,
                             echo=lambda line: print(line), pin_host=pin_host)
    print("%d item(s), %d group(s), reported total %d"
          % (len(snapshot["items"]), len(snapshot["groups"]),
             snapshot["reported_total"]))
    if not token:
        print("WARNING: no token, so this read sees public items only.")
    if snapshot["truncated"] and snapshot["reported_total"] >= SEARCH_CEILING:
        print("")
        print("WARNING: the result set reached the %d row ceiling. search "
              "cannot page past it" % SEARCH_CEILING)
        print("and its total is an estimate, so this snapshot covers an "
              "unknown fraction of the org.")
        print("Narrow --query and take several snapshots instead.")
    elif snapshot["truncated"]:
        print("")
        print("WARNING: the portal reported %d item(s) and %d were read, so "
              "this snapshot is incomplete."
              % (snapshot["reported_total"], len(snapshot["items"])))
        print("Paging a live portal is not atomic. Run it again.")
    return snapshot


def _empty_read(snapshot):
    """Exit code of a snapshot or baseline run: 3 when it holds no items.

    A mistyped query or an account that sees nothing reads as an empty org, and
    every later diff of two empty reads would be "no changes".
    """
    if snapshot["items"]:
        return 0
    print("\nWARNING: the read returned no items, so it proves nothing. Check "
          "--query and the account.")
    return 3


def _write(snapshot, directory, apply_it):
    """Write the snapshot when --apply is given. Raises OSError if it cannot."""
    if not apply_it:
        print("\nCheck only. No snapshot was written. Re-run with --apply.")
        return None
    path = write_snapshot(snapshot, directory, utcnow())
    print("\nwrote %s" % path)
    return path


def _report(old, new, window_minutes):
    """Print the diff. Returns the exit code: 1 for anything to read, 3 for
    nothing found by a read that could not prove it, 0 for a proven quiet day."""
    print("\n%s  ->  %s" % (old.get("taken"), new.get("taken")))
    print("-" * 68)
    for line in truncation_warning(old, new):
        print(line)
    try:
        events = diff_snapshots(old, new, window_minutes)
    except ValueError as exc:
        # access_rank refuses a level it does not know rather than sorting it to
        # private and so calling it safe. That refusal used to reach the
        # operator as a traceback, which reads like a broken tool instead of a
        # portal release this version has not been taught about.
        print("error: %s. A snapshot holds a sharing level this version does "
              "not know, so the comparison would be wrong." % exc,
              file=sys.stderr)
        return 64
    encoding = getattr(sys.stdout, "encoding", None)
    gaps = coverage_gaps(old, new)
    quiet = verdict_text(gaps, "No sharing changes between the two snapshots.")
    for line in describe(events, quiet):
        print(printable(line, encoding))
    return exit_code(events, bool(gaps))


def load_responses(path):
    """Read a file of saved share responses: one JSON object, or a list of them.

    utf-8-sig, because Windows PowerShell writes a byte order mark that plain
    utf-8 hands to the JSON parser as an error.
    """
    with io.open(path, "r", encoding="utf-8-sig") as handle:
        bodies = json.load(handle)
    if isinstance(bodies, dict):
        return [bodies]
    if isinstance(bodies, list):
        return bodies
    raise ValueError("%s has to hold a JSON object or a list of them" % path)


def _open_side(args, side, verify):
    """Sign in to one portal and prove which portal it is, before reading it.

    The new side has to declare the verified host, and the old side must not.
    Both are proved before either is read, so a wrong url costs no paging.
    Returns what the read needs: url, token, the pinned host and portals/self.
    """
    url = getattr(args, side + "_url")
    pin = host_of(url)
    env = SECRET_ENV_OLD if side == "old" else SECRET_ENV_NEW
    token = _sign_in(url, getattr(args, side + "_token"),
                     getattr(args, side + "_username"), args.insecure, env, pin,
                     TOKEN_ENV_OLD if side == "old" else TOKEN_ENV_NEW)
    described = portal_self(url, token, args.insecure, pin)
    declared = declared_hosts(described)
    if side == "new" and verify not in declared:
        raise RuntimeError("the new portal declares %s, not the verified host "
                           "%s. Refusing to compare." % (
                               ", ".join(sorted(declared)) or "no host", verify))
    if side == "old" and verify in declared:
        raise RuntimeError("the old url answers as the verified host %s. "
                           "Refusing to compare." % verify)
    return url, token, pin, described


def _read_side(args, side, opened):
    """Read one proved portal into a snapshot. Each side is pinned to its host."""
    url, token, pin, described = opened
    query = getattr(args, side + "_query")
    if not query:
        if not described.get("id"):
            raise RuntimeError("could not read the org id of the %s portal, "
                               "pass --%s-query" % (side, side))
        query = "orgid:%s" % described["id"]
    print("\n%s portal on host %s" % (side, pin))
    return _read(url, token, query, args.insecure, pin)


def _mirror(args):
    """Compare two portals, read-only. Exit 0 identical sharing, 1 findings."""
    for flag in ("old_url", "new_url", "verify_host"):
        if not getattr(args, flag):
            print("error: --%s is required for mirror." % flag.replace("_", "-"),
                  file=sys.stderr)
            return 64
    if args.apply:
        print("error: mirror writes nothing, so --apply has no meaning here.",
              file=sys.stderr)
        return 64
    for url in (args.old_url, args.new_url):
        if not is_http_url(url):
            print("error: a portal url must start with https:// or http://, "
                  "got %r." % url, file=sys.stderr)
            return 64
    try:
        verify = check_hosts(args.old_url, args.new_url, args.verify_host)
        bodies = load_responses(args.responses) if args.responses else []
        if args.responses and not share_results(bodies):
            raise ValueError("%s holds no share responses" % args.responses)
    except (IOError, OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 64
    try:
        opened_old = _open_side(args, "old", verify)
        opened_new = _open_side(args, "new", verify)
        old = _read_side(args, "old", opened_old)
        new = _read_side(args, "new", opened_new)
    except RuntimeError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    print("\nold %s  ->  new %s (verified host %s)"
          % (host_of(args.old_url), host_of(args.new_url), verify))
    print("-" * 68)
    for line in truncation_warning(old, new, ("old", "new")):
        print(line)
    try:
        events, stats = mirror_diff(old, new, args.window_minutes)
        events = rank_events(events + share_response_findings(bodies, new))
    except ValueError as exc:
        print("error: %s. The comparison would be wrong." % exc, file=sys.stderr)
        return 64
    print("%(paired)d paired, %(old_only)d only on the old portal, %(new_only)d "
          "only on the new, %(ambiguous)d not compared (ambiguous title)" % stats)
    # Nothing compared is not a match. A mistyped query or an account that sees
    # nothing leaves a side empty, and "the new portal shares what the old one
    # did" would be a false sentence. An empty old side is the dangerous one:
    # private items that exist only on the new portal are counted, never
    # reported.
    gaps = coverage_gaps(old, new, ("old", "new"),
                         "the %s portal returned no items")
    encoding = getattr(sys.stdout, "encoding", None)
    quiet = verdict_text(gaps, "The new portal shares what the old one did.")
    for line in describe(events, quiet):
        print(printable(line, encoding))
    return exit_code(events, bool(gaps))


def main(argv=None):
    """Run one command. Every way out is an exit code a scheduler can read.

    An uncaught exception would end as a traceback with exit code 1, which is
    also "findings to read". Anything not handled below is reported and exits 2.
    """
    args = _parse(sys.argv[1:] if argv is None else argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        print("interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print("error: unexpected %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return 2


def _run(args):
    if args.self_test:
        return self_test()

    if not args.mode:
        print("error: a mode is required: snapshot, diff, watch or mirror. Use "
              "--self-test to verify the tool without a portal.", file=sys.stderr)
        return 64
    if args.window_minutes < 0:
        print("error: --window-minutes cannot be negative.", file=sys.stderr)
        return 64
    if args.insecure and (args.username or args.old_username
                          or args.new_username):
        print("error: --insecure with --username would post your password down "
              "an unverified connection. Pass a token in %s instead."
              % TOKEN_ENV, file=sys.stderr)
        return 64

    if args.mode == "mirror":
        return _mirror(args)

    if args.mode == "diff":
        if len(args.paths) != 2:
            print("error: diff takes exactly two snapshot files, older first.",
                  file=sys.stderr)
            return 64
        try:
            old = load_snapshot(args.paths[0])
            new = load_snapshot(args.paths[1])
        except (IOError, OSError, ValueError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 64
        return _report(old, new, args.window_minutes)

    if not args.url:
        print("error: --url is required for %s." % args.mode, file=sys.stderr)
        return 64
    if not is_http_url(args.url):
        print("error: --url must start with https:// or http://, got %r. "
              "urllib quotes a url it cannot open back into its own error, "
              "and that url carries the token." % args.url, file=sys.stderr)
        return 64

    if args.mode == "snapshot":
        if args.apply and not args.out:
            print("error: --apply needs --out, a directory to write into.",
                  file=sys.stderr)
            return 64
        try:
            snapshot = _snapshot(args)
            _write(snapshot, args.out or ".", args.apply)
        except (RuntimeError, OSError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        return _empty_read(snapshot)

    # watch: a fresh snapshot against the newest file already in --dir
    if not args.dir:
        print("error: watch needs --dir, the directory of snapshots.",
              file=sys.stderr)
        return 64
    previous = None
    if os.path.isdir(args.dir):
        name = newest_snapshot(os.listdir(args.dir))
        if name:
            previous = os.path.join(args.dir, name)
    try:
        snapshot = _snapshot(args)
    except RuntimeError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    # The baseline is read before the fresh snapshot is written, because two
    # runs inside the same second produce the same file name and the write
    # lands on the very file this diff is against. Reading it afterwards
    # compared the new snapshot with itself and reported a clean day.
    baseline, unreadable = None, None
    if previous:
        try:
            baseline = load_snapshot(previous)
        except (IOError, OSError, ValueError) as exc:
            unreadable = exc
    # A snapshot that cannot be written must not hide the diff, which is the
    # evidence this run exists to produce. It is reported, and it decides the
    # exit code only when there is nothing more urgent to say.
    write_failed = False
    try:
        _write(snapshot, args.dir, args.apply)
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        write_failed = True
    if unreadable is not None:
        # Written first: the org has already been read, and throwing that away
        # because yesterday's file is corrupt loses today's evidence as well.
        print("error: %s" % unreadable, file=sys.stderr)
        return 64
    if baseline is None:
        if not args.apply:
            # Nothing was written, so the next run finds no baseline either.
            # "This one is the baseline" would be false, and exit 0 would let a
            # schedule that lacks --apply report a quiet org forever.
            print("\nNo earlier snapshot in %s, and without --apply none is "
                  "written, so nothing was compared. Run once with --apply "
                  "to write the baseline." % args.dir)
            return 3
        print("\nNo earlier snapshot in %s. This one is the baseline." % args.dir)
        return 2 if write_failed else _empty_read(snapshot)
    print("\nbaseline: %s" % previous)
    code = _report(baseline, snapshot, args.window_minutes)
    return 2 if write_failed and code != 1 else code


if __name__ == "__main__":
    sys.exit(main())
