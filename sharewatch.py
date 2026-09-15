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

    python sharewatch.py --self-test
    python sharewatch.py snapshot --url https://county.maps.arcgis.com --out snaps/ --apply
    python sharewatch.py diff snaps/sharewatch-20260914T060000Z.json snaps/sharewatch-20260915T060000Z.json
    python sharewatch.py watch --url https://county.maps.arcgis.com --dir snaps/ --apply

Exit codes: 0 nothing widened, 1 findings to review, 2 the portal call failed,
64 usage error.
"""

from __future__ import print_function

import argparse
import datetime
import getpass
import io
import json
import os
import ssl
import sys
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

# =============================================================================
# End of CONFIGURATION.
# =============================================================================

# Sharing levels, ordered. "shared" is an item shared to groups but not to the
# organization, which the REST API reports as its own access value.
ACCESS_RANK = {"private": 0, "shared": 1, "org": 2, "public": 3}

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
}

# Kinds whose timestamp is not evidence of when the change happened, so they are
# collapsed per owner without a time window. A deleted item leaves no deletion
# date behind, only the modified date it had while it existed, and adding an item
# to a group does not bump modified at all. Bucketing either one by time splits
# a single bulk action into one event per item: 60 items deleted in one go were
# reported as 60 events, dated by edits years apart.
UNTIMED_KINDS = frozenset(["item-deleted", "item-joined-group", "item-left-group"])

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


def truncation_warning(old, new):
    """Lines warning that a snapshot in this diff is incomplete.

    A truncated snapshot holds an unknown subset of the org, so every item the
    other snapshot has and this one lacks reads as a deletion. That is the false
    clean day running backwards: instead of hiding 60 deletions it invents
    thousands. The diff still runs, because the widenings in it are real.
    """
    lines = []
    for label, snapshot in (("older", old), ("newer", new)):
        if snapshot.get("truncated"):
            lines.append("WARNING: the %s snapshot reached the %d result "
                         "ceiling." % (label, SEARCH_CEILING))
    if lines:
        lines.append("It covers an unknown fraction of the org, so deletions "
                     "and new items below may")
        lines.append("be paging artefacts. Narrow --query and snapshot again.")
    return lines


def exit_code(events):
    """0 when there is nothing to read, 1 when there is."""
    return 1 if events else 0


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
            out = out.replace("%s" % (secret,), REDACTED)
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


def build_snapshot(url, taken, items, groups, total, truncated):
    """Assemble the snapshot document. No credential ever enters it."""
    return {
        "sharewatch": 1,
        "url": url,
        "taken": taken,
        "reported_total": total,
        "truncated": bool(truncated),
        "items": items,
        "groups": groups,
    }


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

    # Worst first, then the biggest blast radius, so the top line is the line to
    # act on. The owner and kind tail-break only to keep the order stable.
    events.sort(key=lambda e: (-e.severity,
                               -(e.item_count or len(e.items)),
                               e.owner, e.kind))
    return events


def describe(events):
    """Render events as the lines the CLI prints."""
    if not events:
        return ["No sharing changes between the two snapshots."]
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


# ---------------------------------------------------------------- portal i/o

def _opener(insecure):
    """Build a urllib opener, optionally without certificate verification.

    Enterprise portals behind an internal CA are the reason --insecure exists.
    It is off by default and refused together with a password, because posting
    credentials down an unverified connection is the failure it would cause.
    """
    if not insecure:
        return urllib.request.build_opener()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))


def _call(url, path, params, insecure=False, post=False, secret=None):
    """One REST call returning parsed JSON, with the portal's own errors raised.

    The portal answers HTTP 200 with an error object in the body, so the status
    code proves nothing and the body has to be read every time.
    """
    params = dict(params)
    params["f"] = "json"
    endpoint = "%s/sharing/rest/%s" % (url.rstrip("/"), path.lstrip("/"))
    data = urllib.parse.urlencode(params).encode("utf-8")
    opener = _opener(insecure)
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
    if isinstance(body, dict) and "error" in body:
        err = body["error"]
        raise RuntimeError(redact("%s: %s %s" % (endpoint, err.get("code"),
                                                 err.get("message")), secret,
                                  params.get("token"),
                                  params.get("password")))
    return body


def read_secret(username):
    """Get the password from the environment, or prompt for it.

    Never from argv. getpass keeps it off the screen, and it is passed on to
    redact() so that nothing downstream can print it back out.
    """
    secret = os.environ.get(SECRET_ENV)
    if secret:
        return secret
    return getpass.getpass("password for %s (not echoed): " % username)


def generate_token(url, username, secret, insecure=False):
    """Exchange a username and password for a short-lived token."""
    body = _call(url, "generateToken", {
        "username": username,
        "password": secret,
        "client": "referer",
        "referer": url,
        "expiration": 60,
    }, insecure=insecure, post=True, secret=secret)
    token = body.get("token")
    if not token:
        raise RuntimeError("generateToken returned no token")
    return token


def org_id(url, token, insecure=False):
    params = {"token": token} if token else {}
    body = _call(url, "portals/self", params, insecure=insecure)
    return body.get("id")


def search_items(url, query, token, insecure=False, echo=None):
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
        body = _call(url, "search", params, insecure=insecure)
        total = int(body.get("total") or 0)
        results = body.get("results") or []
        for raw in results:
            items[raw.get("id")] = item_record(raw)
        if echo:
            echo("  %d of %d item(s)" % (len(items), total))
        start = next_start(start, len(results), total)
    return items, total, is_truncated(total)


def search_groups(url, query, token, insecure=False):
    """Page /sharing/rest/community/groups the same way search is paged."""
    groups = {}
    start = 1
    while start is not None:
        params = {"q": query, "start": start, "num": clamp_num(SEARCH_MAX_NUM)}
        if token:
            params["token"] = token
        body = _call(url, "community/groups", params, insecure=insecure)
        total = int(body.get("total") or 0)
        results = body.get("results") or []
        for raw in results:
            groups[raw.get("id")] = group_record(raw)
        start = next_start(start, len(results), total)
    return groups


def attach_groups(url, items, groups, token, insecure=False, echo=None):
    """Record which groups each item is shared to.

    Done by searching each group's contents rather than by asking each item for
    its groups. One request per group instead of one per item is the difference
    between a snapshot that finishes and one that gets rate limited.
    """
    for gid in sorted(groups):
        members, _total, _trunc = search_items(
            url, "group:%s" % gid, token, insecure=insecure)
        for iid in members:
            if iid in items:
                items[iid]["groups"].append(gid)
        if echo:
            echo("  group %s: %d item(s)" % (gid, len(members)))
    for item in items.values():
        item["groups"].sort()
    return items


def take_snapshot(url, query, token, insecure=False, echo=None):
    """Read the whole sharing posture of one org into a snapshot document."""
    items, total, truncated = search_items(url, query, token,
                                           insecure=insecure, echo=echo)
    groups = search_groups(url, query, token, insecure=insecure)
    attach_groups(url, items, groups, token, insecure=insecure, echo=echo)
    taken = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return build_snapshot(url, taken, items, groups, total, truncated)


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
    if not snapshot.get("taken"):
        raise ValueError("%s has an empty 'taken' timestamp" % path)
    return True


def write_snapshot(snapshot, directory, when):
    """Write the snapshot under its timestamped name and return the path."""
    if not os.path.isdir(directory):
        os.makedirs(directory)
    path = os.path.join(directory, snapshot_name(when))
    with io.open(path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=1, sort_keys=True)
    return path


# ------------------------------------------------------------------ self-test

def self_test():
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
    check(next_start(201, 50, 250) is None,
          "a page that reaches the total terminates")
    check(next_start(300, 0, 250) is None, "a start past the end terminates")
    check(next_start(9901, 100, 12000) is None,
          "paging stops at the 10,000 ceiling, not at the reported total")
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

    print("-" * 68)
    total = passed[0] + len(failed)
    if failed:
        print("%d assertions, %d failed" % (total, len(failed)))
        for f in failed:
            print("  FAILED: %s" % f)
        return 1
    print("%d assertions, 0 failed" % total)
    return 0


# ----------------------------------------------------------------------- cli

def _parse(argv):
    ap = argparse.ArgumentParser(
        prog="sharewatch.py",
        description="Diff an ArcGIS organization's sharing posture against "
                    "yesterday, because the platform keeps no audit log.",
        epilog="Read-only. There is no flag that changes sharing. The password "
               "is never a flag: export %s or answer the prompt." % SECRET_ENV,
    )
    ap.add_argument("mode", nargs="?", choices=["snapshot", "diff", "watch"],
                    help="snapshot writes one, diff compares two, watch takes a "
                         "fresh one and compares it with the newest in --dir")
    ap.add_argument("paths", nargs="*", default=[],
                    help="for diff: the older snapshot then the newer one")
    ap.add_argument("--url", help="portal url, e.g. https://county.maps.arcgis.com")
    ap.add_argument("--query",
                    help="search query (default: orgid of the signed-in org)")
    ap.add_argument("--token", help="an existing portal token")
    ap.add_argument("--username",
                    help="generate a token for this user. The password comes "
                         "from %s or an unechoed prompt, never from argv."
                         % SECRET_ENV)
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


def _authenticate(args):
    """Return a token, or None for an anonymous read."""
    if args.token:
        return args.token
    if not args.username:
        return None
    secret = read_secret(args.username)
    return generate_token(args.url, args.username, secret, args.insecure)


def _snapshot(args):
    """Take a snapshot and print what it covers. Returns (snapshot, path)."""
    token = _authenticate(args)
    query = args.query
    if not query:
        oid = org_id(args.url, token, args.insecure)
        if not oid:
            raise RuntimeError("could not read the org id, pass --query")
        query = "orgid:%s" % oid
    print("reading %s" % args.url)
    print("query: %s" % query)
    snapshot = take_snapshot(args.url, query, token, args.insecure,
                             echo=lambda line: print(line))
    print("%d item(s), %d group(s), reported total %d"
          % (len(snapshot["items"]), len(snapshot["groups"]),
             snapshot["reported_total"]))
    if snapshot["truncated"]:
        print("")
        print("WARNING: the result set reached the %d row ceiling. search "
              "cannot page past it" % SEARCH_CEILING)
        print("and its total is an estimate, so this snapshot covers an "
              "unknown fraction of the org.")
        print("Narrow --query and take several snapshots instead.")
    return snapshot


def _write(snapshot, directory, apply_it):
    if not apply_it:
        print("\nCheck only. No snapshot was written. Re-run with --apply.")
        return None
    path = write_snapshot(snapshot, directory, utcnow())
    print("\nwrote %s" % path)
    return path


def _report(old, new, window_minutes):
    """Print the diff. Returns the exit code, 1 when there is anything to read."""
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
    for line in describe(events):
        print(printable(line, encoding))
    return exit_code(events)


def main(argv=None):
    args = _parse(sys.argv[1:] if argv is None else argv)

    if args.self_test:
        return self_test()

    if not args.mode:
        print("error: a mode is required: snapshot, diff or watch. Use "
              "--self-test to verify the tool without a portal.", file=sys.stderr)
        return 64
    if args.window_minutes < 0:
        print("error: --window-minutes cannot be negative.", file=sys.stderr)
        return 64
    if args.insecure and args.username:
        print("error: --insecure with --username would post your password down "
              "an unverified connection. Pass --token instead.", file=sys.stderr)
        return 64

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
        except RuntimeError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        _write(snapshot, args.out or ".", args.apply)
        return 0

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
    _write(snapshot, args.dir, args.apply)
    if not previous:
        print("\nNo earlier snapshot in %s. This one is the baseline." % args.dir)
        return 0
    print("\nbaseline: %s" % previous)
    try:
        baseline = load_snapshot(previous)
    except (IOError, OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 64
    return _report(baseline, snapshot, args.window_minutes)


if __name__ == "__main__":
    sys.exit(main())
