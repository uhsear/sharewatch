# sharewatch

Diff your ArcGIS organization's sharing posture against yesterday, because the platform keeps no
audit log. Read-only, never changes sharing.

An internal layer holding addresses with occupant names is public. A resident found it and
called. Somebody shared a folder to Everyone last week to fix a colleague's access problem, and
did not look at what else was in that folder.

ArcGIS Online has no sharing audit log. The portal will tell you the layer is public right now,
and nothing else: not when it changed, not who changed it, not what else moved with it. The
item's modified date is the only trace, and the next edit overwrites it. So the honest answer to
"how long was it exposed, and what else went with it" is that nobody knows.

```
$ python sharewatch.py --self-test
sharewatch self-test: no portal, no network, no credentials
--------------------------------------------------------------------
PASS  private is the narrowest level
PASS  public is the widest level
PASS  group-only sharing is narrower than org-wide
...
PASS  exactly 10,000 cannot be proven complete  <-- pinned defect
PASS  the warning says the deletions below may not be real  <-- pinned defect
...
PASS  a url with no scheme is refused, because urllib quotes the whole url back into its error and that url carries the token  <-- pinned defect
...
PASS  nine bulk items and one unrelated item are two events, not ten
PASS  one owner's bulk share collapses to a single event
...
PASS  a group created public is reported, not only one flipped public  <-- pinned defect
PASS  items missing from the new snapshot are DELETED  <-- pinned defect
PASS  60 deletions by one owner are one event, however old the items were  <-- pinned defect
PASS  a bulk add to one group is one event, because a group share does not bump modified  <-- pinned defect
PASS  an item only in the new snapshot is NEW  <-- pinned defect
PASS  a day where everything was deleted is not a clean day  <-- pinned defect
...
PASS  a windows console gets a replaced character, not a crash that loses every finding below it  <-- pinned defect
...
PASS  a scheme-less --url is refused before any request is built  <-- pinned defect
--------------------------------------------------------------------
125 assertions, 0 failed
```

## Requirements

Python 3.9 or newer. Standard library only: `urllib`, `json`, `os`, `ssl`, `io`, `argparse`,
`datetime`, `getpass`. It runs on ArcGIS Pro's Python and on a plain `python3`. `arcpy` is not used and the
`arcgis` package is not needed.

```
git clone https://github.com/uhsear/sharewatch.git
python sharewatch.py --self-test
```

`--self-test` needs no portal, no network and no credentials, so you can check the tool before
you point it at an organization.

## Usage

Take a snapshot every morning, then read what changed.

```
export SHAREWATCH_PASSWORD='...'
python sharewatch.py snapshot --url https://county.maps.arcgis.com --username gis_admin --out snaps/ --apply
python sharewatch.py diff snaps/sharewatch-20260914T060000Z.json snaps/sharewatch-20260915T060000Z.json
```

`watch` does both: it takes a fresh snapshot and compares it with the newest file already in the
directory. This is the scheduled-task form.

```
python sharewatch.py watch --url https://county.maps.arcgis.com --username gis_admin --dir snaps/ --apply
```

| Flag | Default | What it does |
|---|---|---|
| `mode` | none | `snapshot`, `diff` or `watch`. Required. |
| `--url` | none | Portal url, including `https://`. Required except for `diff`. |
| `--query` | org id | Search query. Defaults to `orgid:` of the signed-in organization. |
| `--token` | none | An existing portal token. |
| `--username` | none | Generate a token for this user. |
| `--out` | none | Directory to write the snapshot into. |
| `--dir` | none | Directory of snapshots, for `watch`. |
| `--window-minutes` | `60` | Minutes within which one owner's changes collapse into one event. |
| `--insecure` | off | Skip TLS verification, for an Enterprise portal behind an internal CA. |
| `--apply` | off | Write the snapshot file. Without it nothing is written. |
| `--self-test` | off | Run the offline assertions and exit. |

There is no `--password` flag, and there never will be. `argv` is readable by every process on
the machine, and it lands in shell history and in scheduler logs. The password comes from
`SHAREWATCH_PASSWORD` or from an unechoed prompt. It is not written into a snapshot, and it is
stripped out of error messages before they are printed, because `generateToken` is a POST and
urllib repeats the request in some of its exceptions.

The token gets the same treatment, which took two goes to get right. A token is sent as a query
parameter, and urllib answers a url it cannot open by quoting the whole url back inside the
exception. `--url county.maps.arcgis.com`, with the scheme left off, printed a live token to
standard error and into the scheduler log that captured it. The url is now refused before the
request is built, and every credential in a request is redacted out of its error, not only the
password.

Exit codes: 0 nothing widened, 1 findings to review, 2 the portal call failed, 64 usage error.

## What it records

Per item: id, title, owner, type, access, the ids of the groups it is shared to, and the modified
date. Per group: access and `membershipAccess`. Nothing else. A snapshot sits in a folder for
months, so it holds what the diff needs and no descriptions, no service urls and no tokens.

Group membership is read by searching each group's contents, one request per group, rather than
asking each item for its groups, one request per item. On an organization with 4,000 items and 30
groups that is 30 requests instead of 4,000.

## What it reports

Findings are ranked, worst first, and bulk actions are collapsed.

```
[100] item-public        9 item(s) by Asir.Khan_MarionCountyFL: org -> public
        - Major Streets (Feature Service) 017177d5e47b46c5bbec757104945eec
        - FHWA County Roads (Feature Service) 0215585d1a854e07aff697f167d3bf18
        - Zoning Overlay (Feature Service) 03bf7a2c9d1e4a55b41d6f77c2d0e9a1
        - Fire Hydrants (Feature Service) 0a6cf1b79c2d4e0d9f3b8a71e5c4d2f6
        - Sidewalk Inventory (Feature Service) 0b1e4d7a8c934f22bb05d6e1f7a3c890
        - Address Points with Occupants (Feature Service) 0c94a2e5f1b7480d9e22a6c3d5f81b47
        - Bus Stops (Feature Service) 0d33b8c1e7a2495fae61d0942b5c7e38
        - Stormwater Basins (Feature Service) 0e57f9a4b2c8416d83e147c6d90ab215
        - Traffic Counts (Feature Service) 0f28c6d3a91b47e5b7204f8ac13d6e90
[ 90] group-public       OCE Application Editors: group access org -> public (9 item(s) inside)
[ 20] item-deleted       2 item(s) by Asir.Khan_MarionCountyFL: deleted or transferred out of the org
        - Parcels 2019 Draft (Feature Service) del0
        - Test Points (Feature Service) del1
```

| Severity | Kind | Meaning |
|---|---|---|
| 100 | `item-public` | An existing item became visible to anyone. |
| 90 | `group-public` | A group became public, or arrived public, reported with the count of items inside it. |
| 85 | `new-item-public` | An item arrived already public. |
| 60 | `item-org` | Private or group-only became organization-wide. |
| 55 | `group-org` | A private group became organization-wide, or opened to org membership. |
| 40 | `item-joined-group` | An item was added to a group. |
| 25 | `new-item` | A new item, not public. |
| 20 | `item-deleted` | An item present yesterday is gone. |
| 15 | `item-left-group` | An item was removed from a group. |
| 10 | `item-narrowed` | Sharing was reduced. Recorded, not alarming. |

Nine items that one owner pushed public within `--window-minutes` are one event listing nine
items, because that is one mistake and one conversation. Two owners doing it on the same day stay
two events. Deletions and group membership changes carry no usable timestamp, so they collapse
per owner with no window at all: a deleted item leaves no deletion date behind, and adding an
item to a group does not update its modified date.

## What it refuses to do

It never changes sharing. There is no flag that does, the REST calls it makes are `search`,
`community/groups`, `portals/self` and `generateToken`, and `--self-test` asserts that a
plausible-looking `--unshare` is rejected rather than ignored.

A snapshot that reaches the 10,000 result ceiling says so instead of reporting a clean total.
`search` counts accurately only to 10,000 and will not page past it, so above that the snapshot
covers an unknown fraction of the organization. Narrow `--query` and take several snapshots.

A diff that involves a truncated snapshot carries the same warning, because the missing tail
reads as deletions. That is the false clean day running backwards: instead of hiding 60
deletions it invents thousands. The diff still runs, since the widenings in it are real.

## Why not the tools that already exist

An ArcGIS Online administrator can download an organization content report, a CSV with one row
per item including its access. It is accurate, it is supported, and it is a photograph of right
now. Yesterday's is not kept for you. If you want to know what changed, you have to have saved
one yesterday and then written the comparison, and the comparison is the part with the traps in
it.

The `arcgis` Python API does the same job more pleasantly: `gis.content.search()` and
`item.shared_with` give you the current state in a few lines. That is the right tool for reading
the state. This one exists because it keeps the history and does the diff, and because it has no
dependency to install on a locked-down server where the scheduled task has to run.

ArcGIS Enterprise portal logs do record some sharing calls, which is more than ArcGIS Online
offers. They are per-deployment, they roll over, and they are not searchable by item. If you are
on Enterprise, read them first.

The trap worth naming is in the diff itself. The obvious version walks the item ids and compares
them:

```python
for item_id in old_items:
    if item_id in new_items:                      # wrong
        compare(old_items[item_id], new_items[item_id])
```

That diffs the intersection. An item deleted overnight is not in `new_items`, so it is skipped,
and an item created overnight is not in `old_items`, so it is never reached. An early version of
this tool did exactly that and reported a clean day after 60 items were deleted. The fix is to
walk the union, and three assertions pin it, including one that a day where everything was
deleted is not a clean day.

## Limits

- It compares snapshots, so it sees nothing before the first one. Start taking them today.
- Resolution is the interval between snapshots. Shared and unshared between two runs is invisible.
- It cannot say who made a change. ArcGIS Online does not record that anywhere, and this tool
  reports the item's owner, who is often not the person who clicked.
- Times come from the item's modified date, which sharing does not always update. The collapse
  window is a heuristic over that date, not an event log.
- `--insecure` skips certificate verification and exists for Enterprise portals behind an
  internal CA. It is off by default and refused together with `--username`, because posting a
  password down an unverified connection is the failure it would cause. Add the CA to your trust
  store instead.
- Folders are not snapshotted. Items are, and an item's access is what actually governs who can
  see it.
- It does not check item permissions on the underlying services. A feature service can be open to
  the world while its item is private.
- The item count on a group finding counts the items in the snapshot, not the group. An item the
  query did not cover is in the group and not in the count.
- A `membershipAccess` that narrows is not reported, and `null` is read as `org`, because `null`
  is what ArcGIS Online returns for a group anyone in the organization may join.
- An item that changed owner is not reported as a change. Its id is stable, so it reads as the
  same item with a different name against it.
- A sharing level this version does not know stops the diff with exit code 64. Sorting an
  unknown level to `private` would make every item holding it look safe.
- Deleted groups are not reported. The items that were in them report as `item-left-group`.

## Contributing

Open an issue or pull request on GitHub.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.
