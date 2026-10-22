# sharewatch

Diff your ArcGIS organization's sharing posture against yesterday, because the platform keeps no
audit log. Read-only, never changes sharing. The `mirror` mode does the same comparison between
two portals, for the day after a cutover.

An internal layer holding addresses with occupant names is public. A resident found it and
called. Somebody shared a folder to Everyone last week to fix a colleague's access problem, and
did not look at what else was in that folder.

A different morning, after a migration. The script that copied the items to the new portal shared
each one the way its twin was shared on the old portal, and logged "done" for every call, because
every call answered HTTP 200. Some of those answers carried a `notSharedWith` list. Other calls
were sent with an empty `groups` value, because the group lookup had come up empty, and those
answered 200 too. Nobody read the lists. A week later the staff who used a planning layer could not
open it, and a layer that was org-only on the old portal was public on the new one. The `mirror`
mode reads what each portal holds and reports the difference, instead of trusting the log.

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
PASS  a page that came back short advances by the ten rows it got, not by the hundred it asked for  <-- pinned defect
PASS  an org whose last page ends one row short of the total is paged to that last row, not stopped one item early  <-- pinned defect
PASS  the row sitting exactly on the ceiling is still asked for  <-- pinned defect
PASS  exactly 10,000 cannot be proven complete  <-- pinned defect
PASS  the warning says the deletions below may not be real  <-- pinned defect
...
PASS  a url with no scheme is refused, because urllib quotes the whole url back into its error and that url carries the token  <-- pinned defect
...
PASS  nine bulk items and one unrelated item are two events, not ten
PASS  one owner's bulk share collapses to a single event
PASS  at equal severity the event touching nine items leads the one touching one, even when the owner names sort the other way  <-- pinned defect
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
PASS  a unique prefix of --apply is refused, so the write flag is never reached by abbreviation  <-- pinned defect
PASS  a scheme-less --url is refused before any request is built  <-- pinned defect
PASS  items as a JSON list is refused, because the diff indexes items by id and would raise TypeError instead  <-- pinned defect
PASS  paging reads all 250 items, not the 100 the server caps a page at  <-- pinned defect
PASS  the portal's modified date is carried into the record, not zeroed  <-- pinned defect
PASS  four items the portal dated ten hours apart stay four events, because the date reached the collapse  <-- pinned defect
PASS  every call asks for f=json, or the portal answers with the html page and json.loads gets a doctype  <-- pinned defect
PASS  a server that quietly gives back ten rows for a page of a hundred is still paged to the end of the org  <-- pinned defect
PASS  an item in two groups gets them back in id order, so an unchanged org writes the same bytes twice  <-- pinned defect
PASS  the token never reaches the snapshot document  <-- pinned defect
PASS  the password never appears in a url  <-- pinned defect
PASS  --username signs in and returns a token  <-- pinned defect
PASS  a token in the url urllib quoted back is redacted out of the error  <-- pinned defect
PASS  a token that dies mid-paging fails the snapshot  <-- pinned defect
PASS  the default opener verifies the certificate  <-- pinned defect
...
PASS  a dry run leaves the directory empty  <-- pinned defect
PASS  the token never reaches stdout  <-- pinned defect
PASS  no credential reaches the snapshot file on disk  <-- pinned defect
PASS  a token that died mid-paging writes no half-read snapshot and does not overwrite the one that finished  <-- pinned defect
PASS  watch diffs against the snapshot that was in --dir before the run, not against the file it just wrote over it  <-- pinned defect
PASS  the org that was just read is still written when yesterday's file turns out to be corrupt  <-- pinned defect
PASS  a sharing level this version has never heard of is refused, not sorted as private and called safe  <-- pinned defect
PASS  an item title a cp1252 console cannot encode is replaced, and the finding still prints  <-- pinned defect
PASS  --insecure with --username is refused, because that posts the password down an unverified connection  <-- pinned defect
...
PASS  a --new-url on another host than --verify-host is refused  <-- pinned defect
PASS  an --old-url on the verified host is refused, or the run compares the new portal with itself  <-- pinned defect
PASS  two items made public by one owner are one event even when their dates are a week apart  <-- pinned defect
PASS  a 200 that names groups in notSharedWith is a finding, not a success  <-- pinned defect
PASS  a prefix of --apply is refused on the mirror mode too  <-- pinned defect
PASS  a pinned call refuses a redirect to another host  <-- pinned defect
PASS  a token for one portal is never sent to the other  <-- pinned defect
PASS  a host refusal is made before any request is sent  <-- pinned defect
PASS  a new url that answers but declares another host is refused, so a DNS alias left on the old portal is caught  <-- pinned defect
...
PASS  the harness records a false check, a missing exception, a wrong exception, an argv argparse accepted and two failed portal calls as six failures, so a broken tool turns this self-test red  <-- pinned defect
...
PASS  a failed tally lists the failure and exits 1  <-- pinned defect
PASS  importing the file runs nothing and does not exit
--------------------------------------------------------------------
356 assertions, 0 failed
```

## Requirements

Python 3.9 or newer. Standard library only: `urllib`, `json`, `os`, `ssl`, `io`, `argparse`,
`datetime`, `getpass`, and `tempfile`, `shutil`, `http.server`, `socketserver`, `threading`,
`contextlib` and `runpy` in the self-test. It runs on ArcGIS Pro's
Python and on a plain `python3`. `arcpy` is not used and the `arcgis` package is not needed.

```
git clone https://github.com/uhsear/sharewatch.git
python sharewatch.py --self-test
```

`--self-test` needs no portal, no network and no credentials, so you can check the tool before
you point it at an organization. It covers the portal calls as well as the decisions: paging,
sign-in, the 10,000 row ceiling, an expired token, an HTTP error, a 200 response carrying an
ArcGIS error envelope, and the `snapshot`, `diff` and `watch` modes end to end are run against a
stand-in portal that answers inside the process.

The `mirror` mode is run against `http.server` on the loopback addresses `127.0.0.1` (the new
portal) and `127.0.0.2` (the old one), so redirects, the sign-in POST and the host proof go
through urllib and a real socket. The self-test therefore opens loopback sockets, and nothing else.
It needs no network and no credentials, but it does need a machine where `127.0.0.2` is loopback.
That holds on Windows and on Linux, which are the two hosts it was run on. It is not run on macOS,
which binds only `127.0.0.1` by default.

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
| `mode` | none | `snapshot`, `diff`, `watch` or `mirror`. Required. |
| `--url` | none | Portal url, including `https://`. Required except for `diff`. |
| `--query` | org id | Search query. Defaults to `orgid:` of the signed-in organization. |
| `--token` | none | An existing portal token. |
| `--username` | none | Generate a token for this user. |
| `--out` | none | Directory to write the snapshot into. |
| `--dir` | none | Directory of snapshots, for `watch`. |
| `--window-minutes` | `60` | Minutes within which one owner's changes collapse into one event. |
| `--insecure` | off | Skip TLS verification, for an Enterprise portal behind an internal CA. |
| `--old-url`, `--new-url` | none | `mirror`: the portal being left and the portal being checked. Both required. |
| `--verify-host` | none | `mirror`: the bare host name the new portal must be on. Required. |
| `--old-token`, `--new-token` | none | `mirror`: an existing token for each portal. |
| `--old-username`, `--new-username` | none | `mirror`: generate a token on that portal. |
| `--old-query`, `--new-query` | org id | `mirror`: the search query on each side. |
| `--responses` | none | `mirror`: a JSON file of saved share-call responses to check for `notSharedWith`. |
| `--apply` | off | Write the snapshot file. Without it nothing is written. Refused by `mirror`. |
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

Exit codes: 0 nothing widened, 1 findings to review, 2 the portal call failed or the host proof
failed, 64 usage error.

## Mirror: did the new portal share what the old one did

```
export SHAREWATCH_OLD_PASSWORD='...'
export SHAREWATCH_NEW_PASSWORD='...'
python sharewatch.py mirror --old-url https://old.example.org --old-username gis_admin \
    --new-url https://new.example.org --new-username gis_admin --verify-host new.example.org
```

The two portals are read the same way `snapshot` reads one, then compared. Item ids do not survive
a copy, so items are paired by title and type, and groups by title with case ignored. Nothing is
written, not even with `--apply`, which this mode refuses. The calls it makes are the same four
REST calls as the other modes: `search`, `community/groups`, `portals/self` and `generateToken`.

A real run against two stub portals holding synthetic data (one item missing, one group lost and
two items made public):

```
old 127.0.0.2  ->  new 127.0.0.1 (verified host 127.0.0.1)
--------------------------------------------------------------------
4 paired, 1 only on the old portal, 0 only on the new, 0 not compared (ambiguous title)
[ 95] mirror-public      2 item(s) by analyst: old org, new public
        - Markers (Feature Service) b4
        - Signs (Feature Service) b3
[ 45] mirror-group-lost  1 item(s) by analyst: group 'Planning'
        - Parcels (Feature Service) b2
[ 45] mirror-missing     1 item(s) by analyst: shared org on the old portal, absent on the new one
        - Trails (Feature Service) a5
```

| Severity | Kind | Meaning |
|---|---|---|
| 95 | `mirror-public` | Public on the new portal and not on the old one. |
| 80 | `mirror-notshared` | A saved share response (`--responses`) was a 200 that did not share. |
| 65 | `mirror-wider` | Wider on the new portal than on the old, short of public. |
| 50 | `mirror-narrower` | Narrower on the new portal. Users lose access. |
| 48 | `mirror-no-group` | The old item's group does not exist on the new portal, so no share into it can land. |
| 45 | `mirror-missing` | An old item with no counterpart on the new portal. |
| 45 | `mirror-group-lost` | In a group on the old portal and not on the new one. |
| 35 | `mirror-group-extra` | In a group on the new portal and not on the old one. |
| 30 | `mirror-new-public` | Public, and present only on the new portal. |
| 30 | `mirror-ambiguous` | Two items share a title and type on a side. Not compared, and not guessed. |

Wider on the new portal ranks above narrower, because a cutover that exposes a layer is worse than
one that breaks a link. A private item that exists only on the new portal is counted and not
reported.

### The 200 that did not share

The share operation answers with `itemId` and a `notSharedWith` array, "Array of groups with which
the item could not be shared" ([share item as item owner][share]). The batch operation returns one
object per item with `success`, `notSharedWith` and, on failure, an `error` object
([share items][shareitems]). The status line is 200 whatever those say.

Two ways to catch it. First, the live comparison above needs no saved responses: an item that was
not shared into a group shows up as `mirror-group-lost`, and an item left less widely shared than
its twin shows up as `mirror-narrower`. This also covers the call that carries no `notSharedWith` at all. The
documentation says that to make an item private you "keep this parameter empty", so a share sent
with an empty `groups` value and no `everyone` or `org` is a request to make the item private, and
the response reports nothing wrong. Only a comparison sees it. Second, `--responses FILE` takes a
JSON file of the answers your script saved, one object or a list, batch answers included, and
reports each one that names groups in `notSharedWith`, holds an `error` object, or says
`success: false`. The self-test runs both against the stub.

[share]: https://developers.arcgis.com/rest/users-groups-and-items/share-item-as-item-owner/
[shareitems]: https://developers.arcgis.com/rest/users-groups-and-items/share-items/

### `--verify-host`: the check cannot read the old portal

`--verify-host new.example.org` is the host name you believe the new portal is on, as a bare name
with no scheme, port or path. The run is refused, with exit code 64 or 2 and before any search, if:

1. `--new-url` is on another host (64).
2. `--old-url` is on the verified host, because the run would compare the new portal with itself (64).
3. The new portal's own `portals/self` answer declares another host (2). It reads `portalHostname`,
   or `urlKey` and `customBaseUrl` joined with a dot. Esri documents these as "the portal host's
   URL", "the prefix selected by the organization's administrator" and "the custom base URL for the
   portal" ([portals/self][self]). A DNS alias that still reaches the old portal answers on the new
   name and declares the old one. A portal that declares no host at all is refused too.
4. The old portal's `portals/self` declares the verified host (2).

After that, every request on each side is pinned to that side's own host. urllib follows a redirect
to another host without a word, so a 302 from the new portal to the old one would have swapped the
data under the new name. The pin refuses it, and the error carries no token.

A token for one portal is never sent to the other. The two sign-ins use `SHAREWATCH_OLD_PASSWORD`
and `SHAREWATCH_NEW_PASSWORD`, or an unechoed prompt, and never a flag.

[self]: https://developers.arcgis.com/rest/users-groups-and-items/portal-self/

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
[100] item-public        9 item(s) by jsmith: org -> public
        - Major Streets (Feature Service) 000000000000000000000000000a0000
        - County Roads (Feature Service) 000000000000000000000000000a0001
        - Zoning Overlay (Feature Service) 000000000000000000000000000a0002
        - Fire Hydrants (Feature Service) 000000000000000000000000000a0003
        - Sidewalk Inventory (Feature Service) 000000000000000000000000000a0004
        - Address Points with Occupants (Feature Service) 000000000000000000000000000a0005
        - Bus Stops (Feature Service) 000000000000000000000000000a0006
        - Stormwater Basins (Feature Service) 000000000000000000000000000a0007
        - Traffic Counts (Feature Service) 000000000000000000000000000a0008
[ 90] group-public       Field Editors: group access org -> public (9 item(s) inside)
[ 20] item-deleted       2 item(s) by jsmith: deleted or transferred out of the org
        - Parcels 2019 Draft (Feature Service) 000000000000000000000000000d0000
        - Test Points (Feature Service) 000000000000000000000000000d0001
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
plausible-looking `--unshare` is rejected rather than ignored. It asserts the same for `mirror`
against the socket stub: every request it made was one of the three read paths, and the only POST
is the sign-in.

Every parser has `allow_abbrev=False`, so no prefix of a flag is accepted. `--ap` is refused, and
`--verify` is not read as `--verify-host`.

A snapshot that reaches the 10,000 result ceiling says so instead of reporting a clean total.
`search` counts accurately only to 10,000 and will not page past it, so above that the snapshot
covers an unknown fraction of the organization. Narrow `--query` and take several snapshots.

A diff that involves a truncated snapshot carries the same warning, because the missing tail
reads as deletions. That is the false clean day running backwards: instead of hiding 60
deletions it invents thousands. The diff still runs, since the widenings in it are real.

## Why not the tools that already exist

For the two-portal comparison I know of no tool that does it. A search of GitHub for `sharemirror`
finds two repositories, and neither is related: one is a Windows utility that mirrors what is on
screen, the other is a project of the same name from 2023 with no ArcGIS content. Searches for an
ArcGIS sharing audit and for portal migration with groups and sharing returned nothing. That is what
the search found, and it does not prove nothing exists. The `arcgis` Python API documents the same
`notSharedWith` key in the return value of `Item.share`, which it has deprecated in favour of
`Item.sharing`, so a script written with it can read the list. Reading it is the script's job, and
the cutover script that did not is the case this mode exists for. This tool does not copy or share
anything. It checks the result afterwards.

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

`watch` had a second way of printing the same false clean day. It wrote the fresh snapshot before
it read the baseline, and a snapshot is named for the second it was taken in. Two runs inside the
same second produce the same file name, so the write landed on the very file the diff was about
to read, and the run compared the new snapshot with itself. The baseline is now read into memory
first, and it is still written afterwards even when yesterday's file turns out to be corrupt,
because the organization has already been read and throwing that away loses today's evidence
too.

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
- A file that is not a snapshot stops the diff with exit code 64 as well. `items` and `groups`
  have to be objects keyed by id, because the diff indexes them by id and a JSON list there
  used to reach the operator as a `TypeError` traceback.
- Deleted groups are not reported. The items that were in them report as `item-left-group`.
- Mirror pairs items by title and type, trimmed and case ignored. A title that two items share on
  either side is reported as `mirror-ambiguous` and not compared. A renamed item reads as one
  `mirror-missing` and one new item. Owners are not compared, because accounts differ after a move.
- Mirror compares the sharing it can see with the token it was given. An item the account cannot
  see is absent from the snapshot and reads as missing. Use an administrator token on each side.
- `--verify-host` compares host names, not ports. Two portals on one host name and two ports are
  not told apart. A reverse proxy that rewrites `portalHostname` would pass the declared-host test.
- The empty `groups` call has no signature in a saved response, so `--responses` cannot see it.
  The live comparison does.
- A mirror read costs one request per group on each portal, the same as the other modes.
- Coverage is 100 percent branch on Windows, measured with `coverage run --branch`. The Linux host
  has no `coverage` module installed, so the Linux run reports the assertion count only.

## Contributing

Open an issue or pull request on GitHub.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

## Related

Other single-file tools in this portfolio that pair with this one:

- [itemcensus](https://github.com/uhsear/itemcensus) - the enumeration underneath this, including the bisect past the 10,000 search ceiling
- [sightline](https://github.com/uhsear/sightline) - the same platform from the other side: what a viewer sees today, rather than what changed
- [ghostsvc](https://github.com/uhsear/ghostsvc) - the services no sharing report can see, because they have no item
