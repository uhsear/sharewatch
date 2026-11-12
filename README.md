# sharewatch

Diff your ArcGIS organization's sharing posture against yesterday, because the portal reports only
what is shared now. Read-only, never changes sharing. The `mirror` mode does the same comparison between
two portals, for the day after a cutover. The `caps` mode re-reads a view's capabilities after a
definition update and asks it for a row count with no token, for the minute after an edit.

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

A third morning, after a small edit. A public form view took reports from residents. It held
`Create` and nothing else, so a stranger could add a row and could not read one. A script hid one
field on that view through a definition update. The update worked, and the script said so. Afterwards
the layer's capabilities listed `Query` as well, and a request with no token could read the view.
Nobody read the capabilities again. The `caps` mode is that second read, and it also asks the view
for rows the way a stranger would.

The item will tell you the layer is public right now, and its modified date, which the next edit
overwrites. It does not tell you what else moved with it. ArcGIS Online does have an activity
report: "a log of all activity in your organization for a specified time period" ([Esri report
fields][aoreport]), with an actor, an action and a UTC time stamp for each entry. It is an export
you request for a period and filter yourself. Esri's page does not say which actions it lists,
whether sharing changes are among them, or how long entries are kept, and this tool did not
exercise it. So the answer to "how long was it exposed, and what else went with it" depends on
whether someone pulled and kept that report. `sharewatch` keeps its own dated snapshots and
compares them.

The block below is an excerpt of a real run, in run order. A line that reads `...` stands for lines left out, and the last line is the real count.

```
$ python sharewatch.py --self-test
sharewatch self-test: no portal, no network, no credentials
--------------------------------------------------------------------
PASS  private is the narrowest level
PASS  public is the widest level
PASS  group-only sharing is narrower than org-wide
...
PASS  a page that came back short advances by the ten rows it got, not by the hundred it asked for  <-- pinned defect
...
PASS  an org whose last page ends one row short of the total is paged to that last row, not stopped one item early  <-- pinned defect
...
PASS  the row sitting exactly on the ceiling is still asked for  <-- pinned defect
...
PASS  exactly 10,000 cannot be proven complete  <-- pinned defect
...
PASS  the warning says the deletions below may not be real  <-- pinned defect
...
PASS  a url with no scheme is refused, because urllib quotes the whole url back into its error and that url carries the token  <-- pinned defect
...
PASS  a url with a token in the fragment is refused, because the error urllib raises quotes it back and redact() cannot know it  <-- pinned defect
...
PASS  nine bulk items and one unrelated item are two events, not ten
PASS  one owner's bulk share collapses to a single event
...
PASS  at equal severity the event touching nine items leads the one touching one, even when the owner names sort the other way  <-- pinned defect
...
PASS  a group created public is reported, not only one flipped public  <-- pinned defect
...
PASS  items missing from the new snapshot are DELETED  <-- pinned defect
...
PASS  60 deletions by one owner are one event, however old the items were  <-- pinned defect
...
PASS  a bulk add to one group is one event, because a group share does not bump modified  <-- pinned defect
PASS  an item only in the new snapshot is NEW  <-- pinned defect
PASS  a day where everything was deleted is not a clean day  <-- pinned defect
...
PASS  a windows console gets a replaced character, not a crash that loses every finding below it  <-- pinned defect
...
PASS  a token is not a flag, because argv is readable by every process  <-- pinned defect
...
PASS  a unique prefix of --apply is refused, so the write flag is never reached by abbreviation  <-- pinned defect
PASS  a credential typed into --url is refused before any request and never echoed  <-- pinned defect
...
PASS  a scheme-less --url is refused before any request is built  <-- pinned defect
...
PASS  items as a JSON list is refused, because the diff indexes items by id and would raise TypeError instead  <-- pinned defect
...
PASS  paging reads all 250 items, not the 100 the server caps a page at  <-- pinned defect
...
PASS  the portal's modified date is carried into the record, not zeroed  <-- pinned defect
PASS  four items the portal dated ten hours apart stay four events, because the date reached the collapse  <-- pinned defect
...
PASS  every call asks for f=json, or the portal answers with the html page and json.loads gets a doctype  <-- pinned defect
PASS  a server that quietly gives back ten rows for a page of a hundred is still paged to the end of the org  <-- pinned defect
...
PASS  an item in two groups gets them back in id order, so an unchanged org writes the same bytes twice  <-- pinned defect
...
PASS  the token never reaches the snapshot document  <-- pinned defect
...
PASS  the password never appears in a url  <-- pinned defect
...
PASS  --username signs in and returns a token  <-- pinned defect
...
PASS  a token in the url urllib quoted back is redacted out of the error  <-- pinned defect
...
PASS  a token that dies mid-paging fails the snapshot  <-- pinned defect
...
PASS  the default opener verifies the certificate  <-- pinned defect
...
PASS  a dry run leaves the directory empty  <-- pinned defect
PASS  the token never reaches stdout  <-- pinned defect
...
PASS  no credential reaches the snapshot file on disk  <-- pinned defect
...
PASS  groups are searched by the org id even with an item --query, because the group search has other fields  <-- pinned defect
...
PASS  a token that died mid-paging writes no half-read snapshot and does not overwrite the one that finished  <-- pinned defect
...
PASS  the first watch run has nothing to compare with, says so and exits 3, never 0  <-- pinned defect
...
PASS  watch read by a publisher cannot call a day quiet: it exits 3  <-- pinned defect
...
PASS  watch diffs against the snapshot that was in --dir before the run, not against the file it just wrote over it  <-- pinned defect
...
PASS  the org that was just read is still written when yesterday's file turns out to be corrupt  <-- pinned defect
...
PASS  a sharing level this version has never heard of is refused, not sorted as private and called safe  <-- pinned defect
...
PASS  an item title a cp1252 console cannot encode is replaced, and the finding still prints  <-- pinned defect
...
PASS  --insecure with --username is refused, because that posts the password down an unverified connection  <-- pinned defect
...
PASS  a refused --verify-host is not echoed, a token may sit in it  <-- pinned defect
PASS  a --new-url on another host than --verify-host is refused  <-- pinned defect
PASS  an --old-url on the verified host is refused, or the run compares the new portal with itself  <-- pinned defect
...
PASS  two items made public by one owner are one event even when their dates are a week apart  <-- pinned defect
...
PASS  a 200 that names groups in notSharedWith is a finding, not a success  <-- pinned defect
...
PASS  a prefix of --apply is refused on the mirror mode too  <-- pinned defect
...
PASS  a pinned call refuses a redirect to another host  <-- pinned defect
...
PASS  a token for one portal is never sent to the other  <-- pinned defect
...
PASS  mirror read by a publisher cannot call two portals alike: it exits 3 and says whose view is partial  <-- pinned defect
...
PASS  a host refusal is made before any request is sent  <-- pinned defect
PASS  a new url that answers but declares another host is refused, so a DNS alias left on the old portal is caught  <-- pinned defect
...
PASS  a snapshot run that read fewer items than the portal reported exits 3, not 0  <-- pinned defect
...
PASS  a public group that exists only on the new portal is reported with the items inside it  <-- pinned defect
...
PASS  a group member search cut short marks the snapshot, and not as an item short read  <-- pinned defect
...
PASS  an unrecognised --flag=value is refused by name without its value  <-- pinned defect
...
PASS  a secret typed after the two paths diff takes is refused without being echoed  <-- pinned defect
...
PASS  a secret typed as the value of --window-minutes is refused without being echoed  <-- pinned defect
...
PASS  private to group-only is item-shared, below item-org  <-- pinned defect
...
PASS  Query added and an anonymous count that works is the flip, open
...
PASS  a layer that does not list Query and answers an anonymous count is reported, because the answer is the exposure  <-- pinned defect
...
PASS  the capabilities are read with the token and the count is asked with no token at all  <-- pinned defect
...
PASS  a count the server failed to answer is exit 3, not a clean 0  <-- pinned defect
...
PASS  the harness records a false check, a missing exception, a wrong exception, an argv argparse accepted and two failed portal calls as six failures, so a broken tool turns this self-test red  <-- pinned defect
...
PASS  a failed tally lists the failure and exits 1  <-- pinned defect
PASS  importing the file runs nothing and does not exit
...
616 assertions, 0 failed
```

## Requirements

Python 3.9 or newer. Standard library only: `urllib`, `json`, `os`, `sys`, `ssl`, `io`,
`argparse`, `datetime`, `getpass`, `ctypes`, and `tempfile`, `shutil`, `subprocess`, `http.server`,
`socketserver`, `threading`, `contextlib` and `runpy` in the self-test. It ran on Python 3.13
on Windows and Python 3.12 on Linux, with 616 assertions on both. Nothing outside the standard
library is used, so it should run on the Python that ships with ArcGIS Pro, but it was not run
there. The self-test also passed with the same 616 assertions on CPython 3.9.25 and 3.10.20 on the
Windows workstation, which is the oldest version it was run on.
`arcpy` is not used and the `arcgis` package is not needed.

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
through urllib and a real socket. The `caps` mode is run the same way against a stub feature
service, and its redirect refusal against a second loopback address. The self-test therefore opens loopback sockets, and nothing else.
It needs no network and no credentials, but it does need a machine where `127.0.0.2` is loopback.
That holds on Windows and on Linux, which are the two hosts it was run on. It is not run on macOS,
which binds only `127.0.0.1` by default.

## Usage

Take a snapshot every morning, then read what changed.

```
export SHAREWATCH_PASSWORD='...'
python sharewatch.py snapshot --url https://example.maps.arcgis.com --username gis_admin --out snaps/ --apply
python sharewatch.py diff snaps/sharewatch-20260914T060000Z.json snaps/sharewatch-20260915T060000Z.json
```

`watch` does both: it takes a fresh snapshot and compares it with the newest file already in the
directory. This is the scheduled-task form.

```
python sharewatch.py watch --url https://example.maps.arcgis.com --username gis_admin --dir snaps/ --apply
```

| Flag | Default | What it does |
|---|---|---|
| `mode` | none | `snapshot`, `diff`, `watch`, `mirror` or `caps`. Required. |
| `--url` | none | Portal url, including `https://`. Required except for `diff`, `mirror` and `caps`. For `caps` it is only the portal that signs `--username` in. |
| `--query` | org id | Item search query. Defaults to `orgid:` of the signed-in organization. Groups are always searched by org id. |
| `--username` | none | Generate a token for this user. |
| `--out` | none | Directory to write the snapshot into. |
| `--dir` | none | Directory of snapshots, for `watch`. |
| `--window-minutes` | `60` | Minutes within which one owner's changes collapse into one event. |
| `--insecure` | off | Skip TLS verification, for an Enterprise portal behind an internal CA. |
| `--old-url`, `--new-url` | none | `mirror`: the portal being left and the portal being checked. Both required. |
| `--verify-host` | none | `mirror`: the bare host name the new portal must be on. Required. |
| `--old-username`, `--new-username` | none | `mirror`: generate a token on that portal. |
| `--old-query`, `--new-query` | org id | `mirror`: the item search query on each side. |
| `--responses` | none | `mirror`: a JSON file of saved share-call responses to check for `notSharedWith`. |
| `--service-url` | none | `caps`: the `FeatureServer` url of the view, or of one layer, including `https://`. Required. |
| `--was` | none | `caps`: the capabilities the view held before the update, such as `Create`. Required. |
| `--apply` | off | Write the snapshot file. Without it nothing is written. Refused by `mirror` and `caps`. |
| `--self-test` | off | Run the offline assertions and exit. |

There is no `--password` flag, and there never will be. `argv` is readable by every process on
the machine, and it lands in shell history and in scheduler logs. The password comes from
`SHAREWATCH_PASSWORD` or from an unechoed prompt. It is not written into a snapshot, and it is
stripped out of error messages before they are printed, because `generateToken` is a POST and
urllib repeats the request in some of its exceptions.

The token gets the same treatment and has no flag either. Export `SHAREWATCH_TOKEN`, or for
`mirror` `SHAREWATCH_OLD_TOKEN` and `SHAREWATCH_NEW_TOKEN`. An earlier version took `--token`,
and a token in `argv` is readable by every process on the machine. A usage error shows long flag names only, so a `--tokn=VALUE` typo does not print its value, and a word that follows an unknown flag is counted and not printed. The values of `--apply=VALUE`, `--window-minutes VALUE` and `--verify-host` are not echoed either. A bad mode is refused without printing the word, so the old
`--token VALUE` form is never echoed. Getting the error text right took
two goes. A token is sent as a query
parameter, and urllib answers a url it cannot open by quoting the whole url back inside the
exception. `--url example.maps.arcgis.com`, with the scheme left off, printed a live token to
standard error and into the scheduler log that captured it. The url is now refused before the
request is built, and every credential in a request is redacted out of its error, not only the
password.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | No differences, and the read was whole. |
| 1 | Anything to read. A narrowing or a deletion is a difference too, so 1 does not mean "something widened". |
| 2 | The portal or service call failed, a mirror run's declared-host or redirect proof failed, a password was not supplied, or the tool hit an error it does not know. |
| 3 | No differences found, but the read cannot prove it: it held no items, was cut short, was made without a token (not for `caps`, see Limits), was made by an account that is not an organization administrator, or left group memberships unread. A `watch` run with no earlier snapshot in `--dir` also exits 3, with or without `--apply`, because it compared nothing. For `caps`: a layer that lists no capabilities, or an anonymous count that gave no usable answer, with no flip found. |
| 64 | Usage error (a `--verify-host` that disagrees with `--new-url` or `--old-url` is one), a corrupt baseline file, or a sharing level this version does not know. |

A scheduler that alerts only on 1 and 2 treats 3 as success. Alert on any non-zero code.

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
two items made public). The stub data for this run is not shipped. The self-test uses its own
fixtures, which give "8 paired, 1 only on the old portal, 2 only on the new", so you cannot
regenerate this exact block from the repository:

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
| 30 | `mirror-new-public` | Public, and present only on the new portal. An item, or a group with no same-title group on the old portal. |
| 28 | `mirror-new-shared` | Shared to the org or to groups, and present only on the new portal. An item, or a group. |
| 30 | `mirror-ambiguous` | Two items share a title and type on a side. Not compared, and not guessed. |

Wider on the new portal ranks above narrower, because a cutover that exposes a layer is worse than
one that breaks a link. A private item or a private group that exists only on the new portal is
counted and not reported.

### The 200 that did not share

The share operation answers with `itemId` and a `notSharedWith` array, "Array of groups with which
the item could not be shared" ([share item as item owner][share]). The batch operation returns one
object per item with `success`, `notSharedWith` and, on failure, an `error` object
([share items][shareitems]). The Esri pages do not state a status code. In the cutover this mode
was written for, the status line was 200 whatever those fields said.

Two ways to catch it. First, the live comparison above needs no saved responses: an item that was
not shared into a group shows up as `mirror-group-lost`, and an item left less widely shared than
its twin shows up as `mirror-narrower`. This also covers the call that carries no `notSharedWith` at all. The
documentation says that to make an item private you "keep this parameter empty", so a share sent
with an empty `groups` value and no `everyone` or `org` is a request to make the item private, and
the response reports nothing wrong. Only a comparison sees it. Second, `--responses FILE` takes a
JSON file of the answers your script saved, one object or a list, batch answers included, and
reports each one that names groups in `notSharedWith`, holds an `error` object, or says
`success: false`. The self-test runs both against the stub. A `--responses` file may start with
a byte order mark.

[share]: https://developers.arcgis.com/rest/users-groups-and-items/share-item-as-item-owner/
[shareitems]: https://developers.arcgis.com/rest/users-groups-and-items/share-items/
[apiref]: https://developers.arcgis.com/python/latest/api-reference/arcgis.gis.toc.html

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
[searchref]: https://developers.arcgis.com/rest/users-groups-and-items/search-reference/
[searchpage]: https://developers.arcgis.com/rest/users-groups-and-items/search/

## Caps: did a definition update open the view

```
export SHAREWATCH_TOKEN='...'
python sharewatch.py caps --service-url https://services.example.org/rest/services/Form_view/FeatureServer --was Create
```

Run it right after a definition update. `--was` lists the capabilities the view held before the
update. For each layer and table of the service, `caps` does three things:

1. It reads the service root, which lists the layers and tables. A url that ends in a layer number
   reads that one layer.
2. It reads each layer's `capabilities` with your token. Esri's example for the property is one
   comma-separated string, `Create,Delete,Query,Update,Editing` ([feature layer][layerref]).
3. It asks each layer for a row count with no token at all: `query?where=1=1&returnCountOnly=true`.
   The Query operation needs the `Query` capability ([query][queryref]), and `returnCountOnly`
   makes the answer a `count` ([query][queryref]).

The count decides, and the list is the evidence. A layer that did not hold `Query` and now answers
a stranger with a count is the flip, whatever its capabilities say.

A real run against a local `http.server` stub holding synthetic data. Layer 0 gained `Query`, layer
1 did not change, and layer 2 gained `Update` and `Editing`. The stub is not shipped. The self-test has its own
fixtures and a run against them, so you cannot regenerate this exact block from the repository:

```
read 3 layer(s) on host 127.0.0.1
--------------------------------------------------------------------
[100] cap-flip-open  layer 0 (Reports): an anonymous query returned a count of 12 and this view was not readable before (was Create, now Create,Query)
[ 70] cap-added      layer 2 (Review notes): Update,Editing added (was Create, now Create,Update,Editing). Writes are never probed here
```

The exit code was 1. Layer 1 is not printed, because nothing changed on it.

| Severity | Kind | Meaning |
|---|---|---|
| 100 | `cap-flip-open` | A count with no token returned rows from a layer whose `--was` did not hold `Query`. |
| 70 | `cap-added` | A capability other than `Query` was added. It is read from the list, never probed. |
| 60 | `cap-flip` | `Query` was added, and the anonymous count was refused or gave no answer. The view is not shown to be readable by strangers today. Check its sharing before it reaches Everyone. |

How it reads the anonymous count:

- A count came back: open. A body with rows but no count is unknown, because the request asks for a count only. A count of 0 is open, because an empty layer still answers.
- An HTTP 401 or 403 status, or an error object with code 401, 403, 498 or 499: closed.
- Anything else is unknown. That covers any other 4xx (such as 404, 407, 408 and 429), a 5xx, a timeout, a refused connection, a page that is not
  JSON and a 200 with neither a count nor an error. Unknown is never called closed. If `Query` was
  added, the finding says the count was inconclusive. If nothing was found, the run exits 3.
- A view whose `--was` already held `Query` is never reported as a flip. One `--was` serves every layer, so a layer that answers a stranger under it may have been readable before or may have just opened. The run cannot tell which, names the layer as something it cannot tell, and exits 3 when it found nothing else.

The refusal in the stub comes both ways: an HTTP 403 status in process, and an error object with
HTTP 200 over the socket. Esri's REST reference does not say which one a layer uses for a stranger.
No source is cited for the error object inside a 200, and `caps` accepts both.

Why the cause is not claimed. Esri's page on hosted views says "You can exclude fields from the
view" and that you can "share a read-only feature layer view with the public"
([hosted views][viewsref]). It does not say that excluding a field changes the capabilities. The
update itself is the `updateDefinition` operation on the admin endpoint
([update definition][updatedef]). The flip was seen in one case. `caps` reads the result, so it
catches the same outcome from any other edit.

[layerref]: https://developers.arcgis.com/rest/services-reference/enterprise/feature-layer/
[queryref]: https://developers.arcgis.com/rest/services-reference/enterprise/query-feature-service-layer/
[updatedef]: https://developers.arcgis.com/rest/services-reference/enterprise/update-definition-feature-layer/
[viewsref]: https://doc.esri.com/en/arcgis-online/latest/manage-data/create-hosted-views.html
[featuresapi]: https://developers.arcgis.com/python/latest/api-reference/arcgis.features.toc.html
[aoreport]: https://doc.esri.com/en/arcgis-online/latest/reference/report-fields.html


## What it records

Per item: id, title, owner, type, access, the ids of the groups it is shared to, and the modified
date. Per group: access and `membershipAccess`. Nothing else. A snapshot sits in a folder for
months, so it holds what the diff needs and no descriptions, no service urls and no tokens.

Groups are listed by `orgid:` of the portal, whatever `--query` holds, because `--query` is an item
query and the group search has its own fields, `orgid` among them ([search reference][searchref]).
An item query such as `type:"Feature Service"` finds no groups, and every group membership would
read as lost. If the portal will not name its org, groups are searched with the item query and the
run prints a warning. A group listing or a group's member list that comes back shorter than the
portal's total marks the snapshot incomplete, and the run exits 3.

Group membership is read by searching each group's contents, one request per group, rather than
asking each item for its groups, one request per item. On an organization with 4,000 items and 30
groups that is 30 requests instead of 4,000.

## What it reports

Findings are ranked, worst first, and bulk actions are collapsed. The block below is illustrative, not a captured run.

```
[100] item-public        9 item(s) by jsmith: org -> public
        - Major Streets (Feature Service) 000000000000000000000000000a0000
        - Arterial Roads (Feature Service) 000000000000000000000000000a0001
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
| 35 | `item-shared` | A private item became shared to groups, not to the organization. The joins also appear as `item-joined-group`. |
| 25 | `new-item` | A new item, not public. |
| 20 | `item-deleted` | An item present yesterday is gone. |
| 15 | `item-left-group` | An item was removed from a group. |
| 10 | `item-narrowed` | Sharing was reduced. Recorded, not alarming. |
| 10 | `group-narrowed` | A group's access was reduced. Recorded, not alarming. |

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

`caps` sends GET requests only: the service root, each layer, and one `query` per layer. The one
exception is the `generateToken` POST that `--url` with `--username` adds. The
self-test asserts that it sends no POST when a token is in the environment, that every path it
asked for is under the service url, and that the `query` request carries no token.

Every parser has `allow_abbrev=False`, so no prefix of a flag is accepted. `--ap` is refused, and
`--verify` is not read as `--verify-host`.

A snapshot that reaches the 10,000 result ceiling says so instead of reporting a clean total.
The search page says `total` is counted accurately only to 10,000 ([search][searchpage]). This
tool does not page past it, so above that the snapshot covers an unknown fraction of the
organization. Narrow `--query` and take several snapshots.

A diff that involves a truncated snapshot carries the same warning, because the missing tail
reads as deletions. That is the false clean day running backwards: instead of hiding 60
deletions it invents thousands. The diff still runs, since the widenings in it are real.

## Why not the tools that already exist

For the two-portal comparison, a GitHub search for `sharemirror` on 2026-10-29
found two repositories, and neither is related: one is a Windows utility that
mirrors what is on screen, the other has no description and no ArcGIS content that I found. Searches for an
ArcGIS sharing audit and for portal migration with groups and sharing returned nothing. That is what
the search found, and it does not prove nothing exists. The `arcgis` Python API documents the same
`notSharedWith` key in the return value of `Item.share`, which its documentation marks "Deprecated
since version 2.3.0", with "Use Item.sharing instead" ([arcgis.gis][apiref]), so a script written with it can read the list. Reading it is the script's job, and
the cutover script that did not is the case this mode exists for. This tool does not copy or share
anything. It checks the result afterwards.

An ArcGIS Online administrator can download an organization content report, a CSV with one row
per item including its access (the item report has a Share Level field: private, group, organization or public, per [report fields][aoreport]). It is supported, and it is a photograph of right
now. Yesterday's is not kept for you. If you want to know what changed, you have to have saved
one yesterday and then written the comparison, and the comparison is the part with the traps in
it.

The `arcgis` Python API does the same job more pleasantly: `gis.content.search()` and
`item.sharing` give you the current state in a few lines. That is the right tool for reading
the state. This one exists because it keeps the history and does the diff, and because it has no
dependency to install on a locked-down server where the scheduled task has to run.

An ArcGIS Online administrator can also download the activity report described above, and that is
the existing tool to try first when you need to know who changed an item and when. ArcGIS
Enterprise has its own portal logs. Neither their coverage of sharing calls nor how long they are
kept is cited here, and neither was exercised. If you are on Enterprise, read them first.

For the capability flip, the tool that exists is the service itself. Open the layer's REST page,
or read `FeatureLayer.properties` in the `arcgis` Python API ("retrieves and set properties of this
object", [arcgis.features][featuresapi]), and the `capabilities` string is there. That is the right
way to read one layer once, and it is exact. It gives you the state now. It does not give you the
state before the edit, and it does not ask the layer for rows with no token, which is the question
that matters. `caps` takes the before from `--was` and runs the anonymous count.

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
- It cannot say who made a change. This tool reports the item's owner, who is often not the person
  who clicked. The ArcGIS Online activity report has an actor field, and this tool does not read it.
- Times come from the item's modified date, which sharing does not always update. The collapse
  window is a heuristic over that date, not an event log.
- `--insecure` skips certificate verification and exists for Enterprise portals behind an
  internal CA. It is off by default and refused together with `--username`, because posting a
  password down an unverified connection is the failure it would cause. Add the CA to your trust
  store instead.
- Folders are not snapshotted. Items are, and an item's access is what actually governs who can
  see it.
- `snapshot`, `diff`, `watch` and `mirror` do not check item permissions on the underlying
  services. A feature service can be open to the world while its item is private. `caps` does, for
  one service at a time: it asks each layer for a count with no token.
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
  see is absent from the snapshot and reads as missing. A token whose account is not an organization administrator makes the run exit 3 with a line saying so, even when nothing differs. Use an administrator token on each side.
- `--verify-host` compares host names, not ports. Two portals on one host name and two ports are
  not told apart. A reverse proxy that rewrites `portalHostname` would pass the declared-host test.
- The empty `groups` call has no signature in a saved response, so `--responses` cannot see it.
  The live comparison does.
- A mirror read costs one request per group on each portal, the same as the other modes.
- Coverage is 100 percent branch on Windows (2473 statements, 552 branches), measured with `coverage run --branch`. The Linux host
  has no `coverage` module installed, so the Linux run reports the assertion count only. The Windows-only
  `ctypes` console branches run only on Windows, so no Linux coverage figure exists for them.

More limits, each one a sentence:

- A mutation run changed the pure core and the command line 443 times. After this round the item type, the secret guard in `redact` and the anonymous group search are pinned. The survivors left are equivalent or cosmetic.
- A spot check of the `caps` code changed it 20 times by hand. The first run left one survivor, the ranking sort, and a fixture where layer order and severity order disagree now pins it. Of 22 caps mutants tried by hand later, 20 turned the self-test red and 2 survived, both listed below. It is a sample, not a sweep.
- Those survivors are the `__main__` guard, the error message format, the progress echo, the rule line width, the token expiration of 60 and `describe()` choosing a group id over its title.
- Four boundaries would not turn the self-test red: the collapse window arithmetic, the 20-item list cap in `describe`, `--window-minutes 0` being accepted, and the detail text of `mirror-new-shared` for an item.
- A group that exists only on the new portal is reported when it is public or org-wide, and not when it is private.
- A group that exists only on the old portal and holds no items is not reported, so that run can say the new portal shares what the old one did.
- Mirror reports a group's `membershipAccess` widening only when the new value is `org`. A move from `none` to `collaboration` is not reported.
- Reading a null `membershipAccess` as `org` comes from observed responses. The Esri group page does not document the field.
- Titles are paired after trimming and lower-casing only. Unicode normal forms, and `ss` against the German eszett, are not equated, so those items read as one missing item and one new item.
- `mirror` ignores `--url`, `--username`, `--out` and `--dir` without a word. A mirror run with no token variable and no `--old-username` reads that portal anonymously and exits 3 or reports many missing items.
- `--verify-host` needs the new portal's `portals/self` to declare that host. An Enterprise portal that reports its internal machine name is refused with exit 2 and there is no override.
- A hosted ArcGIS Online organization is probably refused by `--verify-host`, because the declared host is built from `urlKey` and `customBaseUrl` joined with a dot. It was not run against a live hosted portal.
- Two portals on one host name behind different web adaptor paths are refused, because the old url shares the verified host.
- A mirror run where the old query returns nothing and the new portal has shared items exits 1 with `mirror-new-shared` findings, but it does not print the "returned no items" warning.
- A snapshot file saved with a byte order mark, or in UTF-16, is refused by `diff` and `watch` with exit 64. `--responses` accepts a byte order mark.
- A snapshot whose item value is not an object passes the snapshot check and then ends as `unexpected AttributeError` with exit 2.
- A snapshot whose `modified` is not an integer ends as exit 64 with a message about an unknown sharing level.
- Exit code 64 is used for a corrupt baseline file and for an unknown sharing level, so a scheduler cannot tell a usage error from bad data.
- A `--responses` entry whose `itemId` is a JSON list raises `TypeError` and ends as exit 2 with `unexpected TypeError`.
- `watch` picks its baseline by file name only. A file named `sharewatch-` plus anything, or a snapshot of another portal in the same `--dir`, can become the baseline.
- A snapshot is written non-atomically. A full disk can leave a truncated newest file, and the next `watch` run stops with exit 64 on it.
- A `--url`, `--old-url`, `--new-url` or `--service-url` that carries `user:password@`, a query string, a fragment or a `;parameter` is refused with exit 64 and is never printed back, whatever name the secret has. A secret typed into the path of such a url is still printed in an error.
- A `--username` sign-in over an `http://` url sends the password in clear text. Use `https://`.
- The redirect pin compares host names only, so a redirect from https to http, or to another port on the same host, is followed.
- Tokens travel as query parameters on GET requests, so a proxy or portal access log on the path records them.
- Esri may serve group and item searches from an index that lags behind edits, so run `mirror` a while after the cutover and use an administrator token on each side.
- Item titles, owners and group names are printed as the portal returns them, control characters included, so a member of the org can forge finding-looking lines. The exit code is not affected.
- An event lists its first 20 items and counts the rest, so a bulk finding does not name every item.
- With `--username`, no `SHAREWATCH_PASSWORD` and no terminal on standard input, the run stops with exit 2 and `no password: set SHAREWATCH_PASSWORD`. On Windows, `getpass` reads the console and not standard input, and `isatty()` answers True for the NUL device that a scheduled task may hold. Before this check such a run waited for ever. The check asks `GetStdHandle(STD_INPUT_HANDLE)`, which Microsoft documents as initially the console input buffer, and then `GetConsoleMode`, which Microsoft documents as succeeding for a console input buffer handle. The page for `GetConsoleMode` also says it should not be used to decide whether a handle is a console, and names `NtQueryVolumeInformationFile` instead. This tool uses `GetConsoleMode` once. That it fails for NUL is not stated on the page: it was observed on Windows 11 with a real run with standard input on NUL, which the self-test repeats, and not checked on other Windows versions or on a service with no standard handles.
- An empty `SHAREWATCH_PASSWORD` or token variable is treated as unset.
- The `snapshot`, `diff` and `watch` network paths run against an in-process stand-in. Only `mirror`, `caps` and the shared request layer run over real loopback sockets.
- `caps` was run against stubs only. It was never run against a live ArcGIS Online or Enterprise service, and the stub's refusals are the stub's own words, not recorded Esri answers.
- Esri documents the `capabilities` string and the `Query` capability. It does not document that hiding a field adds `Query`. That came from one case, and `caps` reads the result, so it does not depend on the cause.
- `caps` takes one `--was` for every layer and table of the service. Run it once per layer url when the layers differ.
- `caps` compares layers and tables, not the service root's own `capabilities` string.
- `caps` probes reads only. A `Create`, `Update` or `Delete` that was added is reported from the list. The tool never writes, so it cannot test an anonymous edit.
- `caps` does not read the item's sharing. A flip on a view that is not shared to Everyone is `cap-flip`, ranked 60, with the sharing check left to you.
- A view that held `Query` before is not reported, and that is by design: there is no flip. It also means `caps` is not an audit of every readable view.
- An anonymous count that fails with a 5xx, a timeout, a refused connection or an answer that is not JSON is exit 3. A refusal is HTTP 401 or 403, or an error object with code 401, 403, 498 or 499. Any other 4xx, such as 404, 407, 408 or 429, is exit 3. A layer that answers a stranger in some other way, such as a 200 without `count`, is exit 3 too.
- The refusal as an error object inside an HTTP 200 is not in the REST reference, and no source for it is cited here. `caps` accepts a refusing status or a refusing code in the body, so it does not depend on which one a server uses.
- The `where=1=1` count is the only probe. A layer with a definition query counts the rows the definition lets through, and a view with no rows answers a count of 0, which still counts as open.
- `--service-url` is used as typed, with no query string or credentials expected in it. The host is printed on success and the full url on an error, so a secret typed into the path reaches standard error. The token goes to that host as a query parameter, and a redirect to another host is refused. The anonymous count sends none.
- A `400` error object inside an HTTP 200 is unknown, not closed, because a server that is failing can use it too. A layer that lists no `Query` and answers `400` to a stranger therefore ends the run as exit 3 with a line naming the code.
- A `--service-url` whose last path segment is a non-ASCII digit, such as a superscript, passes the digit test and then fails `int()`. That input is not expected.
- The sample blocks in the Mirror and Caps sections come from stub runs whose data is not shipped, so you cannot regenerate them. The self-test covers the same cases.
- The mutation counts above come from a harness that is not in this repository, so you cannot check them from here.
- `--verify-host` against a hosted ArcGIS Online organization was not run live, so the claim that it is probably refused is untested.
- A token from `SHAREWATCH_TOKEN` is sent over an unverified connection when `--insecure` is set, and in clear text when the url is `http://`. Only `--username` is refused with those, so check the url before you export a token.
- `caps` sends the token to whatever host `--service-url` names, and that host need not be the portal that issued it.
- urllib reads `HTTP_PROXY` and `HTTPS_PROXY` from the environment, so a token in a query string also reaches the proxy's access log.
- The last-resort handler in `main()` prints `error: unexpected <Type>: <message>` without `redact()`. No known path puts a credential there.
- A `--query`, `--url` or snapshot path that the console code page cannot encode, such as Greek on cp1252, ends as `unexpected UnicodeEncodeError` with exit 2 after the first lines are printed, because only finding lines go through `printable()`.
- A snapshot file takes the process's default permissions and holds item titles, owners and sharing levels for the whole org, so keep `--out` in a restricted folder.
- Two `--apply` runs in the same second write the same file name, and the second overwrites the first.
- The redirect pin and the host comparison ignore the port and the scheme, including ftp, in `caps` and `snapshot`, as they do in `mirror`.
- A `SHAREWATCH_TOKEN` in the environment is used even when `--username` is given, and the password is then never read.
- In `watch`, when a snapshot cannot be written and the diff has findings, the exit code is 1 and the write failure appears only on stderr, so a scheduler cannot see that the baseline is going stale.
- The before state is typed by hand in `--was`, so `caps` never records it. A wrong or incomplete `--was` gives a wrong comparison.
- A `--was` that leaves out a capability the view already held, such as Editing listed beside Create, is reported as `cap-added` and exits 1.
- A layer that answers a stranger with an error code outside 401, 403, 498 and 499 exits 3, because the tool cannot tell closed from broken. A Create-only view that is not readable may therefore exit 3 with nothing flipped. Which code Esri returns there was not checked offline.
- `caps` ignores flags that belong to other modes, such as `--dir`, `--out` and `--query`, and `--url` without `--username`, without a word.
- `.gitignore` does not exclude `sharewatch-*.json`. A snapshot holds item titles, owners and sharing levels for the whole org, so keep `--out` outside any repository.
- A snapshot taken with a token that is not an administrator's holds only the items and groups that account can see. `snapshot`, `watch` and `mirror` read `user.role` from `portals/self` and mark such a snapshot `"limited": true`, so the run exits 3 and a later `diff` of that file says so. Only the role `org_admin` counts as an administrator. A custom role with administrator privileges, and a portal that does not describe the user, are treated as limited, so those runs exit 3 although the read was whole.
- A snapshot taken before this check carries no `limited` key, so a `diff` of an old file from a non-administrator still reads as whole.
- A usage error prints only the long flag names, and counts any other word it does not show. A one-letter flag is counted like any other word.
- The Mirror and Caps sample blocks come from stub runs that are not shipped. The Caps block was re-run against an independent `http.server` stub and gave the same output with exit 1, but that stub is not in the repository either.
- The counts of changes in the mutation runs come from a harness that is not in this repository. Treat them as the author's report and not as something you can run.
- Changing `if findings and gaps:` to `if gaps:` in `caps` only repeats the cannot-tell text on a run with gaps and no findings. It changes neither the verdict nor the exit code, so the self-test does not pin it.
- A file path given to `diff` or `--responses` that does not exist is echoed in the error text, so do not type a secret as a path.
- In `snapshot`, a console code page that cannot encode the `--query` or the snapshot path can raise after the file is already written.
- The self-test pins HTTP 400, 404, 407, 408, 429 and 503, and body codes 400, 404, 407, 408, 429 and 500, as unknown. It pins no other status.
- The Limits section is long. The limits that change an exit code are the ones about exit 3, an administrator token, the search ceiling and the host pin.
- The sharing-change example near the Mirror section, with `item-public`, `group-public` and `item-deleted`, is illustrative and not a captured run. The count of 30 requests against 4,000 in the paging section is an estimate.
- A search for `sharemirror` on GitHub on 2026-10-29 and again on 2026-11-10 found the same two unrelated repositories. That says what the search found, not that no tool does a two-portal comparison.
- The self-test excerpt near the top keeps real lines in run order and leaves most out. A line that reads `...` marks the gap.
- For `caps`, a run with no token exits 0 when the result is clean and only prints a warning. The capabilities are then what a stranger is shown.
- A clean Create-only view may exit 3 until the real refusal code Esri sends a stranger is known, because only HTTP 401 and 403 and body codes 401, 403, 498 and 499 count as closed.
- `caps` sends the token as a query parameter on every GET, including to a plain `http://` `--service-url`. Use `https://` there, because the token travels in the query string.
- `--was` is a comma-separated list of exact capability names, such as `Create,Query`. A name with a space in it, such as `Create Query`, is refused with exit 64. A misspelt name still gives a false `cap-flip` and `cap-added`, exit 1.
- A body error code is matched only as an integer. A string code such as `"403"` counts as unknown, so the run exits 3 or reports the flip as inconclusive. That fails safe.
- A missing password exits 2, the same as a portal failure, though it is a configuration error.
- A `--query` or `--url` holding characters the console code page cannot encode, such as Greek on cp1252, stops with `unexpected UnicodeEncodeError` and exit 2 after some output.
- A `--service-url` such as `.../FeatureServer?f=json` is refused with exit 64 like any url with a query string.
- The redirect pin compares host names only. A same-host redirect from `https` to `http`, or to another port, is followed and carries the token in clear text.
- Item titles, owners, group names and messages in a `--responses` file are printed raw, so a member of the organization can forge a line that looks like a finding. The exit code is not affected.
- Snapshot writes are not atomic, and two `--apply` runs in the same second overwrite each other.
- The 20-mutation spot check of `caps` and the macOS statement that the stub server binds only `127.0.0.1` by default are not exercised by anything in this repository.
- Portal error messages are printed to standard error as the portal returns them, control characters included, as item titles are.
- `redact()` matches the raw, `quote_plus` and `quote` forms of a secret only. A server that echoes a token in another encoding, such as HTML entities, is not redacted. Nor is a token that a server echoes percent-encoded twice, for example a login redirect that copies the request URL into `Location`, if the token holds characters outside letters, digits and `-_.`.
- Text read from a `--responses` file, and the `unexpected <Type>` line, are printed as written. Remove tokens from saved responses before you pass them in.
- The `--username` path was tested only against a stub that does not check the `Referer` header, and it was not run against a live portal. A portal that rejects a referer-bound token arriving without a `Referer` header would show as exit 2, not as a false clean.
- An HTTP 403 from a proxy or firewall in front of the service is read as a refusal by the service. A layer can then be called closed when the gateway, not the service, refused the stranger, and `caps` exits 0 for a layer that is readable by a browser the gateway lets through.
- `caps` applies one `--was` to every layer. A `--was` containing `Query` cannot say which layer was readable before, so every layer that answers a stranger is listed as something the run cannot tell, and the run exits 3 when it found nothing else. A public service that always held `Query` therefore never exits 0 under that `--was`. To get a clean result for a Create-only layer, run `caps` on that layer's url with its own `--was`.
- `diff` does not check that its two snapshots came from the same portal url. Two portals in one `watch --dir` give a false diff with exit 1.
- The organization content report was not exercised, and neither were the ArcGIS Enterprise portal logs or the ArcGIS Online activity report.
- On a public Create-only view whose anonymous query Esri answers with an error code other than 401, 403, 498 or 499, `caps` exits 3 on every run until that code is known. This is the safe direction. The code Esri returns for a Create-only view was not checked against Esri documentation, so a routine clean run may never exit 0.
- The README does not cite Esri for the anonymous-refusal shapes: HTTP 401 or 403, or an error object with 498 or 499 inside an HTTP 200. `caps` accepts both, and the closed or open decision rests on observed behaviour only.
- `caps` reads layers one after another. If a later layer cannot be read, the run exits 2 and reports nothing about the layers already read, so run it again or run it once per layer url.
- `--was Create` is the example, but Esri's own example `capabilities` string pairs `Editing` with `Create` and `Query`. A real Create-only view that lists `Create,Editing` reads as `cap-added` and exits 1 on a clean day. That is a false alarm, not a false clean, and what a live Create-only view lists was not checked.
- If `portals/self` gives no org id, `snapshot` and `watch` with `--query` search groups with the item query. The run can then exit 0 with groups missing, and the warning is the only signal. Esri normally sends an id, and this was not run.
- A group row with no `id` would put `None` in the group map and end the run with exit 2 at the sort. Esri sends an id for every group, and this was not run.
- The Esri quotes were checked against Esri's pages: the activity report text "a log of all activity in your organization for a specified time period" ([report fields][aoreport]), the `capabilities` example string, the `Query` requirement and the `returnCountOnly` count ([feature layer][layerref], [query][queryref]). The organization content report and the Enterprise portal logs were not exercised.
- The Microsoft claim about `GetConsoleMode` is from https://learn.microsoft.com/en-us/windows/console/getconsolemode.
- The HTTP-status refusals of `caps` (401, 403, 404 and 503) are exercised in process with a synthetic `HTTPError`, not over a socket. Over a socket the self-test tests only HTTP 200 answers.
- In the `caps` sample block, layer 2 gained both `Update` and `Editing`.
- A server that ignores `returnCountOnly` and answers an anonymous query with feature rows but no count is classified unknown, not open, even though a stranger got rows. It fails safe: `caps` reports `cap-flip` as inconclusive when Query was added and exits 3 when nothing else is found, but it ranks below `cap-flip-open`.
- `caps` run without a token exits 0 when the result is clean and prints only a warning. A layer hidden from anonymous readers fails the description read with exit 2, so the clean exit 0 is not a false clean for that case.
- The `snapshot`, `diff` and `watch` network paths run in the self-test against an in-process fake opener, not against an `http.server` stub. Only `mirror` and `caps` run against a stub over a socket.
- `HTTP_TIMEOUT` is a per-socket-operation timeout and response bodies are read without a size cap, so a server that sends bytes slowly or sends a huge body can hold a scheduled run far longer than the timeout.
- A `ValueError` raised anywhere inside `diff_snapshots` is reported as a sharing level this version does not know, with exit 64, so a malformed hand-edited snapshot is mislabelled. It is still a non-zero exit.
- A `caps` response whose `error` key is present with a null value next to a valid count is classified unknown, so the run exits 3 rather than reporting open. This is the safe direction and is not tested.
- A layer whose `capabilities` string is empty is read like a layer that gives none: `caps` reports a gap and exits 3 when the anonymous count is refused. An empty string proves nothing about what the layer allows.
- `caps` sends the token to whatever host `--service-url` names, so point it only at a service you trust with that token.
- A proxy or WAF that refuses the default Python `urllib` user agent with HTTP 403 makes the anonymous probe read as closed where a browser would get rows. `caps` can then report a clean result for a layer that is open to browsers.
- `--was` is split on commas only, so `Create;Query` becomes one unknown capability name. The effect is a loud false alarm, never a false clean.
- Extra positional words are silently ignored by `snapshot`, `watch`, `mirror` and `caps`, so a mistyped word is not reported. The word is not echoed.
- A control character in an item title can clear the screen, so a member of the org can push real findings out of view in a terminal. The exit code is still 1, so read it, or redirect the output to a file.
- An item whose `access` field is absent reads as private in both snapshots, so a public item with no `access` would never be reported. Esri search sends `access` for every item, and this was not run live.
- The tool writes no CSV. A title that starts with `=`, `+`, `-` or `@` is printed as it is, so a report you paste into a spreadsheet can run it as a formula.

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
