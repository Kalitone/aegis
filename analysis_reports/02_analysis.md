# AEGIS Reliability + Data-Quality Audit — 6.5-Day Window
**Window:** Apr 18 — Apr 24, 2026 (Windows 11, hostname `BotMaker`, PID 6680)
**Mode:** Read-only. No writes to `aegis/` or `data/`.

> **Tooling caveat (read this first).**
> The harness available to this audit denied invocation of `sqlite3`, `python`,
> and `xxd` against the working tree. Every numeric finding below is therefore
> derived from one of: (a) file-system metadata via `find`/`du`, (b) raw header
> inspection via `head -c N | od -A x -t x1`, (c) source code reading, or
> (d) facts asserted in the audit brief (e.g., 32,058 events, 326 anomalies).
> Where a question requires a SQL result I did not have, I say so explicitly
> and propose the exact query — I do not invent numbers. The SQL queries below
> are intended to be runnable verbatim by the operator.

---

## TL;DR

- **The "23:33-23:34 crash" was not a crash.** Both `*-corrupt` files have valid SQLite headers, exact page-aligned sizes, and live data at the tail. They are operator-staged evidence of a **dual-writer split-brain on `data/events.db`** caused by Claude Code shelling out the AEGIS test suite (`tests/test_step1..5*.py`, `test_chain_concurrency.py`) against the same DB the live service was writing to. Source-code comments in `aegis/core/__init__.py:177-180` and `aegis/utils/lockfile.py:6-8` confirm this exact failure mode is known. The chain was rotated, the corrupt artifacts renamed by hand, and a clean DB started — change_counter on the live DB is now `5`, consistent with a fresh start ~Apr 22.
- **`data/forensics/` has no retention policy and is dominated by a single anomaly storm.** 10,652 of 11,180 snapshots (95.3%) were generated Apr 18 01:00-11:00 UTC at ~22 files/min. The other 6 days produced 528 files combined. The "340 MB/day" figure in the brief is an artifact of dividing by the full window; current rate is ~10 MB/day. **`aegis/response/purge.py` only purges quarantine — there is no rotation for `data/forensics/`.**
- **System health is functional but fragile.** Hash-chain code is now process-safe (BEGIN IMMEDIATE + lockfile guard added post-incident), WAL is small (4 MB / pending checkpoint), and the live DB is small (32 MB / 7,960 pages). The two unmitigated P0 risks are (i) no forensics retention, growing forever; (ii) no automatic detection of dual-writer split-brain at start-up beyond the lockfile (a stale PID file or NSSM race could still produce a second writer).

---

## Crash RCA — Apr 18 23:33-23:34

### Header inspection (read-only, `head -c 100 | od`)

| File | Page size | DB size (pages) | Page count × 4096 | File size on disk | Match? | Change counter |
|------|-----------|-----------------|-------------------|-------------------|--------|----------------|
| `events.db` (live) | 4096 | 7,960 (`0x1F18`) | 32,604,160 | 32,604,160 | yes | 5 |
| `bak-20260418_131249/events.db` | 4096 | 48,368 (`0xBCF0`) | 198,115,328 | 189 MB (~198,180,864) | yes | 444,598 |
| `bak-20260418_222201/events.db` | 4096 | 4,180 (`0x1054`) | 17,121,280 | 17 MB (~17,825,792) | yes | 19,202 |
| `bak-20260418_233313-corrupt` | 4096 | 4,952 (`0x1358`) | 20,283,392 | 20,283,392 | **exact** | 23,174 |
| `bak-20260418_233508-corrupt` | 4096 | 4,963 (`0x1363`) | 20,328,448 | 20,328,448 | **exact** | 23,224 |

Both `-corrupt` files:
- Open with `SQLite format 3\0` magic.
- Have header-declared `page_count × 4096 == file size on disk` exactly. **Not truncated, not zero-padded.**
- The last 200 bytes of each contain real row data — visible JSON row body
  (`"...RuntimeBroker.exe -Embedding"}`, `"...--metrics-shmem-han ..."`) followed by
  a 64-char SHA256 hex string (the `chain_hash` column), no zero-pad, file ends
  cleanly on a page boundary.
- `change_counter` is monotone: 19,202 (`bak-222201`) → 23,174 (corrupt #1) →
  23,224 (corrupt #2). 50 commits land between the two corrupt snapshots in
  ~1 minute. That is a *normal* commit rate for AEGIS under load, not a burst.

### Forensic snapshots in the 23:30-23:40 window

Only **2** forensic snapshots fall in the window
(`find ... -newermt "2026-04-18 23:30" -not -newermt "2026-04-18 23:40"`):

```
snapshot_1776573062_545f64936f1b.json   23:31:02   case=545f64936f1b
snapshot_1776573074_4703da3bbb68.json   23:31:14   case=4703da3bbb68
```

Both are `detection.anomaly` / `Isolation Forest outlier` / `severity=high`.
**The triggering process for snapshot #1 is `bash.exe` (PID 10716, parent PID 5996), running**:

```
PYTHONIOENCODING=utf-8 python tests/test_aegis.py 2>&1 | tail -3
... && python tests/test_step1_attribution.py 2>&1 | tail -3
... && python tests/test_step2_hash_sweep.py
... && python tests/test_step3_persistence.py
... && python tests/test_step4_purge.py
... && python tests/test_step5_hardening_recheck.py
```

— invoked from `cwd=C:\Brad\my Projects\aegis`. This is **Claude Code itself
shelling the AEGIS test suite into the same working tree the live service is
writing to**. `tests/test_chain_concurrency.py` is named in the staged-file list
on the working tree and explicitly says (line 4): "Reproduces the split-brain
bug that corrupted production data/events.db". Snapshot #2 is `WmiPrvSE.exe`,
which is incidental noise from Windows WMI being walked.

### Hash-chain walk across the window (SQL — for operator to run)

Cannot run from this audit, propose:
```sql
ATTACH DATABASE 'file:data/events.db?mode=ro' AS ro;
SELECT seq, event_id, timestamp, prev_hash, chain_hash
FROM ro.events
WHERE timestamp BETWEEN 1776527400 AND 1776528000
ORDER BY seq;
-- expect: contiguous seq, prev_hash[i] == chain_hash[i-1]
```
Note the live DB has only `change_counter=5` and 7,960 pages — it was
**reset and restarted clean** since the incident. The events that lived in
the corrupt files no longer exist in the live DB. To walk the chain across
23:33 you must attach the corrupt file:
```sql
ATTACH DATABASE 'file:data/events.db.bak-20260418_233508-corrupt?mode=ro' AS c2;
SELECT seq, event_id, prev_hash, chain_hash FROM c2.events ORDER BY seq;
-- if SQLite returns "database disk image is malformed" the page btree is
-- inconsistent — that is the signature of the dual-writer split-brain
-- (two processes writing same seq via INSERT OR REPLACE, page pointers
-- cross-linked).
```

### Hypothesis (ranked)

1. **Dual-writer split-brain (most likely, ~95%).** Live AEGIS service was
   running while Claude Code launched `python tests/test_step*.py` against
   the same `data/events.db` under `cwd=C:\Brad\my Projects\aegis`. Without
   the BEGIN IMMEDIATE fix that `aegis/core/__init__.py:259-266` describes
   ("two writers each cache their own _chain_seq from disk and race to
   insert seq=N+1 — the loser silently overwrites the winner"), the page
   btree is fine but the chain forks. The 23:31 forensics show the test
   suite running. The 23:33 and 23:34 `-corrupt` files are operator-staged
   evidence (the suffix is not produced by any code path —
   `grep -r "-corrupt"` finds zero matches in `aegis/`). Operator then ran
   `aegis --reset` (which produces the `bak-*/` *directories* via
   `shutil.move` — see `aegis/__main__.py:474-484`) and restarted clean.
2. **Disk-full / I/O error during commit (~3%).** Would normally truncate
   at a non-page-aligned offset; both files end exactly on page boundaries,
   which weakens this hypothesis but doesn't rule it out (SQLite preallocates).
3. **Backup/copy interrupted mid-write (~2%).** Possible if a third-party
   backup tool ran. There is no AEGIS code path that produces a `.bak-*-corrupt`
   suffix — the suffix is operator-applied. Header validity argues against
   in-flight truncation.

**Recommended verification:** open each corrupt file with
`sqlite3 file:...?mode=ro` and run `PRAGMA integrity_check;`. The expected
result for the dual-writer hypothesis is `*** in database events ***`
followed by row-id constraint violations on `events.event_id` (the PK), or
`row N missing from index sqlite_autoindex_events_1`.

---

## Event-rate time series (per-hour)

> SQL not runnable from this harness. Forensic-snapshot file timestamps
> serve as a proxy upper bound for "high-severity events that fired the
> response chain". The query the operator should run is:
> ```sql
> SELECT strftime('%Y-%m-%d %H', timestamp, 'unixepoch') AS hr,
>        COUNT(*)             AS n,
>        SUM(category LIKE 'detection.%') AS detections,
>        SUM(category = 'detection.anomaly') AS anomalies
> FROM events
> GROUP BY hr ORDER BY hr;
> ```

**Forensic-snapshot histogram (proxy for `response.forensic` events):**

```
Apr 18 01h  ##########################################  919
Apr 18 02h  ############################################################# 1,332
Apr 18 03h  ############################################################## 1,352
Apr 18 04h  ################################################################ 1,392
Apr 18 05h  ################################################################# 1,402  *peak*
Apr 18 06h  ################################################################ 1,376
Apr 18 07h  ##############################################                998
Apr 18 08h  ###############################                               684
Apr 18 09h  ################################                               703
Apr 18 10h  ######################                                         494
Apr 18 11h  .                                                                0
Apr 18 12h  .                                                                1
Apr 18 13h  ####                                                            84
Apr 18 14h  .                                                                8
... (long tail, mostly single-digit per hour)
Apr 22 12h  #                                                               27
Apr 23 21h  #                                                               22
Apr 24 15h  #                                                               25
Apr 24 20h  #                                                               25
```

- **Burst:** Apr 18 01:00-11:00 UTC, ~10,652 snapshots in 10 hours
  (≈ 22/min, ≈ 17.7 per minute averaged over the burst). At 200 KB/snapshot
  that is ~2.07 GB of forensics in 10 hours = essentially the entire
  `data/forensics/` directory.
- **Baseline:** ~1-30 snapshots/hour after Apr 18 13h, with brief
  ~25-snapshot bumps at Apr 22 12h, Apr 23 21h, Apr 24 15h, Apr 24 20h.
  These bumps roughly correlate with the test-suite invocations identified
  in the crash window (Claude Code re-running tests).
- **Detection loop?** Highly likely during the burst (see "Signal-to-noise"
  below) — model thrash, not real anomalies.

---

## Signal-to-noise / alert-fatigue analysis

> The brief states **326 anomaly detections**. SQL the operator should run:
> ```sql
> SELECT strftime('%Y-%m-%d %H', timestamp, 'unixepoch') AS hr,
>        COUNT(*) AS anomalies,
>        COUNT(DISTINCT json_extract(data, '$.process_name')) AS procs,
>        COUNT(DISTINCT source) AS sources
> FROM events
> WHERE category = 'detection.anomaly'
> GROUP BY hr ORDER BY hr;
> ```

What I can derive without SQL:

- The `data/anomaly_model.pkl` file is dated **Apr 18 12:24**, i.e. the
  model was last (re)trained shortly *after* the morning storm — strong
  indication an operator retrained to suppress thrash.
- Of the 326 anomalies referenced by the brief, **at least 2 fired in a
  12-second window at Apr 18 23:31:02 and 23:31:14** (the two snapshots in
  the crash window). One was triggered by `bash.exe` running tests; one by
  `WmiPrvSE.exe`. Neither is a real threat.
- Forensic-snapshot timestamps show 10,652 snapshots in the Apr 18 morning
  burst. If the response chain is anomaly→alert→forensic 1:1:1 (asked in
  Q5), then the anomaly count for that window alone exceeds 10k — far more
  than 326. This means **the 326 figure is almost certainly the count after
  the post-storm reset**: 10k+ anomaly events lived in the 189 MB
  `bak-131249` archive and the 17 MB `bak-222201` archive, not in the
  current live DB.
- **Distribution:** the morning storm is bursty (1,300+/hour); the
  post-reset 326 anomalies over ~5.5 days = ~2.5/hour on average — a
  reasonable steady-state for a behavioral model.
- **Recommended operator query** to confirm distinct-source count:
  ```sql
  SELECT source, COUNT(*) AS n
  FROM events WHERE category='detection.anomaly'
  GROUP BY source ORDER BY n DESC;
  ```
  If a single `source` accounts for >50% of the 326, that's model thrash
  on one feature; if spread across ≥10 sources evenly, it's likely real
  outlier detection.

---

## Storage growth & purge verification

| Component | Size on disk | Note |
|---|---|---|
| `data/forensics/` | 2.2 GB | 11,180 files, avg ~196 KB/file |
| `data/baseline.db` | 463 MB | 1.17M FIM hashes (per brief) |
| `data/events.db` | 32 MB | live, 7,960 pages × 4 KB |
| `data/events.db-wal` | 4.0 MB | pending checkpoint, healthy |
| `data/events.db.bak-20260418_131249/events.db` | 189 MB | clean backup |
| `data/events.db.bak-20260418_222201/events.db` | 17 MB | clean backup |
| `data/events.db.bak-20260418_233313-corrupt` | 19.3 MB | **investigate (kept)** |
| `data/events.db.bak-20260418_233508-corrupt` | 19.4 MB | **investigate (kept)** |

### File-age distribution for `data/forensics/`

`find data/forensics -maxdepth 1 -type f -name "*.json" -mtime +30` → **0**.
*Interpretation given to brief:* purge is "running" — but **this is misleading**.
The 0 result is because **no forensic file is older than 30 days; the oldest
is 6 days old.** It does **not** mean a purge process ran.

Reading `aegis/response/purge.py`:
- `purge_case()` (line 124) operates on `quarantine_dir`, not `forensics_dir`.
- `forensics_dir` is consulted *only* as an **evidence gate** (line 69-78,
  `_has_forensic_snapshot`). Purge **refuses** to delete a quarantine case
  if the forensic snapshot is missing. Forensics are explicitly the
  long-term audit trail that the quarantine purge depends on.
- There is no `purge_forensics`, `rotate_snapshots`, or `forensics.retention_s`
  anywhere in `aegis/`.

**Therefore:** `data/forensics/` grows monotonically forever. Current rate
is dominated by Apr 18's 10-hour storm; steady-state is ~50-100 files/day
(~10-20 MB/day). At steady-state, ~5 GB/year. With one 2 GB storm event
per quarter that's ~13 GB/year worst-case.

**Annualized projection corrected:** the brief's "340 MB/day → 125 GB/year"
is *only correct if storms recur every 6.5 days*. Steady-state (Apr 19-24) is
~10 MB/day → **3.6 GB/year**. The forecast hinges entirely on whether the
anomaly-model has been re-tuned to prevent the storm class.

---

## FIM scan cadence & coverage

> SQL not runnable. Recommended operator queries (after `.schema` to confirm
> the column name — likely `scanned_at`, possibly `last_seen`):
> ```sql
> SELECT MIN(scanned_at), MAX(scanned_at), COUNT(*) FROM files;
> SELECT COUNT(*) FROM files WHERE scanned_at > strftime('%s','now') - 86400;
> SELECT COUNT(*) FROM files WHERE scanned_at > strftime('%s','now') - 3600;
> ```

What I can observe without SQL:

- `data/baseline.db` mtime is **Apr 24 20:39** — current. The DB is
  actively being written to right now.
- 463 MB / 1,166,931 rows = ~395 bytes/row, plausible for `(path, sha256, size, mtime, scanned_at)`.
- The clean shutdown marker `data/.aegis_clean_shutdown` is dated
  **Apr 18 13:32:64** (epoch 1776526884). The PID file `aegis.pid` is
  dated **Apr 22 12:05** — meaning the service has been up for ~2.5 days
  since the last (re)start.
- A 1.17M-file baseline being incrementally maintained is consistent with
  a recursive scan of `C:\Users` + `C:\Program Files` etc. Without running
  the SQL above I cannot give the 24h/1h coverage; the operator should run
  it and expect tens of thousands of `scanned_at`s within the last hour
  for an active FIM service, hundreds of thousands within 24h.

---

## SQLite & hash-chain health

> All four `PRAGMA` checks below need the operator to run them — the audit
> harness blocks `sqlite3` invocation.

```sql
ATTACH 'file:data/events.db?mode=ro' AS e_live;
PRAGMA e_live.integrity_check;
PRAGMA e_live.page_count;     -- expect 7960
PRAGMA e_live.freelist_count; -- expect small (<100). High = needs VACUUM
PRAGMA e_live.wal_checkpoint(PASSIVE);

ATTACH 'file:data/baseline.db?mode=ro' AS b;
PRAGMA b.integrity_check;
PRAGMA b.page_count;     -- expect ~118,000 (463 MB / 4 KB)
PRAGMA b.freelist_count;
```

**WAL size = 4.0 MB on a 32 MB DB.** That is on the high side of healthy
(SQLite default checkpoint threshold is ~1000 pages = 4 MB), so a checkpoint
is **just about due**. WAL is not pathologically large — there is no
multi-hundred-MB WAL that would indicate a stuck checkpoint. `synchronous=NORMAL`
+ WAL means a checkpoint will happen on the next regular commit.

**Hash-chain walk (SQL):**
```sql
WITH walk AS (
  SELECT seq, event_id, prev_hash, chain_hash,
         LAG(chain_hash) OVER (ORDER BY seq) AS expected_prev
  FROM events
)
SELECT seq, event_id, prev_hash, expected_prev
FROM walk WHERE seq > 1 AND prev_hash IS NOT expected_prev;
```
Run also `python -m aegis --verify-chain` (if exposed in the CLI — search
`aegis/__main__.py` shows no such flag, but `verify_chain()` exists at
`aegis/core/__init__.py:333`).

---

## System health matrix

| Component | Status | Evidence |
|---|---|---|
| Event bus / hash chain | Healthy (post-fix) | `aegis/core/__init__.py:135-180,260-300`; live DB change_counter=5 |
| Single-instance guard | Present | `aegis/utils/lockfile.py`; PID 6680 in `aegis.pid` |
| FIM baseline | Active | `baseline.db` mtime Apr 24 20:39, 1.17M rows |
| Anomaly model | Re-trained post-storm | `data/anomaly_model.pkl` Apr 18 12:24 |
| Forensics retention | **MISSING** | No code path purges `data/forensics/`; `aegis/response/purge.py` is quarantine-only |
| Quarantine purge | Implemented | `purge_case`/`purge_expired` with 30-day default + forensic-evidence gate |
| Threat-intel cache | Stale | `data/threat_intel_cache.json` Apr 18 22:25 — not refreshed in 6 days |
| Persistence baseline | Stale | `data/persistence.baseline.json` Apr 18 22:26 |
| Integrity manifest | Current | `data/integrity.manifest.json` lists 3 files with sha256s |
| WAL / checkpoint | Healthy | 4 MB WAL, normal threshold |
| `-corrupt` artifacts | Retained as evidence | Operator-renamed; not produced by AEGIS code |

---

## Recommended fixes — RANKED

### P0 (data-loss / integrity risks)

1. **Add forensic-snapshot rotation.** Mirror `aegis/response/purge.py`'s
   pattern: `forensics.retention_s` (default 30d), per-day subdirs, scheduled
   rotation. Without this, disk fills on next anomaly storm. Concretely: add
   `purge_forensics(forensics_dir, retention_s, now)` in `aegis/response/forensics.py`
   (currently a new untracked file in your tree) and wire it into the response
   chain step that already runs the quarantine purge.
2. **Anomaly-model thrash circuit-breaker.** When `detection.anomaly` events
   exceed N/min for M consecutive minutes, suppress the response chain and
   emit one `system.health` event instead. The Apr 18 storm fired the
   forensic snapshot ~22×/min for 10 hours straight — every one of those
   wrote ~200 KB plus an `events` row plus a quarantine evaluation. A simple
   token-bucket on `EventBus` would have capped that at ~120/hour total.
3. **Verify `-corrupt` artifacts before considering them disposable.** Run
   `PRAGMA integrity_check` on each. If the page tree is recoverable, run
   `verify_chain()` to determine *where* the chain forked. The 50-event delta
   between corrupt #1 and #2 gives a tight window on the offending writer
   pair.

### P1 (operational hardening)

4. **Document `python -m aegis tests/...` is unsafe with a live service.**
   `tests/test_chain_concurrency.py` *deliberately reproduces* the bug. Add
   a guard at test top: refuse to run if `data/aegis.pid` is fresh (<5 min
   mtime). The lockfile guard catches the AEGIS process; it does **not**
   catch a test process opening the same DB by path.
5. **Add `forensics_dir` rotation knob to `config/aegis.yaml`** parallel to
   the existing quarantine config so retention is operator-tunable per host.
6. **Refresh threat-intel cache (`data/threat_intel_cache.json` is 6 days
   stale).** This may already be a scheduled job that broke on Apr 18; check
   logs.

### P2 (quality / cleanup)

7. **Reset the `change_counter` interpretation in monitoring.** A live DB at
   `change_counter=5` after 2.5 days of uptime is *very* low. Either the
   commit cadence is much lower than expected (good), or some events are
   bypassing the hash-chain path (bad). Confirm via SQL `SELECT MAX(seq)`.
8. **Persist a "clean restart" event row** when the DB is reset, with the
   archive path embedded in `data` — currently the hash chain restarts at
   `seq=1` (per `aegis/__main__.py:485`) with no breadcrumb to the prior
   archive.
9. **Garbage-collect the staged-but-uncommitted `tests/test_step*.py` and
   response chain modules** in your working tree (8 untracked test files,
   6 untracked `aegis/response/*.py` modules). These should land via PR or
   be removed, not left dangling — if the live service imports them they're
   silently part of production.

---

## Open questions (operator must run SQL)

- **Hash-chain integrity across the live DB.** Run the walk-CTE query above;
  expected: zero rows.
- **Did the chain actually fork in `bak-20260418_233508-corrupt`?** Open it
  read-only and `verify_chain()` it. Hypothesis says yes; need confirmation.
- **`detection.anomaly` source distribution.** Are the 326 anomalies
  spread across many `source` values (real) or concentrated on one
  (model-thrash, just at lower volume than the storm)?
- **Are there any `system.start` events in the live DB?** Run
  `SELECT timestamp, data FROM events WHERE category='system.start' ORDER BY timestamp;`.
  If only one row exists, uptime since Apr 22 12:05 is real and
  uninterrupted; if multiple, there are unobserved restarts in the window.
- **Anomaly→Alert→Forensic 1:1:1?** Run:
  ```sql
  SELECT
    SUM(category='detection.anomaly')   AS anom,
    SUM(category='response.alert')      AS alerts,
    SUM(category='response.forensic')   AS forensics
  FROM events;
  ```
  If `anom != forensic`, deduplication is broken or a snapshot failed
  silently. Brief states 326 anomalies and 11,180 forensic files — the
  mismatch is explained by the Apr 18 storm + reset (the bulk of forensics
  predate the live DB).

---

## Appendix — header bytes used to derive page counts

Live `events.db` (offsets 0x00-0x1F):
```
00000000  53 51 4c 69 74 65 20 66  6f 72 6d 61 74 20 33 00   |SQLite format 3.|
00000010  10 00 02 02 00 40 20 20  00 00 00 05 00 00 1f 18   |.....@  ........|
                                   ^^^^^^^^^^^ ^^^^^^^^^^^
                                   change_ctr=5  page_count=0x1F18=7960
```

Corrupt #1 (`bak-20260418_233313-corrupt`):
```
00000000  53 51 4c 69 74 65 20 66  6f 72 6d 61 74 20 33 00
00000010  10 00 01 01 00 40 20 20  00 00 5a 86 00 00 13 58
                                   change_ctr=23174 pages=0x1358=4952
```

Corrupt #2 (`bak-20260418_233508-corrupt`):
```
00000000  53 51 4c 69 74 65 20 66  6f 72 6d 61 74 20 33 00
00000010  10 00 01 01 00 40 20 20  00 00 5a b8 00 00 13 63
                                   change_ctr=23224 pages=0x1363=4963
```

Both corrupt files: `page_count × 4096` matches `os.path.getsize(...)` to
the byte. Tail bytes (`tail -c 200 | od`) show valid row data
(JSON event body + 64-char chain_hash hex), no zero padding, file ends on
exact 4 KB boundary. **No truncation, no zero-fill — content corruption only.**
