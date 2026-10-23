# Local database backup, verification and recovery

`python -m artemis_v3.storage` verifies or copies the explicit case archive or
review store. Backups and restores create a **new file**; they never replace an
existing database. The commands work without a model, browser or network and do
not execute samples. They preserve source bytes, synthetic labels, saved model
explanations, judgments and revision IDs without migrating a schema.

## Back up a paired investigation

Keep investigation stores and backups outside the checkout. The following example
assumes `../artemis-data` and `../artemis-backups` already exist. Use your own paths
and new destination names each time. Paths with spaces need shell quotes.

1. Stop the workbench and any other writer before backing up both stores. Each
   file has its own consistent snapshot; the two commands are not one cross-file
   transaction. Stopping writers preserves a matching pair.
2. Back up both files that actually exist. Startup alone does not create stores.

```sh
python -m artemis_v3.storage backup --kind case --source ../artemis-data/cases.sqlite --destination ../artemis-backups/cases-20261022.sqlite --json
python -m artemis_v3.storage backup --kind review --source ../artemis-data/reviews.sqlite --destination ../artemis-backups/reviews-20261022.sqlite --json
python -m artemis_v3.storage verify --kind case --source ../artemis-backups/cases-20261022.sqlite --json
python -m artemis_v3.storage verify --kind review --source ../artemis-backups/reviews-20261022.sqlite --json
```

3. Retain each command's counts and snapshot SHA-256 with the pair. Keep an
   independent copy on storage appropriate for the investigation's sensitivity.
   Backups contain original reports and analyst judgments without anonymization
   or encryption. A checksum identifies bytes; it does not authenticate their owner.
4. Restart the original workbench if needed. Later writes are not in these copies.

A single-file snapshot also works with a live WAL store: it includes committed
records visible in the read transaction, excludes uncommitted changes and does
not checkpoint or change the source's journal mode. In rollback-journal mode the
read transaction can temporarily delay writers. Contention may fail the command;
stop writers and retry at a fresh destination. SQLite may manage its normal WAL
shared-memory sidecars even when the source connection is read-only.

Do not copy only a live `.sqlite` main file or delete its `-wal`/`-shm` files by
hand. The utility uses SQLite's backup API and converts **only its private copy**
to DELETE journal mode before validation, so a published snapshot is standalone.

## Restore and rehearse

Stop the workbench before selecting a replacement pair. Restore into new paths:

```sh
python -m artemis_v3.storage restore --kind case --source ../artemis-backups/cases-20261022.sqlite --destination ../artemis-data/recovered-cases.sqlite --json
python -m artemis_v3.storage restore --kind review --source ../artemis-backups/reviews-20261022.sqlite --destination ../artemis-data/recovered-reviews.sqlite --json
python -m artemis_v3.workbench --case-db ../artemis-data/recovered-cases.sqlite --review-db ../artemis-data/recovered-reviews.sqlite
```

Reopen a known source through **本地调查归档**. Check its exact report/rule
fingerprints and synthetic labels. In **当前来源的核验历史**, load a saved review;
the workbench restores the saved explanation and issues a new process-local
receipt without requiring a model. Inspect score history and per-claim judgments.
An explicit subsequent save appends a new revision in the restored store. Keep
the originals and backup pair until the recovered workflow is confirmed.

The backup preserves stored model output; it does not preserve an unsaved browser
draft or an expired receipt. Raw files never archived, exports, configuration and
model weights also require their own copies. Restoring does not approve scores
or record a final malware conclusion.

## Checks and limits

Verification reads **every row**, not only the workbench's recent history page:

- Application/schema IDs and the application's current table/index/constraint
  definitions. Case schema 1 and review schemas 1/2 are supported. Unknown versions,
  extra objects and modified layouts are refused. Schema-1 reviews stay schema 1.
- SQLite integrity plus application record checksums and indexed identities.
- Every archived report/ruleset's size, parseability and stable source identities,
  using the same source check as reopening. Parser-derived counts may evolve.
- Score proposal identity; exact saved generation, claim judgments and summary
  integrity; contiguous revisions and previous-record links within each proposal
  or generation. An intact database page layout alone is not enough.

Verification does not infer factual truth, authenticate reviewers, reconstruct
missing records or detect a deliberately rewritten database with matching hashes.
It cannot detect deletion of an entire history or its final suffix without an
independently retained inventory. A review-only verification has no original
source bytes with which to repeat analysis; source-dependent checks still happen
when the workbench reopens that review. Future parser/schema changes can cause
verification to refuse an older store; preserve it and investigate, rather than
silently changing its contents.

Budgets: a 512 MiB main file/logical database, existing case limits of 1,000 records
and 128 MiB source payload, 10,000 rows per review table, 32 MiB per score record
and the existing 256 KiB per claim record. Oversized stores are refused, not
truncated. Default timeout is 30 seconds; `--timeout 120` can increase it up to
300. The deadline is checked between parsing/hashing/backup steps and through
SQLite progress callbacks, with short lock waits. It cannot forcibly interrupt a
blocked operating-system I/O call or a single running Python parse operation.

## Publication and failures

The utility creates a private temporary database in the destination directory,
closes all database handles, verifies all records, hashes and syncs the file, then
publishes it with an exclusive hard link. Existing files, directories, symlinks
and destination `-wal`, `-shm` or `-journal` sidecars are refused. Source symlinks
and non-regular files are refused. Concurrent publishers cannot replace a winner.
Supported local filesystems must allow hard links; there is no unsafe overwrite
or partially copied-file fallback. Use a directory you control and do not start
a process against the new destination before the command finishes.

Backup/restore success reports `snapshot_sha256`, byte count, schema and record
counts. This hash is for the completed snapshot file; SQLite file headers can
differ from the source or a later restore even when application records match.
Where directory syncing is unsupported, `directory_synced` is false (and the
text CLI prints a notice); crash durability of the directory entry is not
confirmed. A rare temporary cleanup failure after successful publication is
reported as `cleanup_warning`, listing only private temporary files to remove.

Invalid inputs, corruption, incomplete revision chains, budget/time limits and
copy failures return exit code 2. No partially copied or unverified database is
published. The utility never repairs a source, deletes a destination or merges
histories. Preserve the source and read the error before retrying. Exit code 0
means the stated checks passed, not that real-world investigation quality or
physical disk failure recovery has been measured.

## Verification and references

Synthetic tests cover exact-byte round trips, both review schema versions,
committed WAL/uncommitted changes, all-record corruption detection, broken
revision chains, sidecars/symlinks, concurrent publication, I/O failures and
deadline cleanup. A paired restore is reopened through the actual workbench HTTP
API and a claim revision appended without a model. Chromium also stops the original
workbench, backs up and restores both stores through the CLI, reopens the exact
saved explanation in a new process without a model, and appends a third revision.
It checks original database hashes, historical attribution, score history, exported
records and desktop/mobile layout. CI runs these checks on Linux and adds a Windows
recovery job for file-handle and hard-link behavior. Real
deployment paths/filesystems, disk loss, access controls and backup retention
still require an operator's rehearsal.

Implementation references: [SQLite backup API](https://www.sqlite.org/backup.html),
[WAL lifecycle](https://www.sqlite.org/wal.html), and
[Python sqlite3 connection management](https://docs.python.org/3.11/library/sqlite3.html#how-to-use-the-connection-context-manager).
