# TestHarness — Alisia integration-test helper

`TestHarness.aplc` is a small APL class that builds `.eml` files (from scratch
or by patching existing ones) and drops them into the Konducta `pop3repeat`
folder. Konducta then feeds them to Alisia as if they had arrived by POP3, and
you can inspect the archive / outbound folders to see how Alisia responded.

The harness only covers the **input** side: it produces and drops `.eml`s.
Driving the poll cycle and checking the replies is deliberately left to the
caller — so the same harness works in an interactive session, in an automated
test runner, and in ad-hoc repros.

## Prerequisites

1. Alisia must already be loaded in the workspace (`)LOAD ALISIA` or equivalent).
   The harness requires `#.NuGet` and reuses the same MimeKit/MailKit version
   Alisia constructed (`4.14.0` by default — override via
   `th.MailKitVersion←'…'` before any builder is called if your deployment
   uses a different version).
2. You know the absolute path of `pop3repeat`. The harness does not try to
   guess — pass it to the constructor.

## Quick start

```apl
)LOAD ALISIA
⎕IO←1

⍝ Construct once per session:
th←⎕NEW #.Handlers.Alisia.tests.TestHarness 'C:\Konducta\pop3repeat\'
th.FixturesDir←'C:\Konducta-Alisia\APLSource\tests\fixtures\'

⍝ Drop a handful of single-command mails:
{}th.DropCommand 'alice@example.org' 'list@apl-germany.de' 'SUBSCRIBE'
{}th.DropCommand 'bob@example.org'   'list@apl-germany.de' 'HELP'
{}th.DropCommand 'admin@apl-germany.de' 'list@apl-germany.de' 'LISTMEMBERS'

⍝ Drop a threaded reply chain (depth 3, alternating authors):
thread←th.MakeThread 'alice@example.org' 'bob@example.org'
                     'list@apl-germany.de' 3 'Re: Frage zu APL'
{}th.DropMime¨thread

⍝ Patch an existing .eml (swap identity, keep body):
o←⎕NS''
o.From←'alice@example.org'
o.Subject←'Re: repro nach Fix'
o.MessageId←'<new-fresh-id@test.alisia>'
{}'C:\repro-inbox\bad262.eml' th.PatchAndDrop o

⍝ Drop a historical-problem fixture:
{}th.DropFixture '20260412_fading-depth-collision_outlook.eml'

⍝ Trigger Konducta's poll cycle here (whatever your deployment exposes),
⍝ then inspect archive/ and out/ to verify replies and threading.
```

## Method cheatsheet

| Method                        | Purpose                                                          |
| ----------------------------- | ---------------------------------------------------------------- |
| `Drop raw`                    | Drop a raw char-vector as `.eml`. For hand-crafted / broken MIME.|
| `DropFile path`               | Copy an existing file into `pop3repeat`.                         |
| `DropMime mmsg`               | Serialize a `MimeMessage` into `pop3repeat`.                     |
| `DropFixture name`            | Copy `fixtures/<name>` into `pop3repeat`.                        |
| `ListFixtures`                | Return the `.eml` filenames in `FixturesDir`.                    |
| `MakeMail (from to subj t h)` | Build a plain/html/alt `MimeMessage`.                            |
| `MakeCommand (from to cmd)`   | Build a command mail (subject = cmd, empty body).                |
| `DropCommand (from to cmd)`   | Build + drop a command mail in one call.                         |
| `parent MakeReply (from t h)` | Threaded reply: In-Reply-To + References + "Re:" + quotes.       |
| `MakeThread (fA fB to N s)`   | Alternating-author reply chain of depth N.                       |
| `Patch (path overrides)`      | Load `.eml`, apply `overrides` namespace, return `MimeMessage`.  |
| `path PatchAndDrop overrides` | Patch + drop in one call.                                        |
| `MakeEmpty (from to)`         | Empty subject, empty plain body.                                 |
| `MakeHugeHtml (from to s kb)` | Ballast an HTML body up to roughly N KB.                         |
| `DropMalformedMime (f t s)`   | Raw multipart with the terminator omitted.                       |
| `MakeBounceNdr (list orig)`   | Minimal RFC 3464 DSN.                                            |
| `MakeNonUtf8Subject (f t s)`  | Subject encoded with ISO-8859-1 instead of UTF-8.                |

## Filename convention

Each dropped file is named

    <prefix>_<YYYYMMDD>_<HHMMSS>_<MMM>_<NNNN>.eml

where the default prefix is `th` (overridable via the 2-arg constructor:
`⎕NEW TestHarness ('C:\…\pop3repeat\' 'bugrepro')`). The counter guarantees
uniqueness even when multiple drops happen inside the same millisecond.

## Recommended workflow for a new bug

1. Get the raw offending `.eml` from the mailbox that reproduced the bug.
2. Sanitize it (see `fixtures/README.md`).
3. Save as `fixtures/<date>_<slug>_<source>.eml` plus a sidecar `.md`.
4. Add an assertion to `verify_fading.py` (or a new companion validator)
   that would have caught the bug.
5. Before merging the fix: the fixture runs through Alisia and `verify_fading`
   fails. After the fix: the fixture still runs, and the validator passes.
   That's the regression guarantee.

## Limitations & known rough edges

- `MakeReply` quotes in the German "Am … schrieb …" style. If you need
  Outlook's "Von:/Betreff:" formal-forward block to trigger the Phase 2
  forward-depth path, capture a real Outlook forward as a fixture instead;
  the harness intentionally does not try to emulate vendor-specific quoting.
- `MakeNonUtf8Subject` relies on `MimeKit.Headers.Replace(HeaderId, Encoding, string)`.
  If the Dyalog .NET bridge has trouble resolving that overload in your build,
  fall back to setting the header via raw `Drop`.
- Dropping files into `pop3repeat` is not atomic against concurrent reads.
  If the Konducta watcher picks files up while they're still being written,
  you may see partial reads. On Windows this is rarely a problem; on Linux,
  write to a `.tmp` sibling and rename as a follow-up if it becomes an issue.
