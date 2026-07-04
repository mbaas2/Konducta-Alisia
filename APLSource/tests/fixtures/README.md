# Alisia test fixtures

Historical `.eml` files that caused bugs in the past — kept here as permanent
regression fixtures. When a new bug is fixed, the mail that triggered it should
land in this folder so the same shape of input never silently regresses again.

## How fixtures get used

`TestHarness.DropFixture <name>` copies a fixture straight into the configured
`pop3repeat` folder. The test driver then triggers Konducta's poll cycle and
inspects the archive / outbound folders to verify the fix still holds.

## Naming convention

`<YYYYMMDD>_<short-slug>_<source>.eml`

- **YYYYMMDD** — date the bug was hit (not when the fix landed)
- **short-slug** — 2–4 words describing the symptom, lowercase, hyphens
- **source** — `outlook`, `gmail`, `thunderbird`, `mobile`, `mailer-daemon`, …

Examples:

    20260412_fading-depth-collision_outlook.eml
    20260412_footer-dedup-8x_gmail.eml
    20260408_unclosed-boundary_outlook-mobile.eml
    20260401_bounce-soft-then-hard_postfix.eml

## Required sidecar: one-line `.md` per fixture

Every `.eml` MUST have a companion `<same-name>.md` with at minimum:

    # <slug>

    **Symptom:** one sentence — what visibly went wrong.
    **Root cause:** one sentence — which code path mishandled it.
    **Fix:** commit hash or PR link.
    **Asserted invariant:** which check in verify_fading.py / test runner
      confirms the regression is gone. If no assertion exists yet, write
      "TODO — add I<n> to verify_fading.py".

Without the sidecar, the fixture is noise. With it, every file in this folder
tells you exactly why it exists.

## Sanitization

Fixtures are committed to the repo. Before adding one:

- Replace real subscriber addresses with `@example.org` / `@example.invalid`.
- Replace real names with `Alice`, `Bob`, `Carol`.
- Redact any List-Unsubscribe tokens, reset links, or confirmation tokens —
  these are secrets that shouldn't live in git.
- Keep the structural shape (Outlook wrappers, Gmail blockquotes, forward
  markers) byte-identical to the original — that's the whole point.

## Good candidates for early fixtures

Not yet present but worth adding once reproducers are handy:

- `*_fading-depth-collision_*.eml` — the Markos/Michael thread that prompted
  the DepthAtOffset fix. Exercises the formal-forward + blockquote combo.
- `*_footer-dedup-8x_*.eml` — the 8-footer Gmail chain that prompted
  DedupEmbeddedFooters. Exercises Phase 1 Pattern 6.
- `*_u-fffd-subject_*.eml` — any mail where the Subject went through
  `⎕UCS 65533` corruption; tests the charset-repair path.
- `*_empty-mail_*.eml` — headers-only; tests empty-body handling.
- `*_malformed-boundary_*.eml` — multipart missing `--boundary--` terminator.
- `*_huge-html_*.eml` — multi-MB inline HTML from a rich-text sender.
