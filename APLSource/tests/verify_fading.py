#!/usr/bin/env python3
"""Regression validator for Alisia header/footer fading.

Scans one or more archived .eml files and checks the following invariants on
the HTML body that was produced by Alisia:

  I1  No Outlook-mangled Alisia tables survive unchanged.
      (Signature: <table border="0">...<td style="... background: 0% 0% repeat
       rgb(<one of Alisia's palette colours>) ..."> — these must have been
       re-written to <table class="alisia_header"|"alisia_footer">.)

  I2  Every canonical alisia_header / alisia_footer element carries a <td>
      background colour that matches its blockquote nesting depth, i.e. the
      re-fading was actually depth-aware.

  I3  For files that SHOULD be the result of Alisia's own SendMimeMsg (i.e.
      the outbound archive), there is a top-level (<blockquote>-free) Alisia
      header AND a top-level Alisia footer — proving ht / hb insertion worked.

  I4  Outbound HTML contains EXACTLY ONE canonical alisia_footer — the fresh
      one at <blockquote> depth 0. Any footers that accumulated through a long
      reply chain should have been stripped by Phase 1.5 DedupEmbeddedFooters
      (visual noise + Gmail spam signal from repeated near-identical link blocks).

Usage:
    python3 verify_fading.py <file-or-directory> [...]
    python3 verify_fading.py --corpus C:\\devt\\Kondukta\\Data-P\\Alisia_APLde\\archive

Exit status is 0 iff every invariant holds on every file scanned.
"""

import argparse
import email
import email.policy
import os
import re
import sys
from pathlib import Path

# -------------------------------------------------------------------------
# Alisia palette. MUST be kept in sync with Config/alisia_styles.json5.
# If you change that file, mirror the backgrounds here.
# -------------------------------------------------------------------------
PALETTE = [
    # (level, hex, rgb-tuple, nickname)
    (0, 'dbe6f5', (219, 230, 245), 'level-0 / fresh'),
    (1, 'f2f6fb', (242, 246, 251), 'level-1'),
    (2, 'f7f9fc', (247, 249, 252), 'level-2'),
    (3, 'fbfdff', (251, 253, 255), 'level-3'),
]
# Extended palette for extra safety (some shades live in the admin tables).
ALL_ALISIA_BG_HEX = [p[1] for p in PALETTE] + ['e9f0fa', 'e0ebf6']

def rgb_or_hex_pat(hexes):
    parts = []
    for h in hexes:
        r, g, b = int(h[:2], 16), int(h[2:4], 16), int(h[4:], 16)
        parts.append(rf'(?:#{h}|rgb\(\s*{r}\s*,\s*{g}\s*,\s*{b}\s*\))')
    return '|'.join(parts)

BG_ALT = rgb_or_hex_pat(ALL_ALISIA_BG_HEX)

# -------------------------------------------------------------------------
# Outlook-mangled Alisia table signatures (what the fix must eliminate).
# -------------------------------------------------------------------------
OUTLOOK_MANGLED_RE = re.compile(
    r'<table\b(?![^>]*alisia_)(?=[^>]*border="0")[^>]*>'
    r'[\s\S]{0,300}?'
    r'<td\b(?=[^>]*background:[^;"]*(?:' + BG_ALT + r'))'
    r'(?=[^>]*border-style:\s*solid\s+none)'  # header or footer
    r'[^>]*>',
    re.IGNORECASE,
)

# -------------------------------------------------------------------------
# Canonical Alisia elements in their fully re-styled form.
# -------------------------------------------------------------------------
CANON_HDR_RE = re.compile(
    r'<(?:table|div)\b[^>]*alisia_header[^>]*>[\s\S]{0,300}?'
    r'<td\b[^>]*background:\s*#([0-9a-fA-F]{6})[^>]*>',
    re.IGNORECASE,
)
CANON_FTR_RE = re.compile(
    r'<(?:table|div)\b[^>]*alisia_footer[^>]*>[\s\S]{0,300}?'
    r'<td\b[^>]*background:\s*#([0-9a-fA-F]{6})[^>]*>',
    re.IGNORECASE,
)

HEX_TO_LEVEL = {p[1].lower(): p[0] for p in PALETTE}

# -------------------------------------------------------------------------
# Outlook / mobile forward markers. These represent a level of quoting that
# does NOT manifest as a <blockquote> but nonetheless should bump the depth
# used for header/footer fading. Must be kept in sync with the APL helper
# Alisia.DepthAtOffset.
# -------------------------------------------------------------------------
FWD_OUTLOOK_FORMAL_RE = re.compile(
    r'<div\b[^>]*border-style:\s*solid\s+none\s+none[^>]*>'
    r'[\s\S]{0,1500}?(?:Von|From):'
    r'[\s\S]{0,500}?(?:Betreff|Subject):',
    re.IGNORECASE,
)
FWD_MOBILE_RE = re.compile(
    r'-{4,}\s*(?:Urspr(?:u|ü)ngliche Nachricht|Original Message|Forwarded Message)\s*-{4,}',
    re.IGNORECASE,
)


def blockquote_depth_at(html: str, pos: int) -> int:
    """Classic blockquote nesting depth. Kept for backwards compat / debugging."""
    before = html[:pos]
    opens = len(re.findall(r'<blockquote', before, re.I))
    closes = len(re.findall(r'</blockquote', before, re.I))
    return opens - closes


def effective_depth_at(html: str, pos: int) -> int:
    """Full quoting depth seen by Alisia Phase 2. Mirrors APL DepthAtOffset:
    open blockquotes + formal Outlook forward divs + mobile forward markers."""
    before = html[:pos]
    opens = len(re.findall(r'<blockquote', before, re.I))
    closes = len(re.findall(r'</blockquote', before, re.I))
    bq = opens - closes
    fo = len(FWD_OUTLOOK_FORMAL_RE.findall(before))
    fm = len(FWD_MOBILE_RE.findall(before))
    return bq + fo + fm


def iter_html_parts(eml_path: Path):
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            try:
                yield part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or 'utf-8'
                    yield payload.decode(charset, errors='replace')


# -------------------------------------------------------------------------
# Invariant checks.
# -------------------------------------------------------------------------
def check_I1(html: str):
    """I1: no Outlook-mangled Alisia tables must survive."""
    hits = list(OUTLOOK_MANGLED_RE.finditer(html))
    return [f'leftover Outlook-mangled Alisia table at offset {m.start()}' for m in hits]


def _is_fresh(html: str, pos: int, label: str) -> bool:
    """True if this canonical element is the fresh MakeHeaderFooter insert, i.e.
    it is immediately preceded by a <!--alisia_header--> / <!--alisia_footer-->
    sentinel comment. Those inserts always use GetStyles[0] (L0) directly and
    are added AFTER Phase 2, so they're outside Phase 2's depth-based formula."""
    sentinel = f'<!--alisia_{label}-->'
    start = max(0, pos - len(sentinel) - 10)
    return sentinel in html[start:pos]


def check_I2(html: str):
    """I2: canonical header/footer <td> bg colour matches Alisia's fading model.

    Two code paths produce these elements:
      (a) MakeHeaderFooter — fresh ht/hb inserted at top/bottom, always L0
          (directly from GetStyles[0]), identified by the <!--alisia_*-->
          sentinel comment immediately before the element.
      (b) Phase 2 re-styling of quoted old alisia_* elements. Outbound Phase 2
          applies `depth←1+effective_depth`, indexed as `(1+4⌊depth)⊃st`, so
          the td bg level is `min(1+effective_depth, 3)` saturating at L3.

    effective_depth = open <blockquote>s + formal Outlook forward <div>s +
    mobile forward markers — mirrors Alisia.DepthAtOffset in APL.
    """
    msgs = []
    for regex, label in ((CANON_HDR_RE, 'header'), (CANON_FTR_RE, 'footer')):
        for m in regex.finditer(html):
            bg = m.group(1).lower()
            level = HEX_TO_LEVEL.get(bg)
            if level is None:
                msgs.append(f'{label} at {m.start()}: bg #{bg} is not in Alisia palette')
                continue
            if _is_fresh(html, m.start(), label):
                if level != 0:
                    msgs.append(
                        f'{label} at {m.start()}: bg level={level} but is fresh '
                        f'MakeHeaderFooter insert (expected L0)')
                continue
            # Phase 2 restyled. Allowed level = min(1+effective_depth, 3);
            # at effective_depth=0 (rare: un-quoted alisia_header in inbound), APL
            # still produces L1 via the +1 offset.
            depth = effective_depth_at(html, m.start())
            allowed = {min(1 + depth, 3)} if depth >= 1 else {1}
            if level not in allowed:
                allowed_str = ','.join(map(str, sorted(allowed)))
                msgs.append(
                    f'{label} at {m.start()}: bg level={level} but effective depth={depth} '
                    f'(expected level in {{{allowed_str}}})')
    return msgs


def check_I3(html: str, eml_path: Path):
    """I3: outbound archive files must have a top-level header AND footer.

    'Top-level' here means 'outside any blockquote nesting' — forward markers
    don't count for this check because they're point-in-time markers that don't
    enclose subsequent content, whereas the fresh MakeHeaderFooter footer sits
    AFTER the body's quote chain and would otherwise inherit the body's forward
    marker count despite not being nested in any quote."""
    has_hdr_comment = '<!--alisia_header-->' in html
    has_ftr_comment = '<!--alisia_footer-->' in html
    if not (has_hdr_comment or has_ftr_comment):
        return []  # not an outbound-processed file; skip
    msgs = []
    def first_match_depth(regex):
        for m in regex.finditer(html):
            if blockquote_depth_at(html, m.start()) == 0:
                return m.start()
        return None
    if first_match_depth(CANON_HDR_RE) is None:
        msgs.append('no top-level (depth-0) alisia_header found')
    if first_match_depth(CANON_FTR_RE) is None:
        msgs.append('no top-level (depth-0) alisia_footer found')
    return msgs


def check_I4(html: str):
    """I4: outbound HTML must have exactly one canonical alisia_footer, at
    blockquote depth 0 (the fresh MakeHeaderFooter insert). Phase 1.5
    DedupEmbeddedFooters is responsible for stripping any footers that came
    in through the quote chain.

    Why this matters:
      - Visual noise: 8+ near-identical footers in one reply is distracting.
      - Gmail deliverability: repeated near-duplicate blocks with the same
        unsubscribe/privacy link are a known spam signal.

    A pass here proves the dedup actually fired on the chain."""
    footers = list(CANON_FTR_RE.finditer(html))
    n = len(footers)
    if n == 0:
        return ['no canonical alisia_footer present (fresh insert missing?)']
    if n > 1:
        offsets = ', '.join(str(m.start()) for m in footers)
        return [f'{n} alisia_footer blocks found; expected exactly 1 after dedup (offsets: {offsets})']
    # Exactly one — must be at blockquote depth 0 (the fresh one).
    only = footers[0]
    bq_depth = blockquote_depth_at(html, only.start())
    if bq_depth != 0:
        return [f'only alisia_footer is at blockquote depth {bq_depth}; '
                f'fresh footer should be at depth 0 (offset {only.start()})']
    return []


def is_outbound(html: str) -> bool:
    """Alisia-produced outbound mails carry <!--alisia_header--> and
    <!--alisia_footer--> sentinel comments (inserted around ht / hb in the
    add_top_html / add_bot_html templates). Raw inbound messages do not."""
    return '<!--alisia_header-->' in html or '<!--alisia_footer-->' in html


def check_file(eml_path: Path, include_inbound: bool = False):
    """Run all invariants against each HTML part of the given .eml. Returns
    a list of (severity, tag, message) tuples. Empty list == pass."""
    findings = []
    parts = list(iter_html_parts(eml_path))
    if not parts:
        return findings  # no HTML part — skip silently
    for i, html in enumerate(parts):
        tag = f'{eml_path.name}[html#{i}]'
        outbound = is_outbound(html)
        if not outbound and not include_inbound:
            continue  # inbound / unprocessed mail — skip strict invariants
        for msg in check_I1(html):
            findings.append(('I1', tag, msg))
        for msg in check_I2(html):
            findings.append(('I2', tag, msg))
        if outbound:
            for msg in check_I3(html, eml_path):
                findings.append(('I3', tag, msg))
            for msg in check_I4(html):
                findings.append(('I4', tag, msg))
    return findings


def iter_targets(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            yield from sorted(p.rglob('*.eml'))
        elif p.is_file() and p.suffix.lower() == '.eml':
            yield p
        else:
            print(f'  [skip] not an .eml or directory: {p}', file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description='Verify Alisia fading invariants on archived .eml files.')
    ap.add_argument('paths', nargs='+', help='.eml files or directories to scan')
    ap.add_argument('--quiet', action='store_true', help='only print failures')
    ap.add_argument('--include-inbound', action='store_true',
                    help='also scan inbound mails (no <!--alisia_*--> sentinel); normally only '
                         'outbound archive files are checked because inbound mails legitimately '
                         'contain Outlook-mangled tables that Alisia has not yet processed.')
    args = ap.parse_args()

    total = pass_ = 0
    all_findings = []
    for eml in iter_targets(args.paths):
        total += 1
        findings = check_file(eml, include_inbound=args.include_inbound)
        if not findings:
            pass_ += 1
            if not args.quiet:
                print(f'[ok] {eml}')
        else:
            for sev, tag, msg in findings:
                print(f'[FAIL:{sev}] {tag}: {msg}')
            all_findings.extend(findings)

    print(f'\nScanned {total} .eml file(s), {pass_} passed, {total - pass_} failed, '
          f'{len(all_findings)} finding(s) total.')
    return 0 if not all_findings else 1


if __name__ == '__main__':
    sys.exit(main())
