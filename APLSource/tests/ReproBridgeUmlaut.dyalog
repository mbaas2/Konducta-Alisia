:Namespace ReproBridgeUmlaut
⍝ Reproduces + diagnoses the Dyalog↔.NET bridge bug that corrupted Alisia's mails.
⍝
⍝ Symptom (seen on the Linux/.NET-Core server, NOT on Windows/.NET-Framework):
⍝ handing an APL character array to a .NET String argument mangles chars > 127.
⍝ An 8-bit array (⎕DR 80) has its raw Latin-1 bytes decoded as UTF-8, so ü/ä/ö/ß
⍝ each become U+FFFD (bytes EF BF BD). A genuine 16-bit array (⎕DR 160) is fine.
⍝
⍝ IMPORTANT: run this on the SAME platform/interpreter where the mail bug appeared
⍝ (the Linux server). On Windows it typically does NOT reproduce.
⍝
⍝ No MimeKit needed — the fault is at the generic APL-char → .NET-String boundary,
⍝ shown with System.Text.Encoding. GetBytes reveals exactly what String .NET got:
⍝   correct 'für' = 102 195 188 114        (f + ü=C3 BC + r)
⍝   bug     'f�r' = 102 239 191 189 114    (f + U+FFFD=EF BF BD + r)
⍝
⍝     ]LINK.Import # /path/to/ReproBridgeUmlaut.dyalog
⍝     ReproBridgeUmlaut.Run

    ∇ bug←Run;str;⎕USING;bytes;show
      ⎕USING←'System' 'System.Text'
      str←'für'   ⍝ f ü r ; all chars ≤255, so stored as ⎕DR 80

      ⍝ report ⎕DR of an array and the UTF-8 bytes .NET receives for it (traps per line)
      show←{0::⎕←⍺,': ERROR ',⊃⎕DMX.DM
          b←Encoding.UTF8.GetBytes⊂⍵
          ⎕←⍺,': ⎕DR=',(⍕⎕DR ⍵),'  GetBytes=',(⍕b),(1+∨/239 191 189⍷b)⊃' (ok)' ' *** U+FFFD (bug) ***'}

      ⎕←'--- the bug: 8-bit source ---'
      '  str           'show str

      ⎕←'--- widening strategies (which one really yields ⎕DR 160 + ok here?) ---'
      '  append+reshape'show(≢str)⍴str,⎕UCS 256   ⍝ toWide''s method — may squeeze back to 80!
      '  append(keep)  'show str,⎕UCS 256          ⍝ guaranteed 160 (sentinel U+0100 kept)
      '  dyadic 160 ⎕DR'show 160 ⎕DR str            ⍝ explicit conversion to 16-bit char

      bytes←Encoding.UTF8.GetBytes⊂str
      bug←∨/239 191 189⍷bytes   ⍝ 1 = bridge produced U+FFFD for the 8-bit string
      ⎕←(1+bug)⊃'--- bug NOT reproduced on this platform ---' '*** BUG reproduced (8-bit → U+FFFD) ***'
    ∇

:EndNamespace
