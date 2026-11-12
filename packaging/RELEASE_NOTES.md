RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.

**New in 1.0.6** (connecting the dots across accounts)

- Known attacker addresses: what any check proves about an address (a stolen session, a phishing proxy, a
  password that worked, a reported MFA prompt ...) is remembered for 7 days and counts in every check, for every
  account. Other accounts tried from such an address raise an alert of their own.
- Wave of unusual sign-ins: several accounts with an odd sign-in at the same time from one new network or one
  never-seen client - each alone too little to report.
- Attack chains now also run across accounts (same attacker address, or a suspected account acting on another),
  look back 30 days, follow slow attacks between strong steps, and can be completed in hindsight by a finding that
  was only logged. A reported MFA prompt is a chain step.
- New window *Incidents*: alerts that belong together as one incident with a timeline; its open reminders can be
  dismissed together.
- An alert's details say which incident it belongs to and lead there. Open windows now follow every change: the
  details of an alert, the incidents and the alert history update themselves after each scan.
- Windows open at once also while a scan is running (before, a details window could take many seconds).
- Alert details use their space better: the story, the details and the risk assessment stand side by side when
  there is room. The right-click menu is drawn in the app's own look.

**New in 1.0.5**

- The address behind a reported MFA prompt is remembered for 7 days: every sign-in from it, to any account, is rated
  higher, and other accounts tried from it - or anybody signing in from it - raise an alert of their own. A
  report that turns out to be the user's own prompt marks nothing.

**New in 1.0.4**

- New check: a user reports an MFA prompt as not theirs (Microsoft Authenticator, or the reporting code on the
  phone). RADAR raises an alert and judges it by the sign-in that caused the prompt: the account's own device and
  network ends low, an unfamiliar one high. A password attack on the same account is rated higher. The report
  also appears in the live map's feed.
- This needs the Entra setting *Report suspicious activity*. The connection check shows whether it is on and how
  to switch it on; while it is off the check is inactive and the menu says so.

**New in 1.0.3** (hardening after a review of the code)

- One installation, one tenant: after a sign-in to a different tenant RADAR reads nothing until you sign in to the
  original one again or start fresh (the stored data is archived, not deleted).
- The sign-in token is only ever sent to `graph.microsoft.com`.
- A file in the plugins folder is not run before you allowed it in the *Plugins* menu.
- Dismissed and muted alerts are removed after the retention time (90 days), as documented.
- The README lists every service RADAR talks to; licence texts of the bundled components ship with the program;
  pystray ships as plain, replaceable files.
- Guest invitations: more consumer mail providers from around the world are recognised as private mailboxes.
- The release build runs with read-only rights, uses pinned actions and is attested by GitHub.

**Files**

- `RADAR-<version>-setup.exe` - installer for the current user (no administrator rights needed).
- `RADAR-<version>-portable.zip` - the same program folder without an installer.
- `SHA256SUMS.txt` - checksums of the two files above. Compare with `Get-FileHash <file> -Algorithm SHA256`.

The files are **not code-signed**: Windows SmartScreen warns about an unknown publisher ("More info" > "Run
anyway"). They were built by GitHub Actions from the source of this tag; the build log is public, and GitHub
attests which build made them: `gh attestation verify <file> --repo EXepCion/RADAR`. You can also build RADAR
yourself - see the README.

Feedback is welcome: tell us what worked and what did not in an
[issue](https://github.com/EXepCion/RADAR/issues) (take out names and tenant details first).

RADAR is shared as it is: no warranty, no support, use at your own risk. Not
affiliated with or endorsed by Microsoft.
