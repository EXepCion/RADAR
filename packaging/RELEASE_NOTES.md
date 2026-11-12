RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.

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
