RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.

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
