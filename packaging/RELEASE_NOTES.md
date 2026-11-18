RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.

**New in 1.0.10** (who else can administer the tenant, and what gets deleted)

*Detection*

- New rule *Outside organisations given admin access*: a partner given delegated administration, or an outside
  organisation made a service provider that can be given admin roles here - more when a highly privileged role is
  among them. Microsoft Support during a support case stays a record with the case.
- New rule *Many accounts, groups or applications deleted at once*: one actor deleting many of them in a day
  (accounts from 5, groups from 10, applications from 5; the counts are a setting). More when they were deleted for
  good; an application and its enterprise application count once; known automation is logged only.
- A change of what every user may do without an admin (the authorization policy: inviting guests, registering
  applications) is recorded as a rare change of the tenant. Switching on user consent is still said once, by the
  consent watch.

*Under the hood*

- Tests: a window test no longer gets skipped when Windows fails to start a window on the first try, and one
  layout test waits for the window to take its size.
- Unused code removed.

How each rule works is in [docs/DETECTION.md](https://github.com/EXepCion/RADAR/blob/main/docs/DETECTION.md).

Earlier versions: [CHANGELOG.md](https://github.com/EXepCion/RADAR/blob/main/CHANGELOG.md).

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
