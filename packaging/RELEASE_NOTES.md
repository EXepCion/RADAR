RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.

**New in 1.0.12** (nothing that was read is lost, and an administrator at work is not an attack)

*Reliability*

- **A scan that is stopped loses nothing.** Until now a scan stored the sign-ins it read and moved its bookmark
  before the rules had run. When RADAR was closed, the PC shut down or the scan failed in between - also in the
  middle of reading -, those sign-ins were never judged. Now a bookmark moves only when what was read up to it is
  in the alert store: stored sign-ins stay marked as unjudged until then and are not cleared meanwhile, and the
  next scan judges them. The same holds for the hours RADAR was not running, the applications' own sign-ins and
  the audit watch.
- It never gives up on them: a rule that fails keeps the scan open, and after two scans in a row that did not
  finish - or a rule that failed - a reminder says so until it works again.

*Detection*

- **An administrator's own work is no suspicion against the administrator.** An account counts as under
  suspicion - which ties it to the accounts it acts on - only when somebody else may be in it: its password is
  known, or a sign-in of at least Medium that may not be the user. A role it assigned or a policy it changed is no
  such evidence. And an account that was acted on is part of the story from that moment on, not with what it did
  the week before.
- **People an administrator did something for are not one incident.** A role change for five people names them;
  it joins an earlier alert about one of them only when that is still open, at least Medium, or a chain.
- **Role alerts say what was given.** The role and what it is on (`Owner on <subscription> (Azure subscription)`),
  each assignment once although the log lists it several times, and that somebody gave a role to their own
  account. A role on an Azure resource that can hand out access (Owner, User Access Administrator) weighs more.
- **A company device being set up is no way to stay in.** A sign-in to the device registration service waits up
  to 30 minutes for the audit log and the directory: a device that is managed and came through the organisation's
  own programme (registered for Windows Autopilot, Apple's automated enrolment) is logged with that programme
  named and is no step of a chain. Without that proof the registration is judged as before.

*Under the hood*

- The tests can no longer reach the data of a RADAR installed on the same PC, whatever a test undoes.

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
