RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.

**New in 1.0.11** (what happens seconds apart, and what belongs together)

*Detection*

- **Familiar needs age, and something to vouch for it.** A device, network, client or Authenticator counts as the
  account's own only once it has been in use for 12 hours - a device registered a moment ago is not a *known
  device*, and the network it was registered from is not a *usual* one. A device must also have been seen where
  the account otherwise is (an office, a network the account knew before, one an older device of the account
  uses); one that is only ever used from a datacenter stays a stranger, its token lowers nothing. After 14 days it
  counts all the same (settings `scoring.familiar_after_hours`, `scoring.unvouched_after_days`).
- **Corporate device enrolments are recognised** (new rule, record only). Apple's automated enrolment signs in
  from the enrolment service's address in a cloud, Windows Autopilot from wherever the computer is unpacked. Such a
  sign-in is held for up to 30 minutes; when the account then registers a device that the directory knows as
  managed and as the organisation's own (Apple: an automated-enrolment type; Windows: registered for Autopilot),
  it becomes one record and is not judged - and nothing it brought is learned as the user's habit. Without that
  proof it is judged like any other sign-in.
- **Device registrations say which device.** The alert names the registered device and links to it in Entra,
  taken from the audit log - also when the audit entry arrives later. A Windows Hello key set up on a device that
  exists is no longer called a device registration. A registration made from a known attacker address says so.
  Removing the device again answers the alert about its registration.
- **Attack chains.** A sign-in rated High followed by a way to stay (a device, an MFA method, a consent) is a
  chain; so is a suspicious sign-in followed by a grab for power when both are at least Medium. Applications have
  chains too: a secret, owner or consent planted on one, then the application signing in from a country it never
  used. Of several earlier findings that could come before a step, the strongest is taken, not the oldest.
- **Who a finding is about.** Changes in the directory name the accounts something was done to (who got the role,
  whose MFA was reset) and the applications that acted or were changed; "new IP shared by several accounts" names
  its accounts. A change made from a known attacker address says so and weighs more.
- **Travel.** Background activity abroad on the person's own device is only logged when that device is nowhere
  else at the same time; the same device in two countries at once stays an alert and says where else it was. A
  device logged as travelled is watched for 48 hours and raised when it turns up at home too soon.
- Repeated MFA prompts mark the address they came from as an attacker's (when it is foreign to the account).
  Revoked sessions, a password reset and a disabled account also answer unfamiliar sign-ins and new shared
  addresses.

*Fixes*

- Entra lists some sign-ins under one id twice: the sign-in by hand and a background record of the same request.
  The second replaced the first, which was then cleared with the background records after three hours - the
  sign-in was gone from the history and its address was never remembered. Both are kept now.
- A change whose reason the log leaves blank is shown by its name, not as "(blank)".
- Moving the pointer from one link straight onto the next underlines the new one.

*Screens*

- The alerts of an incident are listed by what still needs a look: open first (what sums the incident up, then
  its alerts in the order they happened), then snoozed, dismissed and logged only. On an incident's own page the
  first row is selected.
- A device is shown once, by its name; its link looks it up by its id.

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
