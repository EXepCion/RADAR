RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.

**New in 1.0.9** (closing gaps: what was not watched, and what was not read)

*Detection*

- Changes that switch other protections off are watched: named locations (more when one is marked trusted), the
  sign-in methods policy, authentication strengths and security defaults, and members or owners added to groups
  that can hold admin roles.
- Rare changes of the tenant itself are recorded, one reminder per person and week: a domain added or verified,
  a private network connector registered, a new reply address or public client flows on an existing application.
- New rule *Sign-in from unfamiliar surroundings*: a sign-in by hand from a network, address, device and kind of
  client the account never used, in a country it is known in.
- Admin role activations (PIM) are judged by where the account signed in from at that moment: only from unfamiliar
  surroundings they are an alert, otherwise a quiet record that counts as a step of an attack chain.
- MFA requests that were denied or not answered are judged by where they came from instead of always being High:
  from the person's own computer and network they are logged, from a network and device the account never used
  they are High.
- *Correct password, MFA not completed* also takes the log entry's own steps as proof of the password, whatever
  the result is called (for example "a device is required").
- An application that is not Microsoft's own and signs in for several accounts from one cloud network is taken
  for what it is - its own server - and no longer raises *Background activity from a new country*.
- Networks that only guess passwords are remembered, not just single addresses: what gets past a password from
  such a network is rated higher.

*Handling*

- *Don't remind again* in an alert switches the reminders of that kind off for the account or application it is
  about, for 30 days, 90 days or a year. What matches is still judged and kept in the alert history, anything
  worse still comes, and *Settings > Reminders* lists what is switched off.
- *Ongoing attacks*: the figure on the navigation and the figures on the page are one count - what is going on
  right now. The page opens at once with the last result and then brings it up to date.

*Keeping up*

- After the PC was off, the background sign-ins of that time are read in the scans that follow, up to 7 days
  back. Before, everything older than 6 hours was skipped.
- A lost connection to Microsoft is said as such and waited out, not reported as a failed scan.
- The sign-in history gives back the disk space of what it deleted, once a week.
- Saving the settings no longer fails when Windows holds the file for a moment.
- A build that is not the published release says so beside its version number.

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
