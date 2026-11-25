RADAR - Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.

**New in 1.0.13** (look anything up, and a machine's place is not the person's)

*Search*

- **A Search page.** One field that finds accounts, devices, IP addresses, networks, countries, applications,
  sign-ins and alerts in what RADAR has stored. Before anything is typed it lists what was opened last; filters
  narrow the hits to one kind. Nothing is asked of Microsoft for it, and the page says how old its data is.
- **A page for each account** - and for each device, address, network, country and application: who or what it
  is, what is open right now (its incident and alerts), its habits, what stands out, and one timeline of
  sign-ins, changes and alerts. A sign-in unfolds where it stands; names, addresses and devices in a row lead to
  their own pages, and a back button leads the way back.
- **Movement.** For an account, where its devices were: a lane for each device, a bar for each stay at one place,
  the last 24 hours in view and the days before by dragging the chart, the wheel or the arrow keys. A device's
  name opens its page.
- Sign-ins that were stopped at the MFA prompt and never completed are shown as what they are.

*Detection*

- **A machine's place is not the person's place.** RADAR knew this for the virtual desktops listed in the
  settings. Now it also recognises, from the records alone, a machine that lives in a cloud data centre, a machine
  reached by remote desktop, and the machine that asked for a device code. The rules that place a person pass
  their sign-ins over, no account "knows" a country because of them, and they do not make a cloud network an
  account's usual one.
- **A device-code sign-in is judged once, as what it is.** Its record names the device that approved the code
  but carries the address of the machine that asked for it. The tokens that machine was given are no longer a
  "stolen session" on top of it. And when the approving device was in use somewhere else at that moment, its
  good name counts for nothing: a phished code comes out High from the device-code rule - also for an account
  without any role. Where that rule does not judge (an account on its allowed list, or the rule switched off)
  the other rules look at the sign-in as before.
- **Session-theft alerts are per day.** One long-lived session no longer gathers weeks of evidence in one alert
  that turns High long after it "occurred".
- **An alert's details belong to its score.** A later, lower finding no longer overwrote the details of the
  higher one the alert shows.

*Reliability*

- **Sign-ins a page limit left unread are read by the next scan** instead of being skipped for good.
- **A dismissal is never undone** by a scan that stores a finding for the same alert at that moment.
- **A check that keeps failing no longer holds every scan back.** After three failures in a row the scan
  completes without it, and a reminder names the check until it works again.
- **The live map only reads.** It can no longer replace the settings with defaults when the settings file is
  invalid for a moment (being edited), it shows the true age of its data, and its browser profile is thrown away
  before a map window opens and after it closed. A settings file that lost its plugin section no longer switches
  scanning off.
- "No connection, trying again" is shown when the network is gone during a scan, instead of "last scan failed".
- Unfolding a sign-in never waits for a running scan; a page that cannot be drawn says so instead of loading
  forever; a refresh that fails always ends its "busy" state.

*Screens*

- **Is the disk encrypted?** RADAR asks Windows whether the drive its data is on is protected (BitLocker or device
  encryption), shows the answer under *Settings > Account and connection*, and reminds you when it is not. It
  only tells; the reminder can be switched off.
- Text that is cut short with "..." shows all of it when the pointer rests on it, everywhere.
- Lists scroll with the wheel wherever the pointer is; pages and rows appear and answer to the pointer with short
  animations (off with *Settings > Appearance > Animations*). Country codes are shown with the country's name.

*Under the hood*

- After each scan the log says how many requests it made to Microsoft Graph, how many were throttled and how long
  it waited.

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
