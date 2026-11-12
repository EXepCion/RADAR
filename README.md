# RADAR

**Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID.**

RADAR is a Windows tray app for the people who look after a Microsoft Entra ID (Azure AD) tenant. It reads the
tenant's sign-in and audit logs with your own account, looks for attack patterns, and tells you about them in a
reminder window you can dismiss, snooze or open - like a calendar reminder, but for "somebody got past the password
of this account from a hosting network in another country".

It runs on your PC only: it reads your tenant through Microsoft Graph, changes nothing in it and keeps what it
reads on your PC. There is no telemetry. The two other requests it makes by itself - the registered name of a
network it does not know, and the check for a new version - carry no account or tenant data and can be switched
off; see [What RADAR sends, and to whom](#what-radar-sends-and-to-whom).

> **Use at your own risk.** RADAR is shared as it is. There is no warranty, no
> support and no promise that it finds everything or that what it reports is right. RADAR is not affiliated with
> or endorsed by Microsoft.

**Your feedback is welcome.** If RADAR raised a false alarm, missed something, behaved oddly in your tenant, or
you have an idea for a check, please [open an issue](https://github.com/EXepCion/RADAR/issues) - see
[Feedback](#feedback).

## What it does

- **Watches sign-ins** (every 10 minutes): password spray, brute force, password guessing from rotating addresses,
  MFA fatigue, MFA prompts a user reported as not theirs, a correct password stopped by MFA, session token theft and AiTM phishing, impossible travel, sign-ins
  from new countries (by hand and in the background), legacy protocols, device-code sign-ins, risky sign-ins flagged
  by Entra, accounts excluded from MFA, break-glass and disabled accounts, apps signing in with their own secrets.
- **Watches directory changes** (every 15 minutes): admin role assignments, app secrets and owners, consent grants,
  Conditional Access and federation changes, cross-tenant trust, members added to groups that are excluded from
  Conditional Access, BitLocker and local-admin password reads.
- **Scores every finding** from 0 to 100 and explains the score: the network (hosting, VPN, the person's usual
  one), the device (managed, known, never seen), the kind of MFA, the account (admin, excluded from MFA, disabled).
  Low scores are only logged; from *Low* on a reminder pops up.
- **Connects findings**: steps that together look like an account takeover become one "possible attack chain".
  What was done about an account - sessions revoked, password reset, account disabled - is linked to the alerts it
  answers and lowers their risk; if successful sign-ins continue afterwards, the risk goes up instead.
- **Shows the state on demand**: *Ongoing attacks* (who is being attacked right now, from where), an *MFA exposure
  report* (every account that can sign in without MFA), an *Alert history* (also dismissed alerts, with a way to
  bring one back) and a *Live map* of who is signed in from where, with attacks drawn as arrows.

The full list of rules, their thresholds and how the score is built is in [docs/DETECTION.md](docs/DETECTION.md).

## Requirements

- Windows 10 or 11.
- An account in the tenant with a role that may read the logs: **Global Reader**, Security Reader or Reports
  Reader. RADAR only reads.
- A tenant licence that includes the sign-in log API (Microsoft Entra ID P1 or P2).
- Microsoft Edge for the live map (it opens in an Edge app window). Everything else works without it.

## Install

**From a release:** download `RADAR-<version>-setup.exe` from the
[Releases page](https://github.com/EXepCion/RADAR/releases) and run it. It installs for the current user only
(`%LOCALAPPDATA%\Programs\RADAR`), needs no administrator rights, adds a Start menu entry and - if you leave the
box ticked - starts RADAR when you sign in to Windows. Remove it like any other program (Windows Settings > Apps);
your settings and stored data in `%LOCALAPPDATA%\RADAR` are kept until you delete that folder.
`RADAR-<version>-portable.zip` is the same program folder without an installer.

The installer and the program are **not code-signed**, so Windows SmartScreen will warn about an unknown
publisher ("More info" > "Run anyway"). Each release lists the SHA-256 checksums of its files
(`SHA256SUMS.txt`), and the files are built by GitHub Actions from the public source of that release - the build
log is public. GitHub also attests which build made a file: `gh attestation verify <file> --repo EXepCion/RADAR`.
If you would rather not trust a downloaded program, build or run it yourself:

**Build the program yourself** (Python 3.10 or newer with tkinter; for the installer also
[Inno Setup 6](https://jrsoftware.org/isinfo.php)):

```powershell
git clone https://github.com/EXepCion/RADAR.git
cd RADAR
py -m venv .venv
.\.venv\Scripts\pip install -e .[dev] pyinstaller
powershell -ExecutionPolicy Bypass -File .\packaging\build.ps1     # -> dist\RADAR, the zip, the installer, checksums
```

**Or run it from source without building anything:**

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

This creates a Python environment under `%LOCALAPPDATA%\Programs\RADAR`, installs RADAR into it, registers it to
start when you log on and starts it. Remove that kind of installation with
`%LOCALAPPDATA%\Programs\RADAR\uninstall.ps1` (add `-RemoveData` to delete your data too).

## Signing in

RADAR signs in silently with the account you are signed in to Windows with (through the Windows account broker),
or with another account you choose under *Settings > Account*.

To ask Microsoft Graph for data a program also needs an application identity. RADAR has none of its own - it is
not a service, and nobody runs a shared registration for it. So **on its first start RADAR opens a set-up window**
(later: *Settings > Account > Set-up and connection check*) where you choose how it signs in. It then signs in
and tries, step by step, everything it needs to read - the sign-in log, the audit log, the accounts, the
Conditional Access policies - and tells you in plain words what is missing (a role, a licence, admin consent) and
what to do about it. *Check again* repeats the check, for example after a role was assigned. When everything
works, the window says so and RADAR keeps running in the notification area. Until then nothing is read, and
set-up problems are shown in that window, not as alerts. The two ways to sign in:

1. **An app registration of your organisation (recommended).** In the Entra admin center, under *App
   registrations*, register an application for your organisation only. Under *Authentication* add the platform
   "Mobile and desktop applications" with the redirect URI
   `ms-appx-web://Microsoft.AAD.BrokerPlugin/<application id>`. Under *API permissions* add the delegated
   Microsoft Graph permissions `AuditLog.Read.All`, `Directory.Read.All` and `Policy.Read.All` and grant admin
   consent. Enter the application (client) ID and your directory (tenant) ID in RADAR. RADAR then shows up in your
   sign-in logs under the name you gave the registration, and you can allow or block it like any other application.
2. **Quick start: the Azure CLI identity.** RADAR uses the public client ID of Microsoft's Azure CLI, which may
   already read these logs in most tenants. This needs no set-up, but RADAR then appears in your sign-in logs as
   "Microsoft Azure CLI", it does not work where Azure CLI is blocked, and Microsoft may change what that identity
   can do at any time. Some data (for example PIM eligibilities and Entra's detailed risk detections) cannot be
   read this way. At your own risk.

The delegated permissions only let RADAR read what your own account is allowed to read; the account still needs
one of the roles named under Requirements.

If RADAR loses its access later (a role removed, the sign-in expired), that does come as a reminder - with a
button that opens the connection check.

## First steps

Everything is in the tray icon's menu (right-click the shield in the notification area).

1. **Settings > Offices...** - the public IP addresses your sites sign in from. Sign-ins from there count as "in
   the office": the rules trust them and the map shows the office. The window proposes addresses many people sign
   in from.
2. **Settings > Virtual desktops...** - Citrix, Azure Virtual Desktop and shared servers. A sign-in from one says
   where the machine is, not where the person is; travel rules and the map ignore it. The window proposes
   candidates.
3. **Settings > Detection** - switch whole functions or single rules on and off.
   One rule depends on a setting in Entra: *MFA prompt reported by the user* only works when *Report suspicious
   activity* is switched on there (Entra ID > Authentication methods > Settings). The connection check tells you,
   and the rule's menu entry says when it is inactive.
4. **Settings > Advanced > Edit settings file** - everything else (thresholds, allowed countries, break-glass
   accounts, accounts pinned to fixed addresses, retention times). Changes apply when the file is saved.

The icon is green when all is quiet, red with open reminders, yellow when sign-in is needed or the last scan
failed, blue while scanning, grey while paused.

## The windows

- **Reminders** - comes up when a new alert arrives, flashes until you touch it, plays a sound on the default
  playback device unless that device is muted. *Open item* shows the details: what happened, the risk assessment
  factor by factor, the evidence rows, the recommended action and links into the Entra admin center. *Dismiss* and
  *Snooze* hide a reminder; it returns by itself if it gets worse.
- **Alert history** - every alert RADAR still keeps (90 days), with filters and a search box. *Reactivate* brings a
  dismissed alert back.
- **Ongoing attacks** - password guessing, known passwords, stolen sessions and the attacking addresses, computed
  from the local history each time, independent of what you dismissed.
- **MFA exposure report** - all accounts that can sign in without MFA, with clean-up hints.
- **Live map** - offices and towns with the number of people signed in, password attacks as arrows, a feed of
  sign-ins, attacks and account events (password resets, MFA methods, reported MFA prompts, devices, accounts,
  admin roles). Click a
  place or a person for details. The map is a separate program that only runs while its window is open; its map
  files ship with RADAR, nothing is loaded from the internet.

## What RADAR stores on your PC

All of it is in `%LOCALAPPDATA%\RADAR`, in your own user profile:

| What | For how long |
|---|---|
| Sign-ins made by hand (who, when, from where, which device and app, result) | 30 days |
| Background sign-ins | 3 hours; after that only which device was active from which address, and when |
| Account list of the tenant (state, roles, MFA registration, licences) | refreshed about twice a day |
| Alerts with their evidence | dismissed or muted ones: 90 days after they were last seen; open ones until you deal with them |
| Account events for the live map | 7 days |
| Your settings, a log file, and the sign-in token (encrypted with Windows DPAPI for your account) | until you remove them |

This is personal data about the people in your tenant. Whether and how you may process it is for you and your
organisation to settle. Uninstalling with `-RemoveData` deletes it all.

Only the sign-in token is encrypted. The databases, the settings and the log file are plain files in your Windows
profile (`%LOCALAPPDATA%\RADAR`), protected by your Windows account like the rest of your profile; the log file
names the account RADAR signs in with and its tenant. Use RADAR on a PC whose disk is encrypted.

**One installation, one tenant.** The stored data belongs to the tenant of the first sign-in. If you later sign
in to another tenant, RADAR reads nothing and asks: sign in with an account of the original tenant, or *start
fresh* - the stored data is moved to `%LOCALAPPDATA%\RADAR\archive` (not deleted) and new baselines are built.

### What RADAR sends, and to whom

There is no telemetry. RADAR talks to:

| Whom | What | Switch off |
|---|---|---|
| Microsoft (sign-in service and Microsoft Graph) | the sign-in and the queries that read your tenant's logs and directory. The sign-in token is sent to `graph.microsoft.com` only. | - |
| RIPEstat (`stat.ripe.net`) | the number of a network (AS number) that sign-ins came from and RADAR does not know yet, to get the network's registered name. No address, no account, nothing else. | `lookup_asn_names: false` in the settings file |
| GitHub (`api.github.com`) | once a day: "what is the latest release of RADAR?" (see below) | *Settings > Check for new versions* |
| AbuseIPDB, ipinfo.io, Microsoft's admin portals | only when **you** click such a link in an alert: your browser opens the page, with the IP address or network number in the address. | do not click |

## New versions

Once a day RADAR asks GitHub for the latest release of RADAR (one request to `api.github.com`; nothing about you
or your tenant is in it). When a newer version exists, a notification says so - a click on it opens the release
page in your browser - and the tray menu shows "New version ... available" until you have updated. Switch the
check off under *Settings > Check for new versions*; *Settings > Advanced > Look for a new version now* checks at
once.

RADAR does not update itself. The release files are not code-signed, and a program that downloads and runs
unsigned programs on its own would be a weak spot in a security tool. To update, download the new installer and
run it; it replaces the program and keeps your settings and data.

## Writing your own check (plugin)

Put a `.py` file into `%LOCALAPPDATA%\RADAR\plugins` and choose *Settings > Advanced > Reload plugins*. The file
then appears in the *Plugins* menu as "(new) ...: allow it to load"; RADAR does not run a file from that folder
before you have said yes to it there. Once allowed, every `radar.plugin_api.Plugin` subclass in it is picked up:

```python
from radar.plugin_api import Finding, Plugin, Rule, Severity

class MyCheck(Plugin):
    id = "my_check"                 # key in the settings file
    name = "My check"               # text in the tray menu
    default_enabled = False
    default_interval_minutes = 30
    default_settings = {"threshold": 5}
    rules = [Rule("a", "Sub check A")]   # optional switches of their own

    def run(self, ctx):
        data = ctx.graph.get("/v1.0/...")          # signed-in Graph client (get_all follows paging)
        ctx.state.set("cursor", "...")              # state kept between runs
        return [Finding(key="my|stable-id", title="...", severity=Severity.MEDIUM, summary="...")]
```

`Finding.key` decides what is "the same alert": the same key updates the existing reminder instead of raising a
new one. A complete example is in `templates/example_plugin.py`. A plugin that fails to load or raises an error
is shown in the menu and does not stop the others. That is all the separation there is: a plugin is not sandboxed.
It runs inside RADAR with your rights and RADAR's sign-in, so only allow plugins you wrote or have read.
In the packaged program a plugin can use the Python standard library modules and the packages that ship with RADAR
(`requests`, `msal`, `Pillow`); for anything else run RADAR from source.

## Diagnostics

The log is `%LOCALAPPDATA%\RADAR\logs\radar.log` (the live map writes `mapview.log` next to it).
`RADAR.exe --demo` shows the reminder window with made-up alerts and touches nothing.

With a source installation there are a few more switches, which print to the console:

```powershell
$py = "$env:LOCALAPPDATA\Programs\RADAR\venv\Scripts\python.exe"
& $py -m radar --check-auth    # can RADAR get a token without asking?
& $py -m radar --scan-once     # run the enabled functions once in a temporary folder and print what they find
& $py -m radar --rescore       # re-assess open reminders after changing settings
```

## Development

```powershell
py -m venv .venv
.\.venv\Scripts\pip install -e .[dev]
.\.venv\Scripts\python -m pytest
```

The tests use made-up accounts, addresses and organisations.

## Feedback

RADAR gets better with reports from tenants that are not like the one it was built against. Please
[open an issue](https://github.com/EXepCion/RADAR/issues) when

- an alert was a false alarm, or something real was not reported,
- set-up or sign-in did not work in your tenant,
- a window or the map behaved oddly,
- you have an idea for a check or an improvement.

Say which version you use (tray menu) and what you saw. **Take out names, addresses and tenant IDs before you
post** - an issue is public; the log file and screenshots usually contain them. There is no promise of an answer
or a fix, but every report is read.

## Licence

RADAR is released under the [MIT licence](LICENSE). It includes or depends on software and data by others under
their own licences; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Microsoft, Microsoft Entra, Azure and Windows are trademarks of the Microsoft group of companies.
