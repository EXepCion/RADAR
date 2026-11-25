# What RADAR detects

The detection logic lives in two built-in plugins. Thresholds named here are defaults; most can be changed in the
settings file (RADAR window: Settings > Advanced > Settings file > Edit).

### Sign-in threat detection (`signin_threats`, enabled, every 10 min)
Pulls interactive **and** non-interactive user sign-ins (beta `auditLogs/signIns`), de-duplicates
them into a local history and runs these rules:

| Rule | Default logic | Ranking |
|---|---|---|
| Risky sign-ins | **successful** sign-ins Entra ID Protection rates ≥ medium / confirmed compromised, per user and day (blocked risky attempts count as attack evidence instead; `include_failed`). When the same sign-in is also the first from a new country, that is said and counted here (+10) and no second alert is raised | scored, never below Low |
| Password attack from rotating IPs | per account in 72 h: ≥ 8 failed passwords from ≥ 6 IPs on networks the user never used (residential-proxy botnets: ~1 attempt per IP). Escalates to High if an attempt gets past the password or a device-less sign-in succeeds from an unfamiliar network; one campaign that guesses at several accounts and got nowhere is **one alert** naming them all; a disabled account among them is a line in it (alone it is only logged); an account where something happened keeps an alert of its own | 40–50, escalates |
| Password spray | one IP, failed password for ≥ 5 accounts in 60 min (skipped if the IP is mostly successful traffic) | 80 (90 if an account then succeeded) |
| Brute force | ≥ 10 failed passwords for one account in 60 min; escalates if a success from the same IP follows | 55 → 85 |
| MFA fatigue | ≥ 3 MFA requests denied or not answered (500121) in 60 min, judged by **where they came from**: from the account's own computer and network it is the person not getting through (logged); from a network and device the account never used it is somebody who has the password (High). A request denied in the Authenticator +15; the sign-in completed from the same address afterwards -15. A reported fraud stays 90 | base 60, scored |
| MFA prompt reported by the user | The user reported an MFA prompt as not theirs (Authenticator: *No, it's not me* > report; phone: the reporting code). Entra writes the audit entry `Suspicious activity reported`; a prompt is only sent after the right password, so a true report means the password is known. The sign-in that caused the prompt is a separate row in the sign-in log (failed MFA step, same account, seconds before the report) that Entra delivers **up to 1-2 hours later**. Until it arrives: Medium. With it, the alert is judged by where that sign-in came from: the account's own managed device and usual network → Low ("probably their own sign-in", reported by mistake); an unfamiliar network or device → High. No such row after `wait_minutes` (120) → High. A password reset or disabling the account answers it. **Needs the tenant setting *Report suspicious activity*** (Entra ID > Authentication methods > Settings; "Microsoft managed" means off): while it is off the rule is inactive and the menu says so; when the setting cannot be read with the sign-in used (it needs `Policy.Read.All`) the rule stays active. The connection check shows the state. When the reported prompt did not come from the user's own surroundings, its address is remembered as an attacker's (see *Known attacker addresses* below). Settings: `mfa_report` (`activities`: the audit entry names, `match_seconds_before/after`, `wait_minutes`). | 50 → 25-100 |
| Wave of unusual sign-ins | Within `window_hours` (6), at least `min_accounts` (4) accounts each have a sign-in that got past the password from outside their own surroundings (no office; no device, network or address the account used before) - and all share where it came from: one network nobody in the tenant used before or a hosting/VPN network, or one client (user agent) nobody used before. Each alone stays below every rule; together they are a phishing wave or one attacker working through stolen passwords. A team abroad on their own known laptops is not counted. Settings: `signin_wave`. | 45 +10 new network, +15 hosting/VPN, +5 per further account, +15 completed sign-ins |
| Known attacker address reused | An address another finding proved to be an attacker's (see below) is used on other accounts, or somebody signs in from it afterwards. Sign-ins from a device the account already used are left out. | 45, +20 password right, +35 successful sign-in |
| Correct password, MFA not completed | password accepted, then MFA/CA stopped the sign-in and the user never finished it, from a network/country unusual for the user (settled for 15 min). That the password was right is taken from the result (the results that only come after the password) **or from the entry's own steps**: a "Password" step that succeeded, whatever the result is called (a device was required, an app was not allowed ...) | scored |
| Sign-in from unfamiliar surroundings | a sign-in by hand, authenticated then and there (not carried by an earlier session), from a network, address, device and kind of client the account never used - in a country it is known in (a new country is the next rule's alert). What a phishing proxy on a household address in the victim's own country looks like; also a person on a new private device somewhere new, so it is rated by the usual evidence. Accounts with less than `min_history_days` (7) of history are left out. Settings: `unfamiliar_signin` | base 30, scored |
| Admin role activations (PIM) | an eligible admin role is switched on (`Add member to role completed (PIM activation)`). Judged by where the account signed in from in the `minutes_before` (90) before - when the audit entry names the address, by the sign-ins from that address: only from outside the account's surroundings (no office, no managed or known device, no known network) it is an alert; otherwise it is recorded quietly (15) and counts only as a step of an attack chain that other findings already make. Settings: `role_activation` | base 45, scored |
| Session token theft | the same session used from another country **and** another device (AiTM / cookie theft). Sign-ins of Microsoft back-end services acting for the user (Microsoft-owned app + server credential + no user agent, e.g. "Olympus", the Office policy service) never count as the second device: they log whichever network path the device used (eSIM breakout, roaming, VPN) and often lack a device id. One alert per session and day: a session can live for weeks, and each day it is used from two places is a finding of that day | scored |
| AiTM phishing / session replay | (1) a **fresh** MFA (not "previously satisfied") completed through a hosting/datacenter network without device identity, not the user's habitual network - phishing proxies must do the MFA themselves; (2) the session of a fresh MFA sign-in used from another network within 3 h (also same country, also when neither side has a device id - the gaps of session theft). Both usual networks of the user (Wi-Fi/mobile switch) or alternating use: discounted | base 35 / 40, scored |
| MFA changes + new device | MFA method registered/deleted, MFA reset or TAP by an admin, password reset (directory audit, `Authentication Methods` + SSPR). Judged by **where** the user made the change (his sign-in at that moment - the audit IP is a Microsoft gateway for IPv6) and **what signed in afterwards** from a device/network not used before (baseline ends 12 h before the change). Admin resets/TAPs weigh more (social-engineered help desk). Guests skipped; new accounts (< 7 days) -20 | 10–30 by change, scored |
| Impossible travel | consecutive successful interactive sign-ins ≥ 500 km apart at > 900 km/h | scored |
| New country | success from a country not in the user's baseline (or not in `allowed_countries`) | scored |
| Background activity from a new country | background sign-ins (none by hand) from a country the account was not seen in. On a device the person has long used AND a network they use anyway it is only logged (their phone or laptop, wherever the address is counted to). So it is when that device is nowhere else at the same time: it travelled with its owner. The same device in two countries at once - at home at or after its first sign-in abroad, or so shortly before that no journey covers the distance (`impossible_travel.max_speed_kmh`) - stays an alert and says where else it was: a device is in one place, its sign-in token need not be (or it is a VPN, or a carrier's address counted to another country). A device that was logged as travelled is watched for `watch_hours` (48): when it signs in at home again sooner than any journey allows, the finding is raised after all; networks that hide where someone is (VPN, hosting) count as for any sign-in. An application that is not Microsoft's own and signs in for at least `app_server_min_accounts` (3) accounts from one cloud / hosting network is that application's own server (a connector, an assistant, a sync service), not a device abroad: logged only | scored, otherwise never below Low |
| New IP shared by several accounts | a never-seen IP used by ≥ 2 accounts within 24 h (AiTM phishing proxy) | scored |
| Attack tools / scripted sign-ins | interactive sign-ins from HTTP libraries/attack tools (`Go-http-client`, `python-requests`, `axios`, …) | scored |
| Legacy authentication | successful IMAP/POP/SMTP AUTH/EAS/… sign-in | scored, never below Low |
| Pinned accounts | an account in `pinned_accounts.accounts` signs in successfully from any other IP | 85 |
| Device code / ROPC sign-ins | completed device-code or ROPC (password-only) authentication. Base 55 for device code and 65 for ROPC (the flow is counted once). For ROPC of an admin account that needs no MFA the office network takes off only 10 instead of 30 (the password sits in a script), so it stays High there too. A device-code sign-in is one event, judged here once: its record names the device that **approved** the code but carries the address of the machine that **asked** for it, and so do the tokens that machine was given (the same application at the same address, after the sign-in). Neither is session theft, session replay or a place where the person was (see *A machine's place* below); the same tokens used at any other address are judged like any other sign-in. When the approving device was in use on another network or in another country than that address within 30 minutes before or after the sign-in, the code was asked for somewhere else: that device's identity, management and sign-in token and the MFA done on it are not counted for the machine that asked, +15 instead - so a phished code (approved by the victim at home, asked for from the attacker's network) comes out High, also for an account without any role. For an account on `device_code.allowed_users`, or with this rule switched off, nothing is passed over: the other rules judge these sign-ins like any other | scored, never below Low |
| Admin tools & device registration | first use of Azure CLI / PowerShell / Graph tools, or a device registration. What a sign-in to the registration service was is told by the audit log (the entry of the same account within minutes): a registration names the device it produced (a link to the device in Entra) - a Windows Hello key set up on a device that exists is no device registration and is left to the MFA-change rule. The sign-in waits up to 30 minutes (`device_enrolment.wait_minutes`) for the audit entry and for the directory's word on the device: one that is managed and came through the organisation's own programme (registered for Windows Autopilot, Apple's automated enrolment) is a company device being set up - logged with that programme named, and no persistence step of a chain (neither is the audit watch's record of the same device). Without that proof it is judged as before | scored |
| Corporate device enrolments (record only) | While a company device is enrolled, the account signs in to the enrolment service before the device has an identity: with Apple's automated enrolment from the service's own address in a cloud (another country, no device, password only), with Windows Autopilot from wherever the new computer is unpacked. That it is an enrolment cannot be read from the sign-in - the address may lie in ranges anybody can rent - but from the result: within 30 minutes the account registers a device that the directory knows as **managed** and as coming from an enrolment only the organisation's own devices can go through (Apple: `enrollmentType` contains `DEP`, the serial number is assigned to the organisation; Windows Autopilot: the device carries a `[ZTDID]` physical id, its hardware was registered for the organisation). Such a sign-in to the enrolment service is held back until that shows; then it and the account's other sign-ins from that address in those minutes become one record and are not judged as the user's own (no new country, no risky sign-in, no impossible travel measured against them, no "new IP shared by several accounts", no attacker address remembered, no chain step - the registration of that device recorded by the audit watch is none either) and what they brought is not learned as the user's habit: the service's country, network and address stay as new for the account as they were. Without the proof they are judged like any other sign-in, at most 30 minutes later; the address itself excuses nothing. Settings: `device_enrolment` (`corporate_types`, `wait_minutes`). | record |
| App sign-ins (service principals) | apps signing in with their own secret/certificate (~12,000/day), judged against a per-app baseline (countries, /24 network ranges, credential key ids; 3 days learning; raw rows not stored): new country -> Medium, first use of a credential -> Low, new range in a known country -> logged, >= 50 credential failures a week -> Low "credential failing" (Medium if from networks outside the app's baseline = someone trying its secrets). A credential that keeps failing the same way is one alert for as long as it does: dismissed once it stays dismissed, and returns when it fails differently or starts again after a week without | 10-70 |

Every scored rule also uses: **MFA registration** (account sync reads the registration report; an enabled member
without any MFA method gets +20 - whoever has the password can register their own MFA), **which Authenticator
approved** a successful MFA (usual device -10, a device the user never used +20) and **token binding** (a
device-bound session cannot be replayed: -25 in session theft / replay). MFA denials show the number-match result.

### Account context & MFA exposure
About twice a day the tool reads (read-only) all users, their state, password age and last sign-in, active
admin role assignments, roles activated via PIM in the last 30 days (PIM eligibilities themselves need an extra
permission), and every **enforced Conditional Access MFA policy for all users with its exclusions**
(for example a group of service accounts). The account context changes *which expectations apply*, never a blanket discount:

| Account | Treatment |
|---|---|
| Excluded from MFA (password-only) | +15 on every finding, no "habitual VPN"/travel excuses, and the **strict rule** below |
| Admin (active or PIM-activated role) | +10, highly privileged roles (Global/Privileged Role/Security/CA Admin, sync accounts …) +20 |
| Disabled | a successful sign-in after the account was found disabled is **High**; attempts are annotated |
| Break-glass (`breakglass_groups` and/or `breakglass_accounts` patterns) | any successful sign-in is **High** (background sessions included, one reminder per week), failed attempts raise an alert too |

**MFA-excluded accounts (strict)** learn each account's 30-day pattern (IPs, networks, apps, protocols,
countries). A successful sign-in outside it (new IP, protocol, browser use, country, or a dormant account
waking up) is High; a correct password stopped by Conditional Access from an unfamiliar network is High; 3 failed
passwords from unfamiliar networks within 24 h already raise an alert. The **weekly MFA-exposure report** (kept
for *RADAR > Reports*, never a reminder; a mark on Reports tells when its figures changed) lists
every excluded account with last sign-in, password age, what it really uses and clean-up flags (unused,
old password, looks like a person, disabled, admin role). Directory audit watch raises **High when someone is
added to an MFA exclusion group** (also via access-package approvals).

### Risk score (0–100)
The reasons listed with an alert add up to its score. When a later scan finds the same alert again with a lower
score, the alert keeps the explanation of its highest score - title, summary, reasons and fields - and only adds
what the later finding saw to its evidence. Where a rule never rates lower than a minimum (risky
sign-ins, device code / ROPC, legacy authentication, background activity abroad on an unknown device) and the
reasons add up to less, a line says so and why. Nothing is counted twice: where the base of an assessment already
says something (the flow of a device code / ROPC sign-in, Entra's risk rating and the generic detection it is made
of, a device that is just being registered and so has no identity), it is named and not added again; and for a
risky sign-in that is also the first from a new country, the country counts only when the address is not one of
a cloud, VPN or hosting network.

Every context-dependent finding starts from a base for its pattern and gets points added or removed
for evidence in the sign-in and the local history. The **Risk assessment** box of an alert lists each
factor. Score → severity: < 25 Info (logged, no pop-up), < 45 Low, < 70 Medium, ≥ 70 High. The reminder list
is sorted by severity, then score.

| Raises the score | Lowers the score |
|---|---|
| Hosting / VPN / bulletproof / cloud network (ASN list in `netintel.py`) | Corporate network (trusted named location / `trusted_ips` / `scoring.trusted_asns`) |
| Entra ID Protection detections (anonymous IP, AiTM, anomalous token, …) | User's usual / **habitual** network (≥ 3 days); user **regularly uses VPNs** (≥ 3 days); network used by ≥ 3 colleagues |
| Network never seen in the tenant | Known device of the user; on unmanaged devices a **known client** (same OS + browser family) |
| No device identity; device never seen for the user | Company-managed device (Entra/hybrid joined or compliant) |
| Password only (no MFA); SMS/voice MFA | Device-bound SSO token (PRT); phishing-resistant MFA (WHfB, FIDO2, passkey); passwordless phone sign-in |
| Attack-tool user agent; device code / ROPC flow | Same device active from the home country at the same time (VPN switch) |

Device and network familiarity come from a 30-day per-user **profile** built from *all* sign-ins (phones and desktop apps mostly sign in non-interactively, whose raw rows are only kept for 3 h).
Entra lists some sign-ins under one id twice - the sign-in by hand, and a background record of the same request (often a refused one). They are kept as two: the background copy never replaces the sign-in by hand, which stays its 30 days.

**Familiar needs age.** A device, a network, a client (OS + browser) or an Authenticator counts as the account's
own only once the account has used it for 12 hours (`scoring.familiar_after_hours`; the MFA-change rule's
`baseline_gap_hours` follows it unless set). What turned up moments ago cannot vouch for what
follows it: an attacker who registers a device signs in with it seconds later, from the network it was registered
from - that is not a *known device* on a *usual network*. Until then the device is named as *first used N min
before*, and its device-bound token lowers nothing (the token says as much as the device does). One exception: a
new network is the user's own at once when a device that is already familiar uses it - the phone on a hotel's
Wi-Fi.

**And somebody has to vouch for a device.** Age alone does not make a device the user's: it must also have been
seen where the account otherwise is - on an office network, on a network the account knew before the device
appeared, or on one an older device of the account uses. A device registered through a datacenter and only ever
used from there stays a stranger (*in use since ..., but only on networks the account does not otherwise use*),
its token lowers nothing, and the network it works from does not become a *usual* or *habitual* one through it.
The first devices of a new account need nobody to vouch, and a device nobody vouches for becomes the user's own
after 14 days all the same (`scoring.unvouched_after_days`) - a phone that only ever uses mobile data.

**A machine's place is not the person's.** A sign-in tells where the person is - unless it was made on a machine
the person works on from somewhere else, or on one that only asked for a token for them. Then the address, country
and network are the machine's:
- a virtual desktop or shared host listed in the settings (`virtual_desktops`: device name, wildcard pattern or
  address range - Citrix, Azure Virtual Desktop, terminal servers);
- a machine in a cloud data centre, learned from the records: a device with an identity of which at least 95 % of
  at least 20 sign-ins came from cloud or hosting networks (the ASN list in `netintel.py` and `scoring.extra_asns`;
  not `scoring.trusted_asns`), first seen at least 12 hours ago (`scoring.familiar_after_hours` - one that
  turned up in a data centre an hour ago is a stranger's as likely as not). Only its sign-ins from such a network
  count; the same machine anywhere else is judged as usual, and a laptop that is behind a cloud gateway most of the
  time is no such machine;
- a machine reached by remote desktop: a sign-in that came with a remote desktop token (and that machine's further
  activity at that address), or a registered computer (not a phone or tablet) that began signing in within
  3 minutes after the account's remote desktop client (Remote Desktop, Windows App, Azure Virtual Desktop,
  Windows 365) signed in from another device at another address;
- the machine that asked for a device code (see the device-code rule).

The rules that place the person pass such sign-ins over: impossible travel (also as the previous position), new
country, background activity from a new country (also the same device in two countries at once), sign-in from
unfamiliar surroundings, the wave of unusual sign-ins and *same device active from the home country*. No country is
learned from them: one the account knows only through such a machine is still new for the person. And they make no
network the account's usual or habitual one: of a network the account used on such a machine only its other use
counts, and on a cloud or hosting network colleagues who use it only on such machines are not counted among the
colleagues.

New-country / travel alerts are also **classified**: *corporate network*, *likely VPN / proxy*,
*user's habitual VPN*, *likely travel (known device)* or *unknown device*. A trip with the user's managed laptop or a VPN
on it scores low and does not pop up. An unknown device on a hosting network does.

### Detail views, links and original log entries
Nothing in a detail view is cut off: summary, fields and risk factors wrap and scroll; the split between them
and the evidence table is sized to the content and can be dragged. The selected evidence row is shown in full
below the table (long cells such as targets or user agents included). All text can be selected and copied.

**Blue text is a link.** Click = the most useful action, right-click = all actions + copy (the bottom line says
what a click will do):

| In the text | Click | Right-click adds |
|---|---|---|
| user / guest address, User ID | user in Entra | sign-in logs, authentication methods, audit logs of the user |
| app name, app id (Initiated by, App, Application, Targeted apps) | enterprise app in Entra | its permissions; certificates & secrets and owners (apps registered in this tenant) |
| group, CA policy, device, role | the object in Entra / role description (Microsoft Learn) | group members, Roles and administrators |
| Graph permission | what it allows (Microsoft Learn) | |
| IP address, AS number | AbuseIPDB / ipinfo.io | the other one |
| tenant id | which organisation it is (shown in the window) | cross-tenant access settings |
| Sign-in ID / Audit ID / Correlation ID | the original log entry **in the app** | |
| alert title (attack-chain step, Correlated with, Related signals) | that alert | |
| session / request / token ids | copy | |

Names and addresses are looked up in Entra (read-only Graph, cached) to find the object id the portal link needs;
"not found" means deleted, external, or not a directory object. Entra does not document its portal routes: the
links use the routes the portal itself shows in its address bar.

Double-click an evidence row (or the button above the table) to open what it refers to: the complete **sign-in
record** (basic info, location/ASN, device, authentication steps, Conditional Access - double-click a policy to open
it - risk, raw JSON), the **audit entries of the operation** (every entry with the same correlation id: activity,
who - user or app, app-only note -, each target with all changed properties old -> new decoded from JSON, additional
details such as the User-Agent), the referenced **alert** (attack chains) or the **account** (MFA exposure report).
Right-click a row for the same plus copy cell / row. The *Ongoing attacks* window works the same way (right-click,
full row below the table, double-click an IP for its reputation).
All tables sort by clicking a column header (again = reverse). The Entra portal has no deep link to a single log
entry, so **Open in Entra portal** / **Entra: sign-in logs** copy the Request ID to the clipboard and open the
sign-in logs, where you add the *Request ID* filter and paste it.

Noise controls (in `config.json → plugins.signin_threats.settings`):
- `trusted_ips`: office / VPN egress IPs or CIDRs, either a list or named, e.g.
  `{"198.51.100.177": "UK office (London)"}` (alerts then say *Corporate network: UK office*), and
  `trust_named_locations` (CA *trusted* named locations, on by default). Geo rules ignore them, the score drops.
  To find office IPs: many different users, mostly managed devices, on weekdays.
- `pinned_accounts.accounts` pins service accounts to IPs/CIDRs, e.g.
  `{"scanner@contoso.com": ["198.51.100.10"]}`, or `["trusted_ips"]` for "any office IP" (follows the office
  list): legacy auth from those IPs is expected, any successful sign-in from elsewhere is a High alert.
- `ignore_users`, `ignore_ips` exclude completely; `legacy_auth.allowed_users`,
  `device_code.allowed_users` allow-list per rule. User lists accept wildcards (`meetingroom-*@contoso.com`).
- Impossible travel skips the same device, the same country and country-level-only geolocation by default.
- `scoring.trusted_asns` (e.g. your VPN/ZTNA provider), `scoring.extra_asns`
  (`{"64500": ["Name", "vpn"]}`), `scoring.suspicious_user_agents` (regex list; `null` = built-in).
- Thresholds and windows per rule, `notify_min_severity` (general) for what pops up.

First run: imports a 30-day interactive baseline (Entra's full retention) and evaluates the last 24 h (≈ 4 minutes). Raising `baseline_days` later fetches the missing older days once.
After a time in which RADAR was not running, the non-interactive sign-ins of the last
`non_interactive_max_catchup_hours` (6) are read at once and those before in the following scans, newest first
(`backlog_pages_per_run` pages of 1000 per scan, up to `non_interactive_backlog_days` = 7 back; 0 = skipped).
The same goes for more sign-ins than one scan reads (`max_pages_per_run`, 400 pages of 1000; for the applications'
own sign-ins 200): Microsoft lists the newest first, so what the page limit left unread lies before the oldest
sign-in read - it is owed and read by the following scans in the same way, interactive, background and application
sign-ins alike, and a baseline import the limit cut short is completed by the following scans from where it
stopped. What is read afterwards feeds the profile (devices, networks, countries) and the rules that judge each
new sign-in; rules that compare within the last minutes or hours (session replay right after a fresh MFA) see only
what is still stored.
Non-interactive sign-ins (thousands per hour in a mid-size tenant) are kept for 3 h only
(`non_interactive_retention_hours`; raise it to ~26 if you turn on `include_non_interactive` for the geo rules).

**Nothing that was read is lost.** A bookmark - how far the sign-in log, the audit log, the applications' sign-ins
were read - moves only when what was read up to it is in the alert store. Sign-ins are marked *unjudged* in the
step that stores them and stay so until the findings of the scan that judged them are stored; they are not
cleared meanwhile, however old a background record is. A scan that is stopped (RADAR closed, the PC shut down),
crashes or fails - also in the middle of reading - therefore leaves nothing behind: the next scan reads from the
same place and judges what waits. It never gives up: a rule that fails keeps the scan open (its sign-ins are
judged again by the next scan), and after two scans in a row that did not finish, or a rule that failed, a reminder
says so until it works again. A rule that fails in three scans in a row stops holding the scan back: from then on
the scan is complete without it - what it reads is judged by all the other rules, and not by that one afterwards -
while the rule is still tried with every scan and one reminder names the check that keeps failing until it works
again. The audit watch stores nothing itself: it reads the same entries again, and its findings have fixed keys,
so nothing is doubled. What the user decides during a scan stands: a dismissal or snooze made while a scan is
storing its findings is not undone by that scan, even when its finding is worse; a later scan that finds the alert
worse still brings it back.

### Directory audit watch (`directory_audit`, every 15 min)
Watches the audit log for role assignments (a role alert says which role on what for whom - `Owner on <subscription>
(Azure subscription)` -, counts an assignment once although it is logged as requested, completed and by the directory,
and says when somebody gave a role to their own account, +5; a role on an Azure resource that can hand out access -
Owner, User Access Administrator - adds 15, a top directory role 25), app credential changes, consent grants,
Conditional Access and domain federation changes, members added to groups excluded from any enforced Conditional
Access policy (MFA exclusion 80, other policies 60), BitLocker / LAPS secrets read (single reads logged, >= 5 per
person and week Medium; a LAPS read Low), owners added to apps, a Global Administrator elevating to Azure root
(High), and optionally admin password/MFA resets. Device registrations (silent links for attack chains: the
device with its id - a link to it in Entra -, its kind and the address it was registered from) and
session revocations (remediation context: a chain followed by a revocation is marked "handled?") are recorded.

*Who a finding is about.* A finding of the audit watch names everybody it concerns: the one who made the change
(an application is named as one, also when it is the actor), the accounts it was done to (*Done to*: who got the
role, was made an owner, had their MFA reset) and, for roles, owners and credentials, the application it was done
to. That is what attack chains, incidents and "Don't remind again" go by. *From where.* When the one who made a
change acted from an address the sign-in checks know as an attacker's (within a day), the finding names it
(*Known attacker address*) and gets +30 - and belongs to everything else about that address.

**What switches other protections off** is watched too:

| Change | Why | Score |
|---|---|---|
| Named location added / changed / deleted (`named_locations`) | Conditional Access policies that leave out trusted locations stop applying to sign-ins from it - and RADAR itself counts a trusted location as the organisation's own network (`trust_named_locations`) | 45 (deleted 40), **marked trusted +20** |
| Authentication methods policy, an authentication strength, security defaults (`auth_methods_policy`) | which sign-in methods the tenant allows and what counts as strong, for everybody | 50 / 45 / 60 |
| Member or owner added to a group that can hold admin roles (`privileged_group`) | the group's roles are the member's at once, and no role assignment is logged for the person - only "Add member to group". The role-assignable groups are read from Entra (cached 6 h); activations through PIM are left out | 60 (owner 55) |
| Rare changes of the tenant itself (`tenant_changes`, one reminder per person and week) | a domain added or verified (it can be federated) 25-35; a private network connector registered 35; on an **existing** application a new reply address (where its sign-in tokens go) 20, +20 unencrypted to another machine, +20 wildcard; public client flows switched on 30; the authorization policy changed (what every user may do without an admin: inviting guests, registering applications) 30 | 20-70 |
| Outside organisations given admin access (`partner_access`) | a partner given delegated administration 70; an outside organisation made a service provider that can be given admin roles 50, +25 when a highly privileged role is among them. Microsoft Support during a support case is recorded with the case, not here | 50-75 |
| Many objects deleted at once (`mass_deletion`, per actor and day) | accounts (from 5), groups (from 10) or applications (from 5) deleted by one actor in a day 50, three times that 70; +10 deleted for good, +10 several kinds; -30 known automation. An application and its enterprise application count once. The counts are the setting `mass_deletion` (0 = not watched) | 20-90 |

Your automation (`automation_initiators`) gets -30 here as everywhere. In attack chains the first three are
escalation (stage 5), the last one persistence (stage 4).

**Attack chains** (`radar/chains.py`, after every scan, `general.attack_chains`). Each alert - also dismissed
ones, silent signals and "logged only" findings - is a possible step of an account takeover: 1 targeted (password
guessing, attack tools) -> 2 password known (MFA stopped it, MFA denials) -> 3 suspicious access (risky sign-in,
new country, session theft, device code ...) -> 4 persistence (MFA method change, consent, app credentials, guest
invite ...) -> 5 escalation (admin role, CA / federation change). Steps about the same account whose stages rise
in time order, each within 3 days of the previous one's last activity (a running campaign counts until its last
attempt), form a chain. An admin role activated from the account's own surroundings is such a step only in hindsight
(see below); activated from unfamiliar surroundings it is an alert and a full step. It becomes a reminder ("Possible attack chain: ...") if it starts with stage 1/2 and
reaches 3+, or covers three stages - so "abroad, then a new passkey" stays quiet. One pair of two is a chain as
well: a sign-in that may not be the user (3) followed by a grab for power (5: a role, a policy, a federation, an
outside organisation let in, a mass deletion), when both are at least Medium. And a sign-in rated High on its
own (3) followed by a way to stay (4: a device registered, an MFA method, a consent) - "MFA completed through a
datacenter, then a device registered" is the takeover itself. A chain must combine at least
two different detections; a step must be at least Low on its own (score >= 25); an "access" step whose sign-ins
all failed counts as targeting. Score = strongest step + 10 per further step (+10 if the password was known and
something followed); two-step chains stay Medium unless a step is High on its own.

*What was dismissed:* a step dismissed before the later steps were known counts in full - dismissing each step by
itself is how a chain gets overlooked. A step dismissed with the whole chain on screen is settled: it adds +5
instead of +10, the chain is rated by its strongest step that is not settled, and a chain whose real steps are all
settled leaves the reminders (as does one whose steps no longer add up after a rule change). Guessing at a
disabled account starts no chain. A chain lists each step once, with the state it has now. Dismissing a chain
offers to dismiss its open steps as well, and dismissing its last open steps offers the chain.

*In hindsight:* a finding that was only logged (score 10-24) can be a step of a chain that two real steps already
make (+5 instead of +10); it never starts a chain and never makes one. *Slow attacks:* the look-back is 30 days,
and two steps that are each at least Medium (45) may lie up to 10 days apart instead of 3.

**Known attacker addresses** (`signin_threats/indicators.py`, setting `hostile_indicators`: `enabled`, `days` = 7).
Rules judge one account at a time; what one of them proves about an address is kept and used by all. After every
scan the findings of at least Medium from these rules mark the addresses of their sign-ins: a reported MFA prompt,
session theft, AiTM / session replay, a password attack that got past the password, a guessed password (+25 on any
later assessment), and a correct password stopped by MFA, repeated MFA prompts (whoever causes them knows the password), a new
address shared by several accounts, attack-tool
sign-ins, a password spray (+15). Only sign-ins foreign to their account mark an address (no office network; no
device, network or address the account used before), never an address three or more accounts regularly sign in
from (a hotel, a mobile carrier). The mark then counts in **every rule's assessment** of a sign-in from that
address - to any account, or to the same account later - as "Known attacker address: used in ...", except for
sign-ins from a device the account already used. It never counts against the sign-ins it was derived from. Alerts
whose evidence contains such an address get the field *Known attacker address*.

*Networks that only guess.* A guessing campaign changes its address with every attempt, so its addresses say
nothing about the next one - the networks it rents them in stay the same for weeks. A network (AS) from which the
passwords of at least `network_min_accounts` (3) accounts were guessed at within `days`, and from which nobody in
the tenant has ever signed in, is remembered as well. It adds +15 to the assessment of whatever gets past a password
from it (a successful sign-in, a right password that was stopped), on no device and no network the account knows -
never to the guessing itself, and no longer once anybody signs in from that network (a mobile carrier or a home
provider stops being one with the first person on it).

*Applications* have chains too. What is planted on an application (a credential, an owner, a consent: 4) and
the application then signing in from a country it never used (5) is a chain about the application; its secrets
being tried from outside its networks count as targeting (1). A new credential that is simply used, or one that
keeps failing, is operations and no step. An account under suspicion that did something to an application is
taken together with it like with another account ("Attack across 2 accounts / applications").

**Attacks across accounts** (`chains.spread_findings`). Accounts are taken together when their alerts name the
same known attacker address, or when an account that was already under real suspicion acted on another one
afterwards (*Initiated by* / *Invited by*: reset its MFA, gave it a role, invited it ...). Under suspicion means
evidence that somebody else may be IN the account: its password is known, or a sign-in of at least Medium that may
not be the user (and was not dismissed). What the account DOES with its rights - a role it assigned, a policy it
changed - is no such evidence: an administrator at work would be tied to everybody they administer. The account
that was acted on is part of the story from that moment on; what it did before belongs to nobody else's story.
An administrator nobody suspects joins nothing, and what is
done ABOUT an account - disabling it, enabling it again, revoking its sessions - is the answer to an attack and
ties nobody together. Over the alerts of such a group the same chain is looked for; when it
runs across at least two accounts it is raised as "Attack across N accounts: ..." (chain score +15).

**Incidents** (`radar/incidents.py`, RADAR window > Incidents). Alerts that were reminders (at least Low, not only
logged) about the same account or the same known attacker address, no more than 7 days apart, are one incident;
chains of such pairs join. Chain alerts name the incident; responses (sessions revoked, password reset, account
disabled, and a registered device removed again - which answers the alert about the registration of exactly that
device, by its id) and logged-only findings are shown with it as context but neither make an incident nor join two. The
window lists the incidents of the last 30 days with their alerts in order; the open reminders of one incident can
be dismissed together.

"About an account" means the account it happened to. An alert that only names an account - as the one who did
something (*Initiated by* / *Invited by*: a consent, a policy change, a key that was read) or as one an
administrator's change was done to (*Done to*: five people given a role) - joins an incident about that account
when it comes after an alert about the account itself that is still open, at least Medium, or a chain; a Low
alert that was looked at and dismissed is not reopened by it. Two things an administrator did are their work, not
an incident, and the people an administrator did something for do not become one. An application ties alerts together through its own sign-ins (a new credential or consent,
then a sign-in from somewhere new) - a credential and a consent alone are an application being set up. Not part
of an incident: an alert that was merged into another, a chain that no longer holds, and what merely does not
work (a failing app credential; RADAR's own notices, such as a check that keeps failing). How far an incident got is told by what is still open; a stage whose alerts
were all dismissed is shown as settled. A single alert is never an incident, however severe: it is in the
reminders and the alert history.

**Microsoft 365 support cases.** Opening a case in the admin center adds the Microsoft Support tenant
(`b4c546a4-…`) as cross-tenant service provider (actor: the admin, recorded silently); while an engineer works on it,
Microsoft's Assist API (app `2b8844d8-…`, checked against its service principal id in your tenant) adds
support-tenant groups to the read-only *Microsoft 365 Support Engineer* role. With a case opened by your admins in
the 30 days before, that assignment is logged as Info; without one it is Low ("who requested support?"); assigned
by anything that is not the real Assist API it is High. See [Microsoft's description of the flow](https://learn.microsoft.com/microsoft-365/admin/support-diagnostic-information-collection).

**App consent is judged by what is granted, not by who clicked "Accept".** With user consent disabled every
consent is an admin decision, mostly routine. Grouped per app and week:

| Grant | Treatment |
|---|---|
| App-only permission that controls the tenant (`AppRoleAssignment.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, `Group(Member).ReadWrite.All`, `full_access_as_app` …) | alert, 75 |
| App-only access to content (mail, files, sites, chats, calendars, hunting …) or any `*.ReadWrite*` | alert, 55 |
| App-only read of directory data; any delegated consent (acts within each user's own rights) | **signal** 5–35: alerts only with another ≥ Medium alert about the consenting admin or the app from up to 7 days before the consent to 1 day after it (+25) - the suspicion comes first. Consents that only let an app sign people in (below 10) are left out. App credential/consent alerts do not count as partner (app onboarding), nor does a chain the consent is itself a step of. When the partner no longer counts, the consent goes back to being context |
| The same permission granted to the same app again (just-in-time pattern, remembered in plugin state) | signal ("re-grant") |
| A non-admin consented while user consent is disabled / user consent switched on in the authorization policy | alert, ≥ 70 |

Your automation (`automation_initiators`) gets -30 only if no person was involved. When an app grants a
permission to itself, the alert shows what the same program did with it and when it removed it again
("Used for": e.g. *Update a partner cross-tenant access setting after 11 s …; removed again after 24 s*).

**App-only changes name no person.** An app that signs in with its own secret/certificate appears in the audit
log only as the app. Alerts about such changes therefore show where the app signed in (IP, city, named location),
which credential it used (name, validity, long-lived secrets flagged), who signs in to the app themselves, and -
only on a quiet network, not an office - who else signed in from that IP at the time.

**Cross-tenant trust** (`cross_tenant_access`): trusting a partner tenant's MFA is Low (40), also its devices
Medium (50), any trust in the default setting for *all* organisations High (75); B2B scope, consent suppression
and inbound user sync are rated too. The alert names the partner and its users seen here in the last 14 days.

**Guest invitations and account disables are context signals, not alerts.** Users may invite guests themselves
(often their own private mailbox first, to test), so an invite on its own is recorded silently (still scored:
private mailboxes higher, the inviter's own private mailbox highest). It only becomes a reminder in combination
with something else (`radar/correlation.py`):

| Signal | Combined with | Result |
|---|---|---|
| Guest invite | any other alert of at least Medium about the inviter within ±7 days | invite +15, both alerts link to each other ("Correlated with" / "Related signals") |
| Guest invite of a private mailbox (score ≥ 50) | the inviter's account is disabled 0–30 days later | invite +25 ("leaver taking data?") |

Correlation runs in both directions (the invite can come before or after the other alert), so an activated invite
pops up like a new alert.
Only the relevant audit categories are fetched (provisioning/sync is ~65 % of the
volume), Microsoft system actors (`system_initiators`: MS-PIM, AAD App Management, Cloud Sync, …) and the PIM
activation lifecycle are ignored, role changes are rated by role (Global/Privileged Role/Security/CA Admin …
High), your own automations (`automation_initiators`) get −30 so routine changes are
logged without pop-up, and reminders are grouped per person and day (consent/credential changes per week).
