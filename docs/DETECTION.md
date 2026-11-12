# What RADAR detects

The detection logic lives in two built-in plugins. Thresholds named here are defaults; most can be changed in the
settings file (tray menu: Settings > Advanced > Edit settings file).

### Sign-in threat detection (`signin_threats`, enabled, every 10 min)
Pulls interactive **and** non-interactive user sign-ins (beta `auditLogs/signIns`), de-duplicates
them into a local history and runs these rules:

| Rule | Default logic | Ranking |
|---|---|---|
| Risky sign-ins | **successful** sign-ins Entra ID Protection rates ≥ medium / confirmed compromised, per user and day (blocked risky attempts count as attack evidence instead; `include_failed`) | scored, never below Low |
| Password attack from rotating IPs | per account in 72 h: ≥ 8 failed passwords from ≥ 6 IPs on networks the user never used (residential-proxy botnets: ~1 attempt per IP). Escalates to High if an attempt gets past the password or a device-less sign-in succeeds from an unfamiliar network; lists other accounts hit by the same campaign | 40–50, escalates |
| Password spray | one IP, failed password for ≥ 5 accounts in 60 min (skipped if the IP is mostly successful traffic) | 80 (90 if an account then succeeded) |
| Brute force | ≥ 10 failed passwords for one account in 60 min; escalates if a success from the same IP follows | 55 → 85 |
| MFA fatigue | ≥ 3 MFA denials (500121) in 60 min | 75 |
| MFA prompt reported by the user | The user reported an MFA prompt as not theirs (Authenticator: *No, it's not me* > report; phone: the reporting code). Entra writes the audit entry `Suspicious activity reported`; a prompt is only sent after the right password, so a true report means the password is known. The sign-in that caused the prompt is a separate row in the sign-in log (failed MFA step, same account, seconds before the report) that Entra delivers **up to 1-2 hours later**. Until it arrives: Medium. With it, the alert is judged by where that sign-in came from: the account's own managed device and usual network → Low ("probably their own sign-in", reported by mistake); an unfamiliar network or device → High. No such row after `wait_minutes` (120) → High. A password reset or disabling the account answers it. **Needs the tenant setting *Report suspicious activity*** (Entra ID > Authentication methods > Settings; "Microsoft managed" means off): while it is off the rule is inactive and the menu says so; when the setting cannot be read with the sign-in used (it needs `Policy.Read.All`) the rule stays active. The connection check shows the state. **The attacker's address is remembered**: when the reported prompt did not come from the user's own surroundings, its address counts +25 in every rule's assessment of any sign-in from it, to any account, for `mark_days` (7). Sign-ins from it to other accounts - or a successful one to anybody - raise an alert of their own ("Address of a reported MFA prompt also used on ...": 45, +20 when a password was right, +35 when a sign-in succeeded); sign-ins from a device the account already used are left out (a colleague on the same hotel network). A report judged as the user's own prompt marks nothing. Settings: `mfa_report` (`activities`: the audit entry names, `match_seconds_before/after`, `wait_minutes`, `mark_days`). | 50 → 25-100 |
| Correct password, MFA not completed | password accepted, then MFA/CA stopped the sign-in and the user never finished it, from a network/country unusual for the user (settled for 15 min) | scored |
| Session token theft | the same session used from another country **and** another device (AiTM / cookie theft). Sign-ins of Microsoft back-end services acting for the user (Microsoft-owned app + server credential + no user agent, e.g. "Olympus", the Office policy service) never count as the second device: they log whichever network path the device used (eSIM breakout, roaming, VPN) and often lack a device id | scored |
| AiTM phishing / session replay | (1) a **fresh** MFA (not "previously satisfied") completed through a hosting/datacenter network without device identity, not the user's habitual network - phishing proxies must do the MFA themselves; (2) the session of a fresh MFA sign-in used from another network within 3 h (also same country, also when neither side has a device id - the gaps of session theft). Both usual networks of the user (Wi-Fi/mobile switch) or alternating use: discounted | base 35 / 40, scored |
| MFA changes + new device | MFA method registered/deleted, MFA reset or TAP by an admin, password reset (directory audit, `Authentication Methods` + SSPR). Judged by **where** the user made the change (his sign-in at that moment - the audit IP is a Microsoft gateway for IPv6) and **what signed in afterwards** from a device/network not used before (baseline ends 12 h before the change). Admin resets/TAPs weigh more (social-engineered help desk). Guests skipped; new accounts (< 7 days) -20 | 10–30 by change, scored |
| Impossible travel | consecutive successful interactive sign-ins ≥ 500 km apart at > 900 km/h | scored |
| New country | success from a country not in the user's baseline (or not in `allowed_countries`) | scored |
| New IP shared by several accounts | a never-seen IP used by ≥ 2 accounts within 24 h (AiTM phishing proxy) | scored |
| Attack tools / scripted sign-ins | interactive sign-ins from HTTP libraries/attack tools (`Go-http-client`, `python-requests`, `axios`, …) | scored |
| Legacy authentication | successful IMAP/POP/SMTP AUTH/EAS/… sign-in | scored, never below Low |
| Pinned accounts | an account in `pinned_accounts.accounts` signs in successfully from any other IP | 85 |
| Device code / ROPC sign-ins | completed device-code or ROPC (password-only) authentication | scored, never below Low |
| Admin tools & device registration | first use of Azure CLI / PowerShell / Graph tools, or a device registration | scored |
| App sign-ins (service principals) | apps signing in with their own secret/certificate (~12,000/day), judged against a per-app baseline (countries, /24 network ranges, credential key ids; 3 days learning; raw rows not stored): new country -> Medium, first use of a credential -> Low, new range in a known country -> logged, >= 50 credential failures a week -> Low "credential failing" (Medium if from networks outside the app's baseline = someone trying its secrets) | 10-70 |

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
passwords from unfamiliar networks within 24 h already raise an alert. The **weekly MFA-exposure report** lists
every excluded account with last sign-in, password age, what it really uses and clean-up flags (unused,
old password, looks like a person, disabled, admin role). Directory audit watch raises **High when someone is
added to an MFA exclusion group** (also via access-package approvals).

### Risk score (0–100)
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
Non-interactive sign-ins (thousands per hour in a mid-size tenant) are kept for 3 h only
(`non_interactive_retention_hours`; raise it to ~26 if you turn on `include_non_interactive` for the geo rules).

### Directory audit watch (`directory_audit`, every 15 min)
Watches the audit log for directory role assignments, app credential changes, consent grants,
Conditional Access and domain federation changes, members added to groups excluded from any enforced Conditional
Access policy (MFA exclusion 80, other policies 60), BitLocker / LAPS secrets read (single reads logged, >= 5 per
person and week Medium; a LAPS read Low), owners added to apps, a Global Administrator elevating to Azure root
(High), and optionally admin password/MFA resets. Device registrations (silent links for attack chains) and
session revocations (remediation context: a chain followed by a revocation is marked "handled?") are recorded.

**Attack chains** (`radar/chains.py`, after every scan, `general.attack_chains`). Each alert - also dismissed
ones, silent signals and "logged only" findings - is a possible step of an account takeover: 1 targeted (password
guessing, attack tools) -> 2 password known (MFA stopped it, MFA denials) -> 3 suspicious access (risky sign-in,
new country, session theft, device code ...) -> 4 persistence (MFA method change, consent, app credentials, guest
invite ...) -> 5 escalation (admin role, CA / federation change). Steps about the same account whose stages rise
in time order, each within 3 days of the previous one's last activity (a running campaign counts until its last
attempt), form a chain. It becomes a reminder ("Possible attack chain: ...") if it starts with stage 1/2 and
reaches 3+, or covers three stages - so "abroad, then a new passkey" stays quiet. A chain must combine at least
two different detections; a step must be at least Low on its own (score >= 25); an "access" step whose sign-ins
all failed counts as targeting. Score = strongest step + 10 per further step (+10 if the password was known and
something followed); two-step chains stay Medium unless a step is High on its own.

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
| App-only read of directory data; any delegated consent (acts within each user's own rights) | **signal** 5–35: alerts only with another ≥ Medium alert about the consenting admin or the app within ±7 days (+25). App credential/consent alerts do not count as partner (app onboarding) |
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
