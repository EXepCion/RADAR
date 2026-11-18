# What changed in RADAR

The newest version first. The release notes of a version on GitHub hold its own part only.

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

**New in 1.0.8** (cleaner screens, one layout for incidents and attacks)

- *Ongoing attacks* is laid out like *Incidents*: one row of buttons with counts (password known, stolen
  sessions, password guessing, attacking IPs), a list with a status pill and the key facts under each name, and
  all facts of the selected row on the right. It opens on the most dangerous kind that has entries. The four
  figure tiles, the tabs and the wide scrolling tables are gone.
- *Incidents* always opens on what is open. With nothing open it says so, with a link to the closed incidents
  and a note when single alerts are still open. Closed incidents look closed: a grey pill and the closing date.
- An incident's summary no longer repeats itself: title and state are in the title bar or the list, an
  arrowhead shows which row the panel on the right belongs to, and the facts are an aligned list. In an
  incident's window the strongest finding is shown, and what was only logged is marked as context instead of
  carrying the name of a stage.
- Audit log entries compare instead of listing: a change is shown setting by setting in the columns *Setting*,
  *Before* and *After*, with what was taken out and what was put in highlighted. Only what differs is shown
  (the rest on demand), lists are compared entry by entry, and the entry starts with what was changed.
- Every time shown names its time zone ("14:32 UTC+1"), in all windows and on the live map. Alerts stored
  before get theirs once.
- The reminders' header and an alert's header say less: the full title, when it happened and what happened.
  Severity, score and the rule are where they already were (the row, the risk assessment, *Copy details*).
- After a start or an update the lower left corner knows at once who is signed in: RADAR signs in quietly when
  it starts instead of waiting for the first scan.
- Less text on every page, and several layout fixes (virtual desktops: the *Add* button no longer covers the
  text beside it; values in the facts lists start at one place).

**New in 1.0.7** (one window)

- Incidents, ongoing attacks, alert history, reports and all settings are now in one RADAR window with a
  navigation on the left. The reminders, the details of an alert and the live map stay windows of their own.
- Settings have pages: detection, offices, virtual desktops, reminders and sound, appearance and start, account
  and connection, plugins, advanced. What was a submenu of the tray menu is a switch or a button there.
- The tray menu is short: open RADAR, show reminders, live map, scan now, pause, settings, exit. A click on the
  tray icon opens the RADAR window.
- The navigation shows how many incidents are open and how many accounts are under attack; its lower left
  corner says what RADAR is doing, when it last scanned and when it scans next.
- Tables are easier to read: a line under every row, the severity as a coloured pill, only the state in
  colour, and times as "Today 13:48". Suggested offices and virtual desktops have an Add button in their row.
- Sharp on every monitor: with screens of different scaling (say 150 % and 100 %) RADAR's windows were blurry
  on one of them. A window is now drawn for the screen it opens on.
- On the first start the window opens on the set-up page; the other sections are switched off until RADAR can
  read what it needs.

Fewer reminders about the same thing, and fewer about nothing:

- One password campaign against several accounts is one alert that names them all. A disabled account among
  them is a line in it; an account where something happened (the password worked, a break-in, the person is
  locked out) keeps an alert of its own.
- A risky sign-in that is also the first from a new country is one alert, not two.
- Attack chains: what an administrator does about an account (disabling it, revoking its sessions) no longer
  ties the two accounts into one "attack across accounts"; an account counts as suspected only when its password
  is known or an alert of at least Medium is open. Steps you dismissed with the whole chain in view weigh less,
  and a chain whose steps are all settled or no longer add up leaves the reminders. A chain lists each step once.
- App consents are raised by other suspicious activity only when that came first, and not at all when the
  consent merely lets an app sign people in.
- Background activity from a new country on the person's own, long-used device and a network they use anyway is
  only logged. More networks that hide where someone is are recognised by name.
- A password-only (ROPC) sign-in of an admin account without MFA stays High inside the office too.
- An app credential that keeps failing is one alert for as long as it fails the same way: dismissed once, it
  stays dismissed, and it says that it is an operational problem.
- The weekly MFA exposure report is no longer a reminder: it is in *Reports*, with a mark in the navigation when
  its figures have changed.
- Dismissing a chain offers to dismiss its open steps as well (and the other way round).
- Low alerts you have seen and that did not change for 7 days close by themselves into the alert history
  (*Settings > Reminders and sound*; can be switched off).
- After the update the open reminders are judged once with the new rules, from the data kept on the PC.

The *Incidents* page is laid out for someone on watch:

- On the left the incidents, most urgent first: severity with the highest risk score, who it is about, how far it
  got and how much of it is still open, when it last moved.
- On the right the chosen incident: a track of the five stages of an attack with the time each was reached, the
  accounts and attacker addresses, since when, and what was already done; then its strongest finding with the
  reasons that weigh most, and what to do; then its alerts in order.
- An incident has a window of its own (double-click it, or *Open details* with no alert selected): the same
  summary as on the page, the whole advice, and for each of its alerts the reasons for its rating. Its open
  reminders are dismissed or snoozed together from there; an alert's evidence and links are one double-click on.
- The page says how many open alerts are not part of an incident: those are in the reminders.
- The reminders show an incident as one row ("Incident: who - how many alerts - how far it got") instead of its
  chain alert and every step: it is opened, snoozed and dismissed as one. The window's title counts things to
  handle, not alerts.
- A details window no longer opens behind the RADAR window or an incident's window while the reminders show.
- What makes an incident is stricter: what an administrator did counts only after an alert about their own
  account, an application only through its own sign-ins, and a failing integration not at all. How far an
  incident got is told by what is still open.

Risk assessments say what they count:

- A rating that is held at a minimum says so and why (a device code sign-in is at least Low because, with a
  phished code, the sign-in is always completed on the victim's own device and network).
- Device code and ROPC sign-ins name the flow once instead of counting it in two or three lines.
- Registering a device is no longer rated up because that device has no identity yet.
- For a risky sign-in the detection Entra's rating is made of is named, not counted again; and the country of
  a cloud, VPN or hosting address is named, not counted.

**New in 1.0.6** (connecting the dots across accounts)

- Known attacker addresses: what any check proves about an address (a stolen session, a phishing proxy, a
  password that worked, a reported MFA prompt ...) is remembered for 7 days and counts in every check, for every
  account. Other accounts tried from such an address raise an alert of their own.
- Wave of unusual sign-ins: several accounts with an odd sign-in at the same time from one new network or one
  never-seen client - each alone too little to report.
- Attack chains now also run across accounts (same attacker address, or a suspected account acting on another),
  look back 30 days, follow slow attacks between strong steps, and can be completed in hindsight by a finding that
  was only logged. A reported MFA prompt is a chain step.
- New window *Incidents*: alerts that belong together as one incident with a timeline; its open reminders can be
  dismissed together.
- An alert's details say which incident it belongs to and lead there. Open windows now follow every change: the
  details of an alert, the incidents and the alert history update themselves after each scan.
- Windows open at once also while a scan is running (before, a details window could take many seconds).
- Alert details use their space better: the story, the details and the risk assessment stand side by side when
  there is room. The right-click menu is drawn in the app's own look.

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
