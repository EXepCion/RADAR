"""Check for a new version: asks GitHub once a day, tells once per version, downloads nothing."""
from types import SimpleNamespace

import pytest

from radar import updates
from radar.updates import Release, UpdateChecker


def test_version_numbers_are_compared_as_numbers():
    assert updates.parse_version("v1.10.0") == (1, 10, 0) and updates.parse_version("2") == (2,)
    assert updates.parse_version("1.0.0-beta") == () and updates.parse_version("nightly") == () and updates.parse_version("") == ()
    assert updates.is_newer("1.10.0", "1.9.3") and updates.is_newer("v1.0.1", "1.0.0") and updates.is_newer("2", "1.9.9")
    assert not updates.is_newer("1.0.0", "1.0.0") and not updates.is_newer("1.0", "1.0.0") and not updates.is_newer("0.9.9", "1.0.0")
    assert not updates.is_newer("1.0.0-beta", "0.1.0") and not updates.is_newer("garbage", "1.0.0")


def reply(status=200, **data):
    return SimpleNamespace(status_code=status, json=lambda: data)


def test_latest_release_reads_the_tag_and_is_careful_about_what_it_gets():
    seen = {}

    def get(url, headers=None, timeout=None):
        seen.update(url=url, agent=headers["User-Agent"], timeout=timeout)
        return reply(tag_name="v9.2.0", html_url="https://github.com/EXepCion/RADAR/releases/tag/v9.2.0")

    assert updates.latest_release(get) == Release("9.2.0", "https://github.com/EXepCion/RADAR/releases/tag/v9.2.0")
    assert seen["url"] == updates.LATEST_URL and seen["agent"].startswith("RADAR/") and seen["timeout"] == 10
    # a link that does not lead to GitHub is not passed on: the releases page instead
    odd = updates.latest_release(lambda *a, **k: reply(tag_name="9.0.0", html_url="https://example.com/x"))
    assert odd == Release("9.0.0", updates.RELEASES_PAGE)
    assert updates.latest_release(lambda *a, **k: reply(tag_name="v9.0.0", prerelease=True)) is None
    assert updates.latest_release(lambda *a, **k: reply(tag_name="v9.0.0", draft=True)) is None
    assert updates.latest_release(lambda *a, **k: reply(tag_name="latest-build")) is None
    assert updates.latest_release(lambda *a, **k: reply(status=403)) is None            # rate limit
    assert updates.latest_release(lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))) is None


def checker(fetch, enabled=True):
    state = {"now": 0.0, "notified": "", "enabled": enabled, "fetches": 0}

    def counted():
        state["fetches"] += 1
        return fetch()

    c = UpdateChecker(enabled=lambda: state["enabled"], notified=lambda: state["notified"],
                      remember=lambda v: state.__setitem__("notified", v), fetch=counted, clock=lambda: state["now"])
    return c, state


def test_a_new_version_is_announced_once_and_stays_available():
    newer = Release("99.0.0", "https://github.com/EXepCion/RADAR/releases/tag/v99.0.0")
    c, state = checker(lambda: newer)
    assert not c.due()                                    # not right at the start
    state["now"] = updates.FIRST_CHECK_AFTER
    assert c.due() and c.check() == newer and c.available == newer and state["notified"] == "99.0.0"
    assert not c.due()                                    # next look: tomorrow
    state["now"] += updates.CHECK_EVERY
    assert c.due() and c.check() is None and c.available == newer  # same version: no second notification
    even_newer = Release("99.1.0", updates.RELEASES_PAGE)
    c._fetch = lambda: even_newer
    state["now"] += updates.CHECK_EVERY
    assert c.check() == even_newer                        # a further release is announced again


def test_no_news_no_network_and_switched_off():
    c, state = checker(lambda: Release(updates.__version__, updates.RELEASES_PAGE))
    state["now"] = updates.FIRST_CHECK_AFTER
    assert c.check() is None and c.available is None and state["notified"] == ""   # up to date
    c, state = checker(lambda: None)
    state["now"] = updates.FIRST_CHECK_AFTER
    assert c.check() is None and not c.due()
    state["now"] += updates.RETRY_AFTER                   # could not be found out: tried again in an hour, not a day
    assert c.due()
    c, state = checker(lambda: Release("99.0.0", updates.RELEASES_PAGE), enabled=False)
    state["now"] = 10 * updates.CHECK_EVERY
    assert not c.due() and c.check() is None and state["fetches"] == 0             # switched off: GitHub is never asked


def test_a_click_on_the_notification_runs_its_action():
    pytest.importorskip("pystray")
    from radar import tray as tray_module

    shown, clicks = [], []
    icon = SimpleNamespace(notify=lambda message, title: shown.append(message), on_balloon_click=None)
    t = tray_module.Tray(SimpleNamespace())
    t.icon = icon
    t.notify("RADAR 99 is available", on_click=lambda: clicks.append("page"))
    assert shown == ["RADAR 99 is available"] and callable(icon.on_balloon_click)
    icon.on_balloon_click()                               # what Windows triggers when the notification is clicked
    icon.on_balloon_click()                               # a second click does nothing more
    assert clicks == ["page"]
    t.notify("something else")                            # a notification without an action: a click does nothing
    icon.on_balloon_click()
    assert clicks == ["page"]
    # the icon's message handler passes the click on and leaves other messages to the library
    handled = []
    stand_in = SimpleNamespace(on_balloon_click=lambda: handled.append(1))
    assert tray_module._Icon._on_notify(stand_in, 0, tray_module.NIN_BALLOONUSERCLICK) is None and handled == [1]
