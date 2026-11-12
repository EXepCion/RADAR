"""Windows open on the screen the mouse is on: the placement arithmetic (the screen lookup itself is Windows')."""
from radar import screens
from radar.mapview.__main__ import window_bounds

LEFT, RIGHT = (0, 0, 1536, 976), (2304, 0, 6144, 1552)  # two screens side by side, the right one larger


def test_window_is_centred_on_the_given_screen():
    assert screens.place(1400, 900, LEFT) == (68, 38, 1400, 900)
    x, y, w, h = screens.place(1400, 900, RIGHT)
    assert (w, h) == (1400, 900) and RIGHT[0] <= x and x + w <= RIGHT[2] and RIGHT[1] <= y and y + h <= RIGHT[3]
    assert x - RIGHT[0] == RIGHT[2] - (x + w)  # same room left and right


def test_window_never_exceeds_the_screen_and_can_sit_higher_up():
    assert screens.place(9000, 5000, LEFT) == (8, 8, 1520, 960)  # shrunk to the work area minus a margin
    _, y_mid, _, _ = screens.place(680, 520, LEFT)
    _, y_high, _, _ = screens.place(680, 520, LEFT, vertical=0.33)
    assert LEFT[1] < y_high < y_mid
    x, _, _, _ = screens.place(680, 520, (-1920, 0, 0, 1040))  # a screen left of the primary one: negative coordinates
    assert -1920 < x < -680


def test_map_window_gets_size_and_place_on_that_screen():
    assert window_bounds(None) == ["--window-size=1500,920"]  # screen unknown: the browser chooses the place
    assert window_bounds(RIGHT) == ["--window-size=1500,920", "--window-position=3474,316"]
    assert window_bounds((0, 0, 1280, 700)) == ["--window-size=1264,684", "--window-position=8,8"]


def test_a_window_goes_beside_the_always_on_top_one_when_the_screen_has_room():
    alert = (2900, 300, 696, 560)  # the reminder window on the large screen
    x, y = screens.beside(1180, 740, alert, RIGHT)
    assert (x, y) == (2900 + 696 + 12, 300) and not screens.overlap((x, y, 1180, 740), alert)   # right of it, tops lined up
    near_right_edge = (5400, 300, 696, 560)
    x, y = screens.beside(1180, 740, near_right_edge, RIGHT)
    assert x + 1180 + 12 == 5400 and not screens.overlap((x, y, 1180, 740), near_right_edge)    # no room right: left of it
    tall = (2400, 20, 3600, 500)                                                                # a very wide one: below it
    x, y = screens.beside(1180, 740, tall, RIGHT)
    assert y == 20 + 500 + 12 and not screens.overlap((x, y, 1180, 740), tall)
    assert screens.beside(1180, 740, (428, 150, 696, 560), LEFT) is None                         # small screen: no room anywhere
    assert screens.beside(3000, 2000, alert, LEFT) is None                                       # larger than the screen
    assert screens.overlap((0, 0, 10, 10), (5, 5, 10, 10)) and not screens.overlap((0, 0, 10, 10), (10, 0, 10, 10))
