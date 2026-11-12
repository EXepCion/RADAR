"""Evidence of where a person is: device class, network class, rank, and which evidence decides."""
from datetime import timedelta

from conftest import T0, make_signin

from radar.plugins.signin_threats import presence as P

LAPTOP = dict(device_id="d1", device_name="LT-TOR-00101", os="Windows10", trust_type="Azure AD joined", compliant=True, managed=True)


def test_device_classes():
    assert P.device_class(make_signin(**LAPTOP)) == P.WORK_COMPUTER
    assert P.device_class(make_signin(device_id="m1", os="MacOs", trust_type="Azure AD registered", compliant=True, managed=True)) == P.WORK_COMPUTER
    assert P.device_class(make_signin(device_id="p1", os="Ios 27.2.0", trust_type="Azure AD registered", compliant=True, managed=True)) == P.MANAGED_MOBILE
    assert P.device_class(make_signin(device_id="p2", os="Android", trust_type="Azure AD registered")) == P.UNMANAGED  # registered only
    assert P.device_class(make_signin(os="Windows10", browser="Firefox 140")) == P.UNMANAGED  # did not identify itself
    # a cloud service acting for the user carries the device name but its own credential and address
    assert P.device_class(make_signin(client_credential="clientAssertion", app="Microsoft Teams Services", **LAPTOP)) == P.SERVICE
    assert P.device_class(make_signin(client_credential="clientSecret", **LAPTOP)) == P.SERVICE
    assert P.device_label(make_signin(**LAPTOP)) == "Work computer LT-TOR-00101"
    assert P.device_label(make_signin(os="Windows10", browser="Firefox 140")) == "Unidentified device (Windows10 / Firefox 140)"


def test_ranking_of_single_signins():
    def rank(s, trusted=False, nets=(), names=None):
        e = P.assess(s, trusted, set(nets), None, names)
        return (e.rank, e.precision) if e else None

    phone = dict(device_id="p1", os="Ios", trust_type="Azure AD registered", compliant=True, managed=True)
    assert rank(make_signin(**phone), trusted=True) == (1, "office")  # any real device in the office
    assert rank(make_signin(**LAPTOP)) == (2, "city")
    assert rank(make_signin(ip="198.51.100.10", **phone), nets={"198.51.100.0/24"}) == (3, "city")  # on the laptop's Wi-Fi
    assert rank(make_signin(os="Windows10")) == (4, "city_unconfirmed")
    assert rank(make_signin(ip="198.51.100.10", **phone)) == (5, "country")  # a phone on a network of its own
    assert rank(make_signin(asn=64999, **LAPTOP), names=lambda asn: "CELLCO-PART - Verizon Wireless") == (5, "country")  # tethered
    assert rank(make_signin(client_credential="clientAssertion", **LAPTOP)) is None  # a service is no evidence
    assert P.prefix("198.51.100.77") == "198.51.100.0/24" and P.prefix("2001:db8:1:2:3::9") == "2001:db8:1:2::/64"


def test_choose_one_place_per_device_then_the_best_device_within_the_hold_time():
    def ev(minutes, rank, precision, device_id="d1"):
        return P.Evidence(make_signin(minutes, device_id=device_id), P.WORK_COMPUTER, P.ISP, rank, precision)

    office, home = ev(0, 1, "office"), ev(50, 2, "city")
    assert P.choose([office, home])[0] is home  # the same laptop, later: it is where it is now
    proxy = ev(5, 6, "hidden")
    assert P.choose([office, proxy])[0] is office  # the same moment over two network paths: the better one
    phone = ev(30, 5, "country", device_id="p1")
    assert P.choose([office, phone])[0] is office  # the phone does not pull the person out of the office ...
    later = ev(75, 5, "country", device_id="p1")
    assert P.choose([office, phone, later])[0] is later  # ... until the laptop has been silent for over an hour
    hidden = ev(200, 6, "hidden")
    best, fallback = P.choose([office, hidden])
    assert best is hidden and fallback is office  # behind a VPN now: the last located evidence is kept as fallback
    assert P.choose([]) == (None, None)
    assert P.HOLD == timedelta(minutes=60) and T0


def test_impossible_travel_ignores_a_phone_on_mobile_data_but_not_a_vpn(history):
    """Laptop at home in Toronto, 40 minutes later the phone 'in Vienna' (its carrier's gateway): no journey. An unknown
    computer on a hosting network in Warsaw 20 minutes after that is one - measured from the laptop, not hidden by
    the phone sign-in in between."""
    from radar.plugins.signin_threats import netintel, rules
    from radar.plugins.signin_threats.rules import RuleContext

    home = dict(ip="198.51.100.80", asn=812, city="Toronto", country="CA", lat=43.65, lon=-79.38)
    laptop = make_signin(0, user_id="u1", **dict(LAPTOP, **home))
    phone = make_signin(30, user_id="u1", ip="192.0.2.150", asn=8447, city="Vienna", country="AT", lat=48.21, lon=16.37,
                        device_id="p1", os="Ios", trust_type="Azure AD registered")
    hosting = next(asn for asn, (_n, category) in netintel.KNOWN_ASNS.items() if category == "hosting")
    stranger = make_signin(60, user_id="u1", ip="203.0.113.200", asn=hosting, city="Warsaw", country="PL", lat=52.23, lon=21.01,
                           os="Windows10", browser="Rich Client 4.85")
    history.add([laptop, phone, stranger])

    def travel(new, **cfg):
        rc = RuleContext.build([new], history, {"impossible_travel": cfg}, T0 + timedelta(minutes=61))
        return rules.impossible_travel(rc)

    assert travel(phone) == []
    assert [f.rule_id for f in travel(phone, ignore_phone_networks=False)] == ["impossible_travel"]  # old behaviour, selectable
    found = travel(stranger)
    assert [f.rule_id for f in found] == ["impossible_travel"]
    assert "Toronto" in found[0].fields["From"] and "Warsaw" in found[0].fields["To"]  # from the laptop, past the phone


def test_the_computer_in_use_wins_over_one_that_only_runs_in_the_background():
    """Laptop in hands-on use at home, a Mac left on in the office syncing in the background: the person is at home."""
    def ev(minutes, rank, precision, device_id, os="Windows10"):
        return P.Evidence(make_signin(minutes, device_id=device_id, os=os), P.WORK_COMPUTER, P.ISP, rank, precision)

    laptop, office_mac = ev(100, 2, "city", "nb1"), ev(101, 1, "office", "mac1", os="MacOs")
    used = {"nb1": T0 + timedelta(minutes=30)}  # the laptop was signed in to by hand 70 minutes ago, the Mac never
    assert P.choose([laptop, office_mac])[0] is office_mac  # without knowing who is at which machine: the office
    assert P.choose([laptop, office_mac], hands_on=used)[0] is laptop
    # both in use (walked from the desk PC to the laptop in a meeting room): the office still wins
    assert P.choose([laptop, office_mac], hands_on={"nb1": T0, "mac1": T0})[0] is office_mac
    # a hand sign-in long ago does not count: yesterday's laptop session does not beat today's office PC
    assert P.choose([laptop, office_mac], hands_on={"nb1": T0 - timedelta(hours=20)})[0] is office_mac
    # a phone never pulls somebody out of the office by asking for a sign-in
    phone = P.Evidence(make_signin(102, device_id="p1", os="Ios"), P.MANAGED_MOBILE, P.ISP, 5, "country")
    office_pc = ev(100, 1, "office", "pc1")
    assert P.choose([office_pc, phone], hands_on={"p1": T0 + timedelta(minutes=102)})[0] is office_pc
    # a laptop behind a VPN is "in use" but has no place: it does not remove the office machine
    vpn_laptop = ev(100, 6, "hidden", "nb1")
    assert P.choose([vpn_laptop, office_mac], hands_on=used)[0] is office_mac
