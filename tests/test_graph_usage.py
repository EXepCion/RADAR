"""How much RADAR asks of Microsoft Graph is counted: every request by what it asks for, and how often Graph answered
"too many requests" - so that a scan can say what it cost."""
import logging
from types import SimpleNamespace

from radar.graph import GraphClient


class Answers:
    """A session that answers from a list: (status, body, headers)."""

    def __init__(self, answers):
        self.answers, self.asked, self.headers = list(answers), [], {}

    def get(self, url, params=None, timeout=None, headers=None):
        self.asked.append(url)
        status, body, head = self.answers.pop(0)
        return SimpleNamespace(status_code=status, json=lambda: body, headers=head, url=url, text="", reason="")


def client(answers):
    graph = GraphClient(SimpleNamespace(get_token=lambda force_refresh=False: "token"))
    graph._session = Answers(answers)
    graph._sleep = lambda seconds: None
    return graph


def test_every_request_is_counted_by_what_it_asks_for():
    next_page = "https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=abc"
    graph = client([(200, {"value": [1], "@odata.nextLink": next_page}, {}), (200, {"value": [2]}, {}),
                    (200, {"value": []}, {}), (200, {"displayName": "x"}, {}), (200, {"value": []}, {})])
    assert list(graph.get_all("/beta/auditLogs/signIns", {"$top": "1000"})) == [1, 2]
    graph.get("/v1.0/auditLogs/directoryAudits")
    graph.get("/v1.0/groups/11111111-2222-4333-8444-555555555555")
    graph.get("/v1.0/users")
    assert dict(graph.asked) == {"auditLogs/signIns": 2, "auditLogs/directoryAudits": 1, "groups": 1, "users": 1}
    assert (graph.throttled, graph.waited) == (0, 0.0)
    assert graph.usage() == "5 requests to Microsoft Graph (auditLogs/signIns 2, auditLogs/directoryAudits 1, groups 1, users 1); at most 5 within 10 seconds"
    graph._times = [0.0, 1.0, 9.5, 10.5, 30.0]
    assert graph.busiest() == 3                      # (0, 1 and 9.5 - and 1, 9.5 and 10.5 - are within ten seconds)


def test_too_many_requests_is_counted_with_the_time_it_cost():
    graph = client([(429, {}, {"Retry-After": "22"}), (429, {}, {"Retry-After": "22"}), (200, {"value": []}, {})])
    graph.get("/beta/auditLogs/signIns")
    assert dict(graph.asked) == {"auditLogs/signIns": 3} and graph.throttled == 2 and graph.waited == 44.0
    assert graph.usage() == ("3 requests to Microsoft Graph (auditLogs/signIns 3); at most 3 within 10 seconds, 2 of them answered with 'too many requests' "
                             "(44 s waited)")
    assert client([]).usage() == ""       # nothing asked: nothing to say


def test_a_scan_says_what_it_asked_of_graph(tmp_path, monkeypatch, caplog):
    """After every run of a plugin - also one that failed - the log says how many requests it made."""
    monkeypatch.setenv("RADAR_HOME", str(tmp_path))
    from radar.app import App
    from radar.graph import GraphError

    app = App(demo=True)
    try:
        graphs = []

        def factory():
            graphs.append(client([(200, {"value": []}, {})] * 3 + [(429, {"error": {"code": "TooManyRequests", "message": "slow down"}}, {})] * 9))
            return graphs[-1]

        app.plugins._graph_factory = factory
        plugin_id = next(iter(app.plugins.runtimes))
        runtime = app.plugins.runtimes[plugin_id]

        def run(ctx):
            for _ in range(3):
                ctx.graph.get("/beta/auditLogs/signIns")
            return []

        monkeypatch.setattr(runtime.plugin, "run", run)
        with caplog.at_level(logging.INFO):
            app.plugins.run(plugin_id)
        assert f"{plugin_id}: 3 requests to Microsoft Graph (auditLogs/signIns 3); at most 3 within 10 seconds" in caplog.text
        caplog.clear()

        def fails(ctx):
            for _ in range(4):
                ctx.graph.get("/beta/auditLogs/signIns")
            return []

        monkeypatch.setattr(runtime.plugin, "run", fails)
        with caplog.at_level(logging.INFO):
            try:
                app.plugins.run(plugin_id)
            except GraphError as exc:
                assert exc.status == 429
        assert "9 requests to Microsoft Graph (auditLogs/signIns 9); at most 9 within 10 seconds, 6 of them answered with 'too many requests'" in caplog.text
    finally:
        app.store.close()
