import threading
import time

from radar.config import ConfigManager
from radar.scheduler import Scheduler


class FakeRuntime:
    def __init__(self, pid):
        self.plugin = type("P", (), {"id": pid})()


class FakePlugins:
    def __init__(self):
        self.enabled = {"a": True, "b": False}

    def ordered(self):
        return [FakeRuntime("a"), FakeRuntime("b")]

    def is_enabled(self, pid):
        return self.enabled[pid]

    def interval_seconds(self, pid):
        return 3600


class FakeApp:
    def __init__(self, tmp_path):
        self.stop_event = threading.Event()
        self.cfg = ConfigManager(tmp_path / "config.json")
        self.cfg.set("general", "startup_delay_seconds", value=0)
        self.cfg.set("general", "tick_seconds", value=5)
        self.plugins = FakePlugins()
        self.paused = False
        self.runs: list[str] = []
        self.ran = threading.Event()

    def on_tick(self):
        pass

    def run_plugin(self, pid):
        self.runs.append(pid)
        self.ran.set()
        return True


def test_scheduler_thread_runs_enabled_plugins_and_forced_runs(tmp_path):
    app = FakeApp(tmp_path)
    sched = Scheduler(app)
    sched.start()  # must not clash with threading.Thread internals
    try:
        sched.wake()
        assert app.ran.wait(5)
        assert app.runs == ["a"]  # b is disabled, a not due again for an hour
        app.ran.clear()
        sched.trigger("b")  # forced run works even for a disabled plugin
        assert app.ran.wait(5)
        assert app.runs == ["a", "b"]
        app.paused = True
        app.ran.clear()
        sched.trigger()  # "scan now" while paused still runs enabled plugins
        assert app.ran.wait(5)
        assert app.runs[-1] == "a"
    finally:
        app.stop_event.set()
        sched.wake()
        sched.join(5)
    assert not sched.is_alive()
