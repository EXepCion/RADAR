"""The reminder sound: played on the default playback device and only there, silent when that device is."""
import struct

from radar import audio
from radar.audio import OutputState

SPEAKERS = dict(device="Speakers (Realtek Audio)", device_id="{0.0.0.00000000}.{aaa}")
ELLIPSIS = chr(0x2026)


def test_silent_states():
    assert OutputState(available=True, muted=True, volume=0.8).silent
    assert OutputState(available=True, muted=False, volume=0.0).silent
    assert OutputState(available=False).silent  # no output device
    assert not OutputState(available=True, muted=False, volume=0.3).silent
    assert not OutputState(available=False, error="COM failure").silent  # unknown -> do not suppress


def test_state_names_the_default_device():
    assert OutputState(available=True, muted=True, volume=0.8, **SPEAKERS).describe_device() == "Speakers (Realtek Audio): muted"
    assert OutputState(available=True, volume=0.41, **SPEAKERS).describe_device() == "Speakers (Realtek Audio): on, volume 41%"
    long = OutputState(available=True, muted=True, device="Surface Omnisonic Speakers (3- SoundWire Audio)", device_id="x")
    assert long.describe_device() == "Surface Omnisonic Speakers (3- SoundWire Au" + ELLIPSIS + ": muted"  # fits the menu
    assert OutputState(available=False).describe_device() == "no output device"


def patch(monkeypatch, state, wave_device=3):
    played = []
    monkeypatch.setattr(audio, "output_state", lambda: state)
    monkeypatch.setattr(audio, "wave_device_for", lambda endpoint: wave_device if endpoint == state.device_id and endpoint else None)
    monkeypatch.setattr(audio, "_reminder_sound_files", lambda: ["a.wav"])
    monkeypatch.setattr(audio, "_play_on", lambda device, path: played.append((device, path)) or "")
    monkeypatch.setattr(audio.time, "sleep", lambda s: None)
    return played


def test_play_respects_mute_of_the_default_device(monkeypatch):
    played = patch(monkeypatch, OutputState(available=True, muted=True, volume=1.0, **SPEAKERS))
    assert audio.play_reminder(respect_mute=True) == (False, "Windows audio is muted (Speakers (Realtek Audio))")
    assert played == []
    assert audio.play_reminder(respect_mute=False)[0] is True  # asked to play anyway: on that device (Windows keeps it silent)
    assert played == [(3, "a.wav")]


def test_sound_goes_to_the_default_device_and_nowhere_else(monkeypatch):
    played = patch(monkeypatch, OutputState(available=True, muted=False, volume=0.5, **SPEAKERS), wave_device=3)
    assert audio.play_reminder() == (True, "played") and played == [(3, "a.wav")]  # the device that was checked
    # the default device cannot be addressed: no sound at all - never "whatever Windows picks"
    played = patch(monkeypatch, OutputState(available=True, muted=False, volume=0.5, **SPEAKERS), wave_device=None)
    assert audio.play_reminder() == (False, "the default playback device could not be addressed") and played == []
    # no playback device, and a state that cannot be read (devices changing): nothing is played on a guess
    played = patch(monkeypatch, OutputState(available=False))
    assert audio.play_reminder() == (False, "there is no playback device") and played == []
    played = patch(monkeypatch, OutputState(available=False, error="device invalidated"))
    assert audio.play_reminder()[0] is False and played == []
    # the mute could not be read but the device is known: played there (if it is muted, Windows keeps it silent)
    played = patch(monkeypatch, OutputState(available=False, error="GetMute failed", **SPEAKERS))
    assert audio.play_reminder() == (True, "played") and played == [(3, "a.wav")]


def test_wav_files_are_read_whatever_their_format(tmp_path):
    def wav(fmt, data, extra=b""):
        body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + extra + b"data" + struct.pack("<I", len(data)) + data
        return b"RIFF" + struct.pack("<I", len(body)) + body

    pcm = struct.pack("<HHIIHH", 1, 2, 48000, 192000, 4, 16)
    path = tmp_path / "pcm.wav"
    path.write_bytes(wav(pcm, bytes([1, 2, 3, 4]), extra=b"LIST" + struct.pack("<I", 4) + b"abcd"))  # with a chunk in between
    fmt, data = audio.read_wav(str(path))
    assert fmt == pcm + bytes(2) and data == bytes([1, 2, 3, 4])  # completed to the layout Windows expects
    adpcm = struct.pack("<HHIIHHH", 2, 1, 22050, 11155, 512, 4, 4) + bytes([0xF4, 0x03, 0x07, 0x00])  # the compressed Outlook sound
    path.write_bytes(wav(adpcm, b"xyz" * 10))
    fmt, data = audio.read_wav(str(path))
    assert fmt == adpcm and len(data) == 30
    path.write_bytes(b"not a wav")
    try:
        audio.read_wav(str(path))
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_real_output_state_is_readable():
    state = audio.output_state()  # real Core Audio call on this machine
    assert not state.error, state.error
    assert 0.0 <= state.volume <= 1.0
    if state.available:  # the default device has a name and can be addressed for playing
        assert state.device and state.device_id and audio.wave_device_for(state.device_id) is not None
