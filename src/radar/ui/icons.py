"""Icons drawn with Pillow at 4x and downsampled (no image files to ship)."""
from __future__ import annotations

from functools import lru_cache

from PIL import Image, ImageDraw

from ..plugin_api import Severity

SEVERITY_RGB = {
    Severity.INFO: (0, 120, 212),
    Severity.LOW: (202, 160, 0),
    Severity.MEDIUM: (247, 99, 12),
    Severity.HIGH: (196, 43, 28),
}
STATE_RGB = {
    "ok": (16, 124, 16),
    "alert": (196, 43, 28),
    "warn": (234, 163, 0),
    "paused": (122, 122, 122),
    "busy": (0, 120, 212),
}
_SS = 4  # supersampling factor


def _canvas(size: int) -> tuple[Image.Image, ImageDraw.ImageDraw, float]:
    img = Image.new("RGBA", (size * _SS, size * _SS), (0, 0, 0, 0))
    return img, ImageDraw.Draw(img), size * _SS / 64.0


def _finish(img: Image.Image, size: int) -> Image.Image:
    return img.resize((size, size), Image.LANCZOS)


def _darker(rgb: tuple[int, int, int], f: float = 0.7) -> tuple[int, int, int]:
    return tuple(int(c * f) for c in rgb)  # type: ignore[return-value]


@lru_cache(maxsize=16)
def app_icon(size: int = 256) -> Image.Image:
    """RADAR's own icon: a radar scope - dark disc, range rings, the sweep, one red blip."""
    img, d, u = _canvas(size)
    navy, ring, sweep, blip = (13, 27, 42), (64, 201, 142), (64, 201, 142), (255, 92, 77)
    d.ellipse([2 * u, 2 * u, 62 * u, 62 * u], fill=navy + (255,), outline=(36, 62, 86, 255), width=max(1, int(1.5 * u)))
    glow = Image.new("RGBA", img.size, (0, 0, 0, 0))
    g = ImageDraw.Draw(glow)
    for i, step in enumerate(range(0, 70, 5)):  # the sweep fades out behind its leading edge
        g.pieslice([5 * u, 5 * u, 59 * u, 59 * u], start=-70 - step - 5, end=-70 - step, fill=sweep + (int(150 * (1 - i / 14)),))
    img.alpha_composite(glow)
    line = max(1, int((1.6 if size >= 32 else 2.4) * u))
    for r in ((27, 18, 9) if size >= 32 else (27, 14)):
        d.ellipse([(32 - r) * u, (32 - r) * u, (32 + r) * u, (32 + r) * u], outline=ring + (235,), width=line)
    if size >= 32:
        d.line([(32 * u, 5 * u), (32 * u, 59 * u)], fill=ring + (110,), width=max(1, int(0.9 * u)))
        d.line([(5 * u, 32 * u), (59 * u, 32 * u)], fill=ring + (110,), width=max(1, int(0.9 * u)))
    d.line([(32 * u, 32 * u), (41.2 * u, 6.6 * u)], fill=(170, 255, 214, 255), width=max(1, int(2.2 * u)))
    b = 4.2 if size >= 32 else 6
    d.ellipse([(44 - b) * u, (40 - b) * u, (44 + b) * u, (40 + b) * u], fill=blip + (255,))
    d.ellipse([29.5 * u, 29.5 * u, 34.5 * u, 34.5 * u], fill=(170, 255, 214, 255))
    return _finish(img, size)


def save_ico(path: str, sizes: tuple[int, ...] = (16, 20, 24, 32, 40, 48, 64, 128, 256)) -> None:
    """Write the app icon as a Windows .ico with every size drawn for itself (small ones are simplified)."""
    images = [app_icon(s) for s in sizes]
    images[-1].save(path, format="ICO", sizes=[(s, s) for s in sizes], append_images=images[:-1])


@lru_cache(maxsize=32)
def tray_icon(state: str, size: int = 64) -> Image.Image:
    """Shield with a state glyph: ok (check), alert (!), warn (!), paused (||), busy (dots)."""
    img, d, u = _canvas(size)
    color = STATE_RGB.get(state, STATE_RGB["ok"])
    shield = [(32, 2), (58, 10), (58, 30), (54, 43), (45, 53), (32, 62), (19, 53), (10, 43), (6, 30), (6, 10)]
    d.polygon([(x * u, y * u) for x, y in shield], fill=color + (255,), outline=_darker(color) + (255,))
    w = (255, 255, 255, 255)
    glyph_dark = (60, 40, 0, 255)
    if state == "ok":
        d.line([(19 * u, 32 * u), (28 * u, 41 * u), (45 * u, 21 * u)], fill=w, width=int(7 * u), joint="curve")
    elif state in ("alert", "warn"):
        g = glyph_dark if state == "warn" else w
        d.rounded_rectangle([28 * u, 13 * u, 36 * u, 38 * u], radius=3 * u, fill=g)
        d.ellipse([27.5 * u, 42 * u, 36.5 * u, 51 * u], fill=g)
    elif state == "paused":
        d.rounded_rectangle([22 * u, 18 * u, 29 * u, 44 * u], radius=2 * u, fill=w)
        d.rounded_rectangle([35 * u, 18 * u, 42 * u, 44 * u], radius=2 * u, fill=w)
    elif state == "busy":
        for cx in (20, 32, 44):
            d.ellipse([(cx - 4.5) * u, 27.5 * u, (cx + 4.5) * u, 36.5 * u], fill=w)
    return _finish(img, size)


@lru_cache(maxsize=32)
def bell(size: int = 32, severity: Severity | None = None) -> Image.Image:
    """Outlook-like reminder bell, optionally with a severity badge."""
    img, d, u = _canvas(size)
    gold, dark = (240, 186, 40, 255), (168, 118, 8, 255)
    d.ellipse([29 * u, 3 * u, 35 * u, 9 * u], fill=gold, outline=dark, width=max(1, int(u)))
    d.pieslice([15 * u, 7 * u, 49 * u, 41 * u], 180, 360, fill=gold, outline=dark, width=max(1, int(1.5 * u)))
    d.polygon([(15 * u, 24 * u), (49 * u, 24 * u), (52 * u, 44 * u), (57 * u, 50 * u), (7 * u, 50 * u),
               (12 * u, 44 * u)], fill=gold)
    d.line([(15 * u, 24 * u), (12 * u, 44 * u), (7 * u, 50 * u)], fill=dark, width=max(1, int(1.5 * u)))
    d.line([(49 * u, 24 * u), (52 * u, 44 * u), (57 * u, 50 * u)], fill=dark, width=max(1, int(1.5 * u)))
    d.rounded_rectangle([5 * u, 48 * u, 59 * u, 54 * u], radius=3 * u, fill=dark)
    d.ellipse([27 * u, 52 * u, 37 * u, 62 * u], fill=dark)
    if severity is not None:
        c = SEVERITY_RGB[severity] + (255,)
        d.ellipse([38 * u, 34 * u, 63 * u, 59 * u], fill=c, outline=(255, 255, 255, 255), width=int(3 * u))
        d.rounded_rectangle([48.5 * u, 39 * u, 52.5 * u, 50 * u], radius=1.5 * u, fill=(255, 255, 255, 255))
        d.ellipse([48.3 * u, 52 * u, 52.7 * u, 56 * u], fill=(255, 255, 255, 255))
    return _finish(img, size)


@lru_cache(maxsize=32)
def badge(severity: Severity, size: int = 44) -> Image.Image:
    """Fluent-style header badge: a translucent tinted rounded square (works on light and dark windows) with a
    shield and '!' in the severity colour."""
    img, d, u = _canvas(size)
    rgb = SEVERITY_RGB[severity]
    d.rounded_rectangle([0, 0, 64 * u - 1, 64 * u - 1], radius=12 * u, fill=rgb + (46,))
    shield = [(32, 12), (49, 18), (49, 31), (46, 40), (40, 47), (32, 53), (24, 47), (18, 40), (15, 31), (15, 18)]
    d.line([(x * u, y * u) for x, y in shield + shield[:1]], fill=rgb + (255,), width=int(3.5 * u), joint="curve")
    d.rounded_rectangle([30.2 * u, 22 * u, 33.8 * u, 36 * u], radius=1.8 * u, fill=rgb + (255,))
    d.ellipse([29.8 * u, 39.5 * u, 34.2 * u, 43.9 * u], fill=rgb + (255,))
    return _finish(img, size)


@lru_cache(maxsize=32)
def severity_dot(severity: Severity, size: int = 16) -> Image.Image:
    img, d, u = _canvas(size)
    c = SEVERITY_RGB[severity] + (255,)
    d.ellipse([12 * u, 12 * u, 52 * u, 52 * u], fill=c, outline=_darker(SEVERITY_RGB[severity]) + (255,),
              width=int(3 * u))
    return _finish(img, size)
