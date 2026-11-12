"""Live sign-in map: an on-demand window that runs as a process of its own.

The tray app never imports this package. "Live map..." in the tray starts ``python -m radar.mapview``; that process
reads the data the app has already collected (sign-in history, account copy, settings), serves one local page to an
Edge app window and exits when the window is closed. Whatever happens here cannot slow down or crash the tray app.
"""
