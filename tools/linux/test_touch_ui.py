"""Run with Xvfb on Linux; never uses pkexec, system sockets or real devices."""
import os
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

from test_desktop import HERE, load


@unittest.skipUnless(os.environ.get("DISPLAY"), "requires an isolated X display")
class TouchUiTests(unittest.TestCase):
    def setUp(self):
        self.ui = load("localkey_touch", HERE / "localkey-touch")
        self.root = self.ui.tk.Tk(className=self.ui.WINDOW_CLASS)
        self.window = self.ui.TouchWindow(self.root)

    def tearDown(self):
        self.window.close()

    def test_desktop_launcher_matches_the_actual_tk_window_class(self):
        self.assertIn(f"StartupWMClass={self.root.winfo_class()}\n",
                      (HERE / "localkey-touch.desktop").read_text())

    def test_presence_enables_touch_but_never_sends_it_automatically(self):
        with patch.object(self.window, "send_tap") as sent:
            for message, state in [("presence idle", "disabled"), ("presence waiting", "normal"),
                                   ("presence idle", "disabled")]:
                self.window.events.put(("line", message))
                self.window.update()
                self.assertEqual(str(self.window.touch["state"]), state)
            sent.assert_not_called()

    def test_errors_and_disconnect_keep_touch_disabled(self):
        self.window.events.put(("line", "authentication refused"))
        self.window.update()
        self.assertEqual(str(self.window.touch["state"]), "disabled")
        self.window.events.put(("line", "presence waiting"))
        self.window.events.put(("end", "Disconnected"))
        self.window.update()
        self.assertEqual(str(self.window.touch["state"]), "disabled")
        self.assertEqual(str(self.window.connect["state"]), "normal")

    def test_a_rejected_touch_shows_the_control_reply(self):
        reply = CompletedProcess([], 1, stdout="error no pending presence or sensor unavailable\n", stderr="")
        with patch.object(self.ui.subprocess, "run", return_value=reply):
            self.window.send_tap()
        self.assertEqual(self.window.events.get_nowait(), ("tap", reply.stdout.strip()))
