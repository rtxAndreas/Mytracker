import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

from charset import generate, resolve_charset
from auth_test import find_target_bssid, normalize_bssid, select_interface, try_password
from local_ui import build_audit_argv, build_command, detect_interfaces, detect_networks, render_page, validate_config


class Result:
    def __init__(self, ssid, bssid):
        self.ssid = ssid
        self.bssid = bssid


class FakeInterface:
    def __init__(self):
        self.scanned = False

    def name(self):
        return "test0"

    def scan(self):
        self.scanned = True

    def scan_results(self):
        return [Result("Lab", "AA-BB-CC-DD-EE-FF")]


class FakeWifi:
    def __init__(self):
        self.iface = FakeInterface()

    def interfaces(self):
        return [self.iface]


class FakeAuthInterface(FakeInterface):
    def __init__(self, bssid):
        super().__init__()
        self.bssid = bssid

    def disconnect(self):
        pass

    def connect(self, _profile):
        pass

    def status(self):
        return 1

    def associated_ap_info(self):
        return Result("Lab", self.bssid)


class OfflineTests(unittest.TestCase):
    def test_shared_charset_and_lazy_generation(self):
        self.assertEqual(resolve_charset("digit"), "0123456789")
        self.assertEqual(list(generate("ab", 1, 2)), ["a", "b", "aa", "ab", "ba", "bb"])


    def test_interface_is_selected_by_name(self):
        wifi = FakeWifi()
        self.assertIs(select_interface(wifi, "test0"), wifi.iface)


    def test_target_bssid_is_pinned_and_normalized(self):
        iface = FakeInterface()
        self.assertEqual(find_target_bssid(iface, "Lab", "aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff")
        self.assertTrue(iface.scanned)
        self.assertEqual(normalize_bssid("AA-BB"), "aa:bb")

    def test_connected_neighbour_is_not_reported_as_success(self):
        class Const:
            IFACE_CONNECTED = 1

        class Profile:
            key = ""

        iface = FakeAuthInterface("11:22:33:44:55:66")
        self.assertFalse(try_password(iface, Profile(), "secret", Const(), "aa:bb:cc:dd:ee:ff", 0.01))

    def test_ui_requires_authorization_and_builds_safe_preview(self):
        values = {
            "ssid": "Mon hotspot",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "interface": "wlan0",
            "charset": "alphanumeric",
            "min_length": "8",
            "max_length": "10",
            "limit": "100",
            "timeout": "5",
        }
        with self.assertRaises(ValueError):
            validate_config(values)
        values["authorized"] = "yes"
        command = build_command(validate_config(values))
        self.assertIn("--ssid 'Mon hotspot'", command)
        self.assertIn("--bssid AA:BB:CC:DD:EE:FF", command)
        argv = build_audit_argv(validate_config(values))
        self.assertIn("--charset", argv)
        self.assertNotIn("sh", argv)

    def test_ui_escapes_user_content(self):
        config = {
            "ssid": "<script>alert(1)</script>",
            "bssid": "",
            "interface": "wlan0",
            "charset": "digit",
            "min_length": "8",
            "max_length": "8",
            "limit": "10",
            "timeout": "5",
        }
        page = render_page(config).decode()
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_ui_detects_and_sorts_ssids_without_connecting(self):
        class Completed:
            stdout = "Lab:AA\\:BB\\:CC\\:DD\\:EE\\:FF:42:WPA2\nHotspot:11\\:22\\:33\\:44\\:55\\:66:91:WPA3\n"

        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return Completed()

        networks = detect_networks("wlan0", runner=runner)
        self.assertEqual([item["ssid"] for item in networks], ["Hotspot", "Lab"])
        self.assertIn("ifname", calls[0][0])
        self.assertNotIn("connect", calls[0][0])

    def test_ui_rejects_unsafe_interface_name(self):
        with self.assertRaises(ValueError):
            detect_networks("wlan0; reboot", runner=lambda *_args, **_kwargs: None)

    def test_ui_detects_wireless_interfaces(self):
        class Completed:
            stdout = "lo:loopback:connected\nwlp2s0:wifi:disconnected\neth0:ethernet:connected\n"

        interfaces = detect_interfaces(runner=lambda *_args, **_kwargs: Completed())
        self.assertEqual(interfaces, [{"name": "wlp2s0", "state": "disconnected"}])
