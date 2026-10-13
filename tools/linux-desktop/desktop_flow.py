#!/usr/bin/python3
"""Real session, real browsers and real UHID; fixture credentials stay in the VM."""
import json
import os
import platform
from pathlib import Path
import subprocess
import time
import traceback

from PIL import Image
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService

RESULTS = Path("/localkey/results")
PASSWORD = "localkey-test-only"
PIN = "12345678"
CHECKS = []
REBOOT = RESULTS / "reboot.json"


def run(*args, check=True, input=None, timeout=120):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args}: exit {result.returncode}: {result.stdout} {result.stderr}")
    return result


def sudo(*args, check=True):
    return run("sudo", "-S", "-p", "", *args, input=PASSWORD + "\n", check=check)


def wait(predicate, description, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.25)
    screenshot("timeout")
    raise TimeoutError(description)


def screenshot(name):
    run("scrot", "-o", str(RESULTS / f"{name}.png"), check=False)


def window(pattern, field="--name"):
    result = run("xdotool", "search", "--onlyvisible", field, pattern, check=False)
    return result.stdout.splitlines()[-1] if result.returncode == 0 and result.stdout.strip() else None


def connect_window(identifier):
    # While disconnected, Connect is the only enabled button; labels may wrap.
    run("xdotool", "windowactivate", "--sync", identifier)
    run("xdotool", "key", "Tab", "space")
    def watcher_ready():
        return run("pgrep", "-u", "0", "-f",
                   "^/usr/bin/python3 -I /usr/local/libexec/localkey-control watch$", check=False).returncode == 0
    state = wait(lambda: window("Authentication") or watcher_ready(), "touch connection did not start")
    authenticated = isinstance(state, str)
    if authenticated:
        screenshot("polkit-authentication")
        run("xdotool", "windowactivate", "--sync", state)
        run("xdotool", "type", "--clearmodifiers", PASSWORD)
        run("xdotool", "key", "Return")
        wait(watcher_ready, "authenticated touch watcher did not start")
        record("native polkit authentication completed")
    return authenticated


def presence():
    result = sudo("localkeyd", "ctl", "--control", "/var/lib/localkey/control.sock", "status", check=False)
    return "presence=waiting\n" in result.stdout


def record(name, **details):
    entry = {"check": name, "passed": True, **details}
    CHECKS.append(entry)
    print(json.dumps(entry), flush=True)
    (RESULTS / "checks.json").write_text(json.dumps(CHECKS, indent=2) + "\n")
    serial = "ttyS0" if platform.machine() == "x86_64" else "ttyAMA0"
    sudo("python3", "-c", "import sys; open(sys.argv[1], 'w').write(sys.argv[2] + '\\n')",
         f"/dev/{serial}", json.dumps(entry))


def session_denials():
    session_id = os.environ["XDG_SESSION_ID"]
    vt = run("loginctl", "show-session", session_id, "-p", "VTNr", "--value").stdout.strip()
    assert int(vt) > 0
    try:
        sudo("chvt", "2" if vt != "2" else "3")
        wait(lambda: run("loginctl", "show-session", session_id, "-p", "Active", "--value").stdout.strip() == "no",
             "desktop session did not become inactive")
        refused = run("pkexec", "--disable-internal-agent", "/usr/local/libexec/localkey-control", "status", check=False)
        assert refused.returncode != 0 and "Not authorized" in refused.stderr, refused
        state = run("loginctl", "show-session", session_id, "-p", "Active", "-p", "Remote", "-p", "Seat").stdout
        record("polkit denies the actual inactive local desktop session", session=state, exit=refused.returncode)
    finally:
        sudo("chvt", vt)
    wait(lambda: run("loginctl", "show-session", session_id, "-p", "Active", "--value").stdout.strip() == "yes",
         "desktop session did not reactivate")
    # SSH is loopback-only inside the NIC-free VM, with real sshd/PAM/logind.
    sudo("systemctl", "start", "ssh.service")
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/home/lkdesktop/.ssh/id_ed25519")
    Path("/home/lkdesktop/.ssh/authorized_keys").write_bytes(Path("/home/lkdesktop/.ssh/id_ed25519.pub").read_bytes())
    Path("/home/lkdesktop/.ssh/authorized_keys").chmod(0o600)
    remote = run("ssh", "-o", "StrictHostKeyChecking=no", "lkdesktop@127.0.0.1",
                 'loginctl show-session "$XDG_SESSION_ID" -p Active -p Remote -p Seat; '
                 'pkexec --disable-internal-agent /usr/local/libexec/localkey-control status', check=False)
    assert "Remote=yes" in remote.stdout and remote.returncode != 0 and "Not authorized" in remote.stderr, remote
    record("polkit denies a real SSH remote session", session=remote.stdout.strip(), exit=remote.returncode)
    sudo("systemctl", "stop", "ssh.service")


def record_versions():
    versions = run("dpkg-query", "-W", "systemd", "lightdm", "chromium", "firefox-esr", "python3-fido2").stdout
    (RESULTS / "versions.txt").write_text(versions + run("uname", "-a").stdout)


def create_drivers():
    drivers = {}
    chrome_options = webdriver.ChromeOptions()
    chrome_options.binary_location = "/usr/bin/chromium"
    chrome_options.add_argument("--no-first-run")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--user-data-dir=/tmp/localkey-chromium-profile")
    drivers["chromium"] = webdriver.Chrome(service=ChromeService("/usr/bin/chromedriver", log_output=str(RESULTS / "chrome.log")), options=chrome_options)
    firefox_options = webdriver.FirefoxOptions()
    firefox_options.binary_location = "/usr/bin/firefox-esr"
    drivers["firefox"] = webdriver.Firefox(service=FirefoxService("/usr/local/bin/geckodriver", log_output=str(RESULTS / "gecko.log")),
                                            options=firefox_options)
    return drivers


def main():
    global CHECKS
    assert os.geteuid() != 0
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    session = run("loginctl", "show-session", os.environ["XDG_SESSION_ID"],
                  "-p", "Active", "-p", "Remote", "-p", "Type", "-p", "Seat").stdout
    print(session, flush=True)
    assert "Active=yes" in session and "Remote=no" in session and "Seat=seat0" in session
    rebooted = REBOOT.exists()
    if rebooted:
        CHECKS = json.loads((RESULTS / "checks.json").read_text())
        before = json.loads(REBOOT.read_text())
        assert before["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        assert before["key_hash"] == sudo("sha256sum", "/etc/localkey/storage.key").stdout.split()[0]
        assert before["records"] == sudo("sh", "-c", "sha256sum /var/lib/localkey/*.rec").stdout
        assert before["rp_hash"] == run("sha256sum", "/home/lkdesktop/localkey-rp-state.json").stdout.split()[0]
        record("full reboot preserves key, sealed records and the same relying-party credentials/counters",
               previous_boot=before["boot_id"], boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    sudo("sh", "-c", "printf '127.0.0.1 localhost\\n127.0.1.1 localkey-desktop\\n::1 localhost\\n' > /etc/hosts")
    sudo("ip", "link", "set", "dev", "lo", "up")
    sudo("date", "-u", "-s", "2026-10-12 08:00:00")
    record_versions()
    if not rebooted:
        run("python3", "/localkey/test_rp.py")
        run("tar", "-xzf", "/localkey/bundle.tar.gz", "-C", "/tmp")
        bundle = next(Path("/tmp").glob("localkey-*-musl"))
        sudo(str(bundle / "install.sh"), "install", "--development")
    wait(lambda: sudo("localkeyd", "ctl", "--control", "/var/lib/localkey/control.sock", "status", check=False).returncode == 0,
         "installed service never became ready")
    assert sudo("systemctl", "is-active", "localkeyd.service").stdout.strip() == "active"
    def user_tokens():
        tokens = run("fido2-token", "-L").stdout
        return tokens if "localkey" in tokens else None
    tokens = wait(user_tokens, "own HID device did not become accessible to the desktop user")
    record("automatic service startup and user HID access" if rebooted else "real systemd install and user HID access",
           session=session, tokens=tokens)

    rp = subprocess.Popen(["python3", "/localkey/rp.py"], stdout=open(RESULTS / "rp.log", "w"), stderr=subprocess.STDOUT)
    touch = subprocess.Popen(["localkey-touch"], stdout=open(RESULTS / "touch.log", "w"), stderr=subprocess.STDOUT)
    wait(lambda: window("localkey.*Touch"), "touch window not shown")
    touch_window = window("localkey.*Touch")
    screenshot("touch-before-connect")
    assert connect_window(touch_window), "a fresh session must require administrator authentication"
    time.sleep(2)
    screenshot("touch-connected")
    record("desktop polkit administrator authentication")
    if not rebooted:
        session_denials()
    assert run("/usr/local/libexec/localkey-control", "status", check=False).returncode != 0
    assert run("cat", "/etc/localkey/storage.key", check=False).returncode != 0
    assert run("ls", "/var/lib/localkey", check=False).returncode != 0
    refused = sudo("/usr/local/libexec/localkey-control", "tap", check=False)
    assert refused.returncode != 0 and "no pending presence" in refused.stdout, refused
    record("unprivileged key/state/helper access and idle touch refused")
    sudo("systemd-run", "--quiet", "--unit=localkey-polkit-denied", "--uid=lkdesktop",
         "--property=StandardOutput=file:/localkey/results/polkit-denied.log",
         "--property=StandardError=file:/localkey/results/polkit-denied.log",
         "python3", "-c", "import subprocess; raise SystemExit(subprocess.call("
         "['pkexec', '--disable-internal-agent', '/usr/local/libexec/localkey-control', 'status']))")
    wait(lambda: sudo("systemctl", "show", "localkey-polkit-denied", "-p", "SubState", "--value").stdout.strip()
         in {"dead", "failed"}, "non-session polkit check did not finish")
    assert "Not authorized" in (RESULTS / "polkit-denied.log").read_text()
    record("polkit denies a process outside a local desktop session")

    drivers = create_drivers()
    for browser, driver in drivers.items():
        driver.set_page_load_timeout(60)
        driver.get("http://localhost:8000")
        field = driver.find_element(By.ID, "user")
        field.clear()
        field.send_keys(browser + "-pin" if rebooted else browser)
        if rebooted:
            driver.find_element(By.ID, "required").click()
            operation(driver, browser + "-after-reboot", "login", touch_window, pin=True)
            driver.find_element(By.ID, "discoverable").click()
            operation(driver, browser + "-account-after-reboot", "login", touch_window, pin=True, discoverable=True)
            driver.quit()
            continue
        operation(driver, browser, "register", touch_window)
        operation(driver, browser, "login", touch_window)
        # Native Chromium prompts block later WebDriver commands until dismissed.
        driver.execute_script("setTimeout(() => controller.abort(), 5000)")
        driver.find_element(By.ID, "login").click()
        wait(presence, "cancel test did not request presence")
        wait(lambda: not presence(), "cancelled browser request kept presence pending")
        wait(lambda: driver.find_element(By.ID, "result").text != "Waiting", "cancel did not finish")
        cancelled = json.loads(driver.find_element(By.ID, "result").text)
        assert not cancelled["ok"] and cancelled["name"] in {"AbortError", "NotAllowedError"}, cancelled
        refused = sudo("/usr/local/libexec/localkey-control", "tap", check=False)
        assert refused.returncode != 0 and "no pending presence" in refused.stdout, refused
        record(f"{browser} cancellation retires presence and late touch is refused", error=cancelled["name"])
        driver.find_element(By.ID, "login").click()
        wait(presence, "timeout test did not request presence")
        started = time.monotonic()
        wait(lambda: not presence(), "authenticator presence did not expire", timeout=45)
        elapsed = time.monotonic() - started
        assert elapsed >= 25, "presence ended before the authenticator timeout"
        refused = sudo("/usr/local/libexec/localkey-control", "tap", check=False)
        assert refused.returncode != 0 and "no pending presence" in refused.stdout, refused
        screenshot(f"{browser}-timeout")
        # Chromium keeps its retry/cancel dialog after the CTAP timeout.
        run("xdotool", "key", "Escape")
        wait(lambda: driver.find_element(By.ID, "result").text != "Waiting", "timeout dialog did not finish")
        expired = json.loads(driver.find_element(By.ID, "result").text)
        assert not expired["ok"] and expired["name"] == "NotAllowedError", expired
        record(f"{browser} presence timeout and late touch refusal", seconds=round(elapsed, 2))

    if rebooted:
        touch.terminate()
        rp.terminate()
        record("desktop flow complete including full reboot")
        return False

    # Set a fixture PIN through the native HID client, then use browser PIN dialogs.
    run("python3", "-c", "from fido2.hid import CtapHidDevice; from fido2.ctap2 import Ctap2; "
        "from fido2.ctap2.pin import ClientPin; d=next(CtapHidDevice.list_devices()); c=Ctap2(d); "
        f"c.info.options['clientPin'] or ClientPin(c).set_pin('{PIN}'); d.close()")
    for browser, driver in drivers.items():
        field = driver.find_element(By.ID, "user")
        field.clear()
        field.send_keys(browser + "-pin")
        driver.find_element(By.ID, "required").click()
        operation(driver, browser + "-pin", "register", touch_window, pin=True)
        operation(driver, browser + "-pin", "login", touch_window, pin=True)

    for browser, driver in drivers.items():
        driver.find_element(By.ID, "discoverable").click()
        operation(driver, browser + "-account", "login", touch_window, pin=True, discoverable=True)
        driver.find_element(By.ID, "discoverable").click()

    sudo("systemctl", "stop", "localkeyd.service")
    sudo("cp", "-a", "/etc/localkey", "/root/localkey-key-backup")
    sudo("cp", "-a", "/var/lib/localkey", "/root/localkey-state-backup")
    before_key = sudo("sha256sum", "/etc/localkey/storage.key").stdout.split()[0]
    sudo(str(bundle / "install.sh"), "install", "--development")
    assert before_key == sudo("sha256sum", "/etc/localkey/storage.key").stdout.split()[0]
    record("upgrade preserves storage key")

    # Reconnect after the service restart; the old watch ends by design.
    connect_window(touch_window)
    time.sleep(2)
    for browser, driver in drivers.items():
        operation(driver, browser + "-after-upgrade", "login", touch_window, pin=True)

    # Refresh after the acknowledged logins so restore cannot rewind the RP's counter.
    sudo("systemctl", "stop", "localkeyd.service")
    sudo("rm", "-rf", "/root/localkey-key-backup", "/root/localkey-state-backup")
    sudo("cp", "-a", "/etc/localkey", "/root/localkey-key-backup")
    sudo("cp", "-a", "/var/lib/localkey", "/root/localkey-state-backup")

    sudo(str(bundle / "install.sh"), "uninstall")
    assert sudo("test", "-f", "/etc/localkey/storage.key").returncode == 0
    assert sudo("test", "-d", "/var/lib/localkey").returncode == 0
    assert sudo("systemctl", "is-active", "localkeyd.service", check=False).returncode != 0
    record("uninstall keeps original key and records")
    sudo(str(bundle / "install.sh"), "install", "--development")
    sudo("systemctl", "stop", "localkeyd.service")
    sudo("mv", "/etc/localkey/storage.key", "/root/localkey-saved.key")
    refused = sudo(str(bundle / "install.sh"), "install", "--development", check=False)
    assert refused.returncode != 0 and "Restore the original key" in refused.stderr, refused
    assert sudo("test", "-e", "/etc/localkey/storage.key", check=False).returncode != 0
    sudo("mv", "/root/localkey-saved.key", "/etc/localkey/storage.key")
    record("missing storage key refuses reinstall without generating a replacement")
    sealed_hashes = sudo("sh", "-c", "sha256sum /var/lib/localkey/*.rec").stdout
    sudo("mv", "/etc/localkey/storage.key", "/root/localkey-saved.key")
    sudo("localkeyd", "keygen", "--key-file", "/etc/localkey/storage.key")
    refused = sudo("localkeyd", "run", "--state", "/var/lib/localkey",
                   "--key-file", "/etc/localkey/storage.key", check=False)
    assert refused.returncode == 3, refused
    assert sealed_hashes == sudo("sh", "-c", "sha256sum /var/lib/localkey/*.rec").stdout
    sudo("rm", "/etc/localkey/storage.key")
    sudo("mv", "/root/localkey-saved.key", "/etc/localkey/storage.key")
    record("wrong storage key refuses startup with sealed records unchanged")
    # All paths are inside this disposable VM; use the matched stopped backup.
    sudo("rm", "-rf", "/etc/localkey", "/var/lib/localkey")
    sudo("cp", "-a", "/root/localkey-key-backup", "/etc/localkey")
    sudo("cp", "-a", "/root/localkey-state-backup", "/var/lib/localkey")
    sudo("systemctl", "start", "localkeyd.service")
    assert before_key == sudo("sha256sum", "/etc/localkey/storage.key").stdout.split()[0]
    connect_window(touch_window)
    time.sleep(2)
    for browser, driver in drivers.items():
        operation(driver, browser + "-after-restore", "login", touch_window, pin=True)
        driver.quit()
    record("recent matched backup restore and both browser logins")
    touch.terminate()
    rp.terminate()
    rp.wait(timeout=10)
    sudo("systemctl", "stop", "localkeyd.service")
    REBOOT.write_text(json.dumps({"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                                 "key_hash": sudo("sha256sum", "/etc/localkey/storage.key").stdout.split()[0],
                                 "records": sudo("sh", "-c", "sha256sum /var/lib/localkey/*.rec").stdout,
                                 "rp_hash": run("sha256sum", "/home/lkdesktop/localkey-rp-state.json").stdout.split()[0]}))
    record("full reboot requested after acknowledged browser logins")
    return True


def operation(driver, name, action, touch_window, pin=False, discoverable=False):
    browser_class = "firefox" if driver.capabilities["browserName"] == "firefox" else "chromium"
    identifier = wait(lambda: window(browser_class, "--class"), "browser window not found")
    run("xdotool", "windowactivate", "--sync", identifier)
    driver.find_element(By.ID, action).click()
    if pin:
        time.sleep(3)
        screenshot(f"{name}-{action}-pin")
        run("xdotool", "type", "--clearmodifiers", PIN)
        run("xdotool", "key", "Return")
    wait(presence, f"{name} {action}: HID presence not requested")
    time.sleep(.5)  # Let the user-session watch update the enabled button.
    screenshot(f"{name}-{action}-waiting")
    run("xdotool", "windowactivate", "--sync", touch_window)
    run("xdotool", "key", "Tab", "space")
    time.sleep(1)
    run("xdotool", "windowactivate", "--sync", identifier)
    screenshot(f"{name}-{action}-after-touch")
    if browser_class == "firefox" and (action == "register" or discoverable):
        # shortcut: fixed English Firefox doorhanger coordinates; recalibrate after browser UI changes.
        prompt = f"{name}-attestation" if action == "register" else f"{name}-account-picker"
        def prompt_visible():
            screenshot(prompt)
            red, green, blue = Image.open(RESULTS / f"{prompt}.png").convert("RGB").getpixel(
                (625, 254 if action == "register" else 175))
            return red < 100 and 80 < green < 180 and blue > 180
        wait(prompt_visible, "Firefox native permission/account picker did not appear")
        if action == "register":
            run("xdotool", "mousemove", "647", "264", "click", "1")
        else:
            run("xdotool", "mousemove", "495", "183", "click", "1")
    elif discoverable:
        time.sleep(2)
        screenshot(f"{name}-account-picker")
        run("xdotool", "key", "Return")
    wait(lambda: driver.find_element(By.ID, "result").text != "Waiting", f"{name} {action}: browser did not finish")
    result = json.loads(driver.find_element(By.ID, "result").text)
    assert result.get("ok"), result
    if pin:
        assert result["flags"] & 4, "browser result must have user verification"
    if discoverable:
        assert result["discoverable"] and result["user_handle"] in {"chromium-pin", "firefox-pin"}, result
    screenshot(f"{name}-{action}-verified")
    record(f"{name} {action} verified by relying party", **result)


def execute():
    success = False
    reboot = False
    try:
        reboot = main()
        success = True
    except Exception:
        screenshot("failure")
        traceback.print_exc()
    finally:
        (RESULTS / "result.json").write_text(json.dumps({"passed": success and not reboot, "checks": CHECKS}, indent=2) + "\n")
        journal = sudo("journalctl", "-b", "-u", "localkeyd.service", "--no-pager", check=False)
        (RESULTS / ("journal-before-reboot.log" if reboot else "journal.log")).write_text(journal.stdout + journal.stderr)
        kernel = sudo("journalctl", "-k", "-b", "--no-pager", check=False)
        (RESULTS / ("kernel-before-reboot.log" if reboot else "kernel.log")).write_text(kernel.stdout + kernel.stderr)
        marker = "===== LK-DESKTOP-REBOOT =====" if success and reboot else (
                 "===== LK-DESKTOP-END rc=0 =====" if success else "===== LK-DESKTOP-END rc=1 =====")
        serial = "ttyS0" if platform.machine() == "x86_64" else "ttyAMA0"
        sudo("sh", "-c", f"echo '{marker}' > /dev/{serial}", check=False)
        sudo("systemctl", "reboot" if success and reboot else "poweroff", check=False)


if __name__ == "__main__":
    execute()
