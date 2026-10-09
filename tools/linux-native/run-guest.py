#!/usr/bin/env python3
"""Boot real distro kernel under local QEMU and require a complete native report."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import traceback
from pathlib import Path

directory = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--artifacts", type=Path, default=directory / "artifacts")
parser.add_argument("--image", default="ske-linux-native:0.36")
parser.add_argument("--revalidate-console-sha256", help="Recheck an existing real execution after a host-gate correction; requires its exact console hash and saved zero runner exit")
parser.add_argument("--expect-extra", action="store_true")
parser.add_argument("--expect-composite", action="store_true")
args = parser.parse_args()
artifacts = args.artifacts.resolve()
log_path = artifacts / "linux-native-console.log"
command = [
    "docker",
    "run",
    "--rm",
    "--network",
    "none",
    "--name",
    "ske-linux-native-guest",
    "--mount",
    f"type=bind,source={artifacts},target=/artifacts,readonly",
    args.image,
    "timeout",
    "--kill-after=10s",
    "1800s",
    "qemu-system-aarch64",
    "-machine",
    "virt",
    "-cpu",
    "cortex-a72",
    "-accel",
    "tcg",
    "-m",
    "4096",
    "-smp",
    "2",
    "-kernel",
    "/artifacts/guest-kernel",
    "-initrd",
    "/artifacts/guest-initramfs.gz",
    "-append",
    "console=ttyAMA0 rdinit=/init panic=1",
    "-nic",
    "none",
    "-display",
    "none",
    "-serial",
    "stdio",
    "-monitor",
    "none",
    "-no-reboot",
]
if args.revalidate_console_sha256:
    prior_path=artifacts/'linux-native-host-gate-failure.json'
    prior=json.loads(prior_path.read_text())
    assert prior['runner_exit']==0,'saved real execution did not exit successfully'
    assert hashlib.sha256(log_path.read_bytes()).hexdigest()==args.revalidate_console_sha256,'captured real console hash changed'
    runner_exit=prior['runner_exit']
else:
    with log_path.open("wb") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
    runner_exit=result.returncode

console = log_path.read_text(errors="replace")
report = {
    "passed": False,
    "runner_exit": runner_exit,
    "native_uhid_registration_verified": False,
}
try:
    start, end = "SKE_NATIVE_RESULT_BEGIN", "SKE_NATIVE_RESULT_END"
    assert console.count(start) == 1 and console.count(end) == 1
    report = json.loads(console.split(start, 1)[1].split(end, 1)[0].strip())
    report.update(runner_exit=runner_exit,console_sha256=hashlib.sha256(log_path.read_bytes()).hexdigest())
    if args.expect_extra:
        extra_start, extra_end = "SKE_NATIVE_EXTRA_BEGIN", "SKE_NATIVE_EXTRA_END"
        assert console.count(extra_start) == 1 and console.count(extra_end) == 1
        report["extra"] = json.loads(
            console.split(extra_start, 1)[1].split(extra_end, 1)[0].strip()
        )
        assert report["extra"].get("passed") is True, report["extra"].get("error")
        assert all(
            report["extra"].get(key) is True
            for key in (
                "native_linux_otp_feature_verified",
                "native_linux_keyboard_evdev_verified",
                "native_linux_pcsc_resource_manager_verified",
            )
        )
    if args.expect_composite:
        start_usb, end_usb = "SKE_USB_RESULT_BEGIN", "SKE_USB_RESULT_END"
        start_extra, end_extra = "SKE_USB_EXTRA_BEGIN", "SKE_USB_EXTRA_END"
        assert all(
            console.count(marker) == 1
            for marker in [start_usb, end_usb, start_extra, end_extra]
        )
        composite = json.loads(
            console.split(start_usb, 1)[1].split(end_usb, 1)[0].strip()
        )
        composite["extra"] = json.loads(
            console.split(start_extra, 1)[1].split(end_extra, 1)[0].strip()
        )
        assert composite.get("passed") and composite.get(
            "native_linux_composite_usb_verified"
        )
        assert composite["test_count"] == len(composite["tests"]) == 75
        assert all(
            item["passed"] for item in composite["tests"] + composite["extra_checks"]
        )
        assert composite["extra"].get("passed"), composite["extra"].get("error")
        assert composite["extra"]["test_count"] == len(composite["extra"]["tests"])
        assert all(item["passed"] for item in composite["extra"]["tests"])
        assert all(
            composite["extra"].get(key)
            for key in [
                "native_linux_usb_otp_sdk_verified",
                "native_linux_usb_keyboard_verified",
                "native_linux_usb_ccid_pcsc_verified",
            ]
        )
        assert (
            composite["extra"]["native_pcsc"]["sdk_atr_transport_classification"]
            == "USB"
        )
        reboot_start, reboot_end = "SKE_USB_REBOOT_BEGIN", "SKE_USB_REBOOT_END"
        assert console.count(reboot_start) == console.count(reboot_end) == 1
        reboot = json.loads(
            console.split(reboot_start, 1)[1].split(reboot_end, 1)[0].strip()
        )
        assert reboot.get("passed"), reboot.get("error")
        assert reboot["test_count"] == len(reboot["tests"])
        assert all(item["passed"] for item in reboot["tests"])
        assert all(
            reboot.get(key)
            for key in [
                "native_linux_usb_configuration_reenumeration_verified",
                "native_linux_usb_all_interface_combinations_verified",
                "native_linux_usb_reboot_volatile_state_verified",
                "requested_endpoint_addresses_all_profiles_verified",
                "reference_descriptor_equivalence_verified",
            ]
        )
        assert len(reboot["enumerations"]) == 9
        composite["reboot"] = reboot
        state_start, state_end = 'SKE_USB_STATE_BEGIN', 'SKE_USB_STATE_END'
        assert console.count(state_start) == console.count(state_end) == 1
        usb_state = json.loads(console.split(state_start, 1)[1].split(state_end, 1)[0].strip())
        state_spec = importlib.util.spec_from_file_location('usb_state_gate', directory / 'validate-usb-state.py')
        state_gate = importlib.util.module_from_spec(state_spec)
        state_spec.loader.exec_module(state_gate)
        state_gate.validate(usb_state)
        # Reports can embed previous dmesg text. Count actual console kernel
        # lines in this test's interval, not copies inside serialized reports.
        state_console=console.split('SKE_USB_REBOOT_END',1)[1].split('SKE_USB_STATE_END',1)[0]
        assert len(re.findall(r'^\[[^\n]+\] usb [^\n]+: reset full-speed USB device',state_console,re.M))==4
        assert usb_state['controller'] == composite['controller']
        for name, key in [('swpasskeyd', 'emulator_binary_sha256'), ('ske-usbd', 'usb_bridge_binary_sha256')]:
            assert usb_state[key] == hashlib.sha256((artifacts / 'build' / name).read_bytes()).hexdigest()
        report['usb_state'] = usb_state
        power_start,power_end='SKE_USB_POWER_BEGIN','SKE_USB_POWER_END'
        assert console.count(power_start)==console.count(power_end)==1
        usb_power=json.loads(console.split(power_start,1)[1].split(power_end,1)[0].strip())
        power_spec=importlib.util.spec_from_file_location('usb_power_gate',directory/'validate-usb-power.py')
        power_gate=importlib.util.module_from_spec(power_spec);power_spec.loader.exec_module(power_gate)
        power_gate.validate(usb_power)
        assert usb_power['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert usb_power[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        report['usb_power']=usb_power
        interrupt_start,interrupt_end='SKE_USB_INTERRUPT_BEGIN','SKE_USB_INTERRUPT_END'
        assert console.count(interrupt_start)==console.count(interrupt_end)==1
        usb_interrupt=json.loads(console.split(interrupt_start,1)[1].split(interrupt_end,1)[0].strip())
        interrupt_spec=importlib.util.spec_from_file_location('usb_interrupt_gate',directory/'validate-usb-interrupt.py')
        interrupt_gate=importlib.util.module_from_spec(interrupt_spec);interrupt_spec.loader.exec_module(interrupt_gate)
        interrupt_gate.validate(usb_interrupt)
        assert usb_interrupt['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert usb_interrupt[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        report['usb_interrupt']=usb_interrupt
        runtime_start,runtime_end='SKE_USB_RUNTIME_BEGIN','SKE_USB_RUNTIME_END'
        assert console.count(runtime_start)==console.count(runtime_end)==1
        usb_runtime=json.loads(console.split(runtime_start,1)[1].split(runtime_end,1)[0].strip())
        runtime_spec=importlib.util.spec_from_file_location('usb_runtime_gate',directory/'validate-usb-runtime.py')
        runtime_gate=importlib.util.module_from_spec(runtime_spec);runtime_spec.loader.exec_module(runtime_gate)
        runtime_gate.validate(usb_runtime)
        assert usb_runtime['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert usb_runtime[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        report['usb_runtime']=usb_runtime
        pending_start,pending_end='SKE_USB_RUNTIME_PENDING_BEGIN','SKE_USB_RUNTIME_PENDING_END'
        assert console.count(pending_start)==console.count(pending_end)==1
        usb_runtime_pending=json.loads(console.split(pending_start,1)[1].split(pending_end,1)[0].strip())
        pending_spec=importlib.util.spec_from_file_location('usb_runtime_pending_gate',directory/'validate-usb-runtime-pending.py')
        pending_gate=importlib.util.module_from_spec(pending_spec);pending_spec.loader.exec_module(pending_gate)
        pending_gate.validate(usb_runtime_pending)
        assert usb_runtime_pending['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert usb_runtime_pending[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        report['usb_runtime_pending']=usb_runtime_pending

        reboot_pending_start,reboot_pending_end='SKE_USB_REBOOT_PENDING_BEGIN','SKE_USB_REBOOT_PENDING_END'
        assert console.count(reboot_pending_start)==console.count(reboot_pending_end)==1
        usb_reboot_pending=json.loads(console.split(reboot_pending_start,1)[1].split(reboot_pending_end,1)[0].strip())
        reboot_pending_spec=importlib.util.spec_from_file_location('usb_reboot_pending_gate',directory/'validate-usb-reboot-pending.py')
        reboot_pending_gate=importlib.util.module_from_spec(reboot_pending_spec);reboot_pending_spec.loader.exec_module(reboot_pending_gate)
        reboot_pending_gate.validate(usb_reboot_pending)
        assert usb_reboot_pending['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert usb_reboot_pending[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        report['usb_reboot_pending']=usb_reboot_pending

        long_start,long_end='SKE_USB_LONG_CUTOVER_BEGIN','SKE_USB_LONG_CUTOVER_END'
        assert console.count(long_start)==console.count(long_end)==1
        usb_long_cutover=json.loads(console.split(long_start,1)[1].split(long_end,1)[0].strip())
        long_spec=importlib.util.spec_from_file_location('usb_long_cutover_gate',directory/'validate-usb-long-cutover.py')
        long_gate=importlib.util.module_from_spec(long_spec);long_spec.loader.exec_module(long_gate);long_gate.validate(usb_long_cutover)
        assert usb_long_cutover['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert usb_long_cutover[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        report['usb_long_cutover']=usb_long_cutover

        partial_start,partial_end='SKE_USB_PARTIAL_INTERRUPT_BEGIN','SKE_USB_PARTIAL_INTERRUPT_END'
        assert console.count(partial_start)==console.count(partial_end)==1
        usb_partial_interrupt=json.loads(console.split(partial_start,1)[1].split(partial_end,1)[0].strip())
        partial_spec=importlib.util.spec_from_file_location('usb_partial_interrupt_gate',directory/'validate-usb-partial-interrupt.py')
        partial_gate=importlib.util.module_from_spec(partial_spec);partial_spec.loader.exec_module(partial_gate);partial_gate.validate(usb_partial_interrupt)
        assert usb_partial_interrupt['current_release_transport_verification'] is True
        assert usb_partial_interrupt['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert usb_partial_interrupt[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        assert all(row['original_worker']['kind']=='native-aio' for row in usb_long_cutover['cycles'])
        report['usb_partial_interrupt']=usb_partial_interrupt

        large_runtime_start,large_runtime_end='SKE_USB_LARGE_PARTIAL_RUNTIME_BEGIN','SKE_USB_LARGE_PARTIAL_RUNTIME_END'
        assert console.count(large_runtime_start)==console.count(large_runtime_end)==1
        usb_large_partial_runtime=json.loads(console.split(large_runtime_start,1)[1].split(large_runtime_end,1)[0].strip())
        large_runtime_spec=importlib.util.spec_from_file_location('usb_large_partial_runtime_gate',directory/'validate-usb-large-partial-runtime.py')
        large_runtime_gate=importlib.util.module_from_spec(large_runtime_spec);large_runtime_spec.loader.exec_module(large_runtime_gate)
        large_runtime_gate.validate(usb_large_partial_runtime)
        assert usb_large_partial_runtime['current_release_transport_verification'] is True
        assert usb_large_partial_runtime['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert usb_large_partial_runtime[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        report['usb_large_partial_runtime']=usb_large_partial_runtime

        stock_start,stock_end='SKE_STOCK_LIBCCID_LARGE_BEGIN','SKE_STOCK_LIBCCID_LARGE_END'
        assert console.count(stock_start)==console.count(stock_end)==1
        stock_large=json.loads(console.split(stock_start,1)[1].split(stock_end,1)[0].strip())
        stock_spec=importlib.util.spec_from_file_location('stock_large_gate',directory/'validate-stock-libccid-large.py')
        stock_gate=importlib.util.module_from_spec(stock_spec);stock_spec.loader.exec_module(stock_gate)
        stock_wire=stock_gate.validate(stock_large)
        assert stock_large['current_release_transport_verification'] is True and len(stock_wire)==12
        assert stock_large['controller']==composite['controller']
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:
            assert stock_large[key]==hashlib.sha256((artifacts/'build'/name).read_bytes()).hexdigest()
        report['stock_libccid_large']=stock_large
        report['stock_libccid_large_independent_wire']=stock_wire







        composite["usb_bridge_binary_sha256"] = hashlib.sha256(
            (artifacts / "build/ske-usbd").read_bytes()
        ).hexdigest()
        report["composite_usb"] = composite
        browser_start, browser_end = (
            "SKE_BROWSER_RESULT_BEGIN",
            "SKE_BROWSER_RESULT_END",
        )
        assert console.count(browser_start) == console.count(browser_end) == 1
        browser = json.loads(
            console.split(browser_start, 1)[1].split(browser_end, 1)[0].strip()
        )
        assert browser.get("passed"), browser.get("error")
        assert all(
            browser.get(key) is True
            for key in [
                "browser_native_usb_webauthn_verified",
                "browser_restart_verified",
                "browser_live_usb_reboot_verified",
            ]
        )
        assert browser["test_count"] == len(browser["tests"]) and all(
            item["passed"] for item in browser["tests"]
        )
        assert not any(
            browser.get(key)
            for key in [
                "physical_device_access",
                "host_usb_passthrough",
                "virtual_authenticator_enabled",
                "webauthn_api_replaced",
                "manufacturer_trust_reproduced",
            ]
        )
        assert {item["algorithm"] for item in browser["registrations"]} == {-7, -8, -35}
        assert len(browser["assertions"]) == 12 and all(
            item["signature_verified"] for item in browser["assertions"]
        )
        assert (
            browser["final_metrics"]["make_cred_ok"] == 3
            and browser["final_metrics"]["get_assert_ok"] >= 12
        )
        assert (
            browser["first_browser"]["prefs"]
            == browser["second_browser"]["prefs"]
            == {"usb": True, "soft": False, "ctap2": True}
        )
        assert all(
            not cmd.startswith("WebAuthn:")
            for cmd in browser["first_commands"] + browser["second_commands"]
        )
        browser["emulator_binary_sha256"] = hashlib.sha256(
            (artifacts / "build/swpasskeyd").read_bytes()
        ).hexdigest()
        browser["usb_bridge_binary_sha256"] = composite["usb_bridge_binary_sha256"]
        report["browser_usb"] = browser
        resident_start, resident_end = "SKE_BROWSER_RESIDENT_BEGIN", "SKE_BROWSER_RESIDENT_END"
        assert console.count(resident_start) == console.count(resident_end) == 1
        resident = json.loads(console.split(resident_start, 1)[1].split(resident_end, 1)[0].strip())
        assert resident.get("passed"), resident.get("error")
        assert all(resident.get(key) is True for key in [
            "browser_pin_uv_resident_verified", "browser_multiple_account_selection_verified",
            "browser_resident_restart_verified", "browser_resident_live_usb_reboot_verified",
        ])
        assert resident["test_count"] == len(resident["tests"]) and all(t["passed"] for t in resident["tests"])
        assert len(resident["registrations"]) == 6
        assert {row["algorithm"] for row in resident["registrations"]} == {-7, -8, -35}
        assert len(resident["assertions"]) == 18 and all(row["signature_verified"] and row["user_verified"] and row["user_handle_verified"] for row in resident["assertions"])
        assert {row["phase"] for row in resident["assertions"]} == {"initial", "browser-restart", "live-usb-reboot"}
        assert resident["final_metrics"]["make_cred_ok"] == resident["final_metrics"]["store_creds"] == 6
        assert resident["final_metrics"]["get_assert_ok"] >= 18
        assert resident["initial_metrics"]["pin_fail"] == 1 and resident["initial_metrics"]["errors"]["0x31"] == 1
        assert resident["final_metrics"]["pin_retries"] == 8
        assert all(not resident[key] for key in [
            "physical_device_access", "host_usb_passthrough", "virtual_authenticator_enabled",
            "webauthn_api_replaced", "browser_webauthn_service_callbacks_invoked_directly",
            "physical_touch_verified", "manufacturer_trust_reproduced",
            "browser_extensions_verified", "browser_attestation_consent_verified",
        ])
        assert resident["controller"] == composite["controller"]
        resident["emulator_binary_sha256"] = browser["emulator_binary_sha256"]
        resident["usb_bridge_binary_sha256"] = browser["usb_bridge_binary_sha256"]
        report["browser_resident_usb"] = resident
        prf_start, prf_end = "SKE_BROWSER_PRF_BEGIN", "SKE_BROWSER_PRF_END"
        assert console.count(prf_start) == console.count(prf_end) == 1
        prf = json.loads(console.split(prf_start, 1)[1].split(prf_end, 1)[0].strip())
        assert prf["passed"] and prf["test_count"] == len(prf["tests"]) == 123
        assert all(item["passed"] for item in prf["tests"])
        assert all(prf[key] for key in [
            "browser_prf_dual_sdk_reference_verified", "browser_prf_restart_and_live_usb_reboot_verified",
            "prf_single_output_verified", "prf_eval_by_credential_verified",
        ])
        assert len(prf["registrations"]) == 6 and len(prf["assertions"]) == 30
        assert {row["algorithm"] for row in prf["registrations"]} == {-7, -8, -35}
        assert all(row["signature_verified"] and row["user_verified"] and row["user_handle_verified"] and row["independent_sdk_prf_match"] for row in prf["assertions"])
        assert {row["phase"] for row in prf["assertions"]} == {"initial", "browser-restart", "live-usb-reboot", "single-output", "eval-by-credential"}
        for account in {row["account"] for row in prf["registrations"]}:
            rows = [row for row in prf["assertions"] if row["account"] == account]
            assert len(rows) == 5
            assert len({row["prf_first_sha256"] for row in rows}) == 1
            assert len({row["prf_second_sha256"] for row in rows if row["prf_second_sha256"] is not None}) == 1
            assert [row["prf_request_mode"] for row in rows] == ["dual", "dual", "dual", "single", "eval-by-credential"]
        assert prf["independent_sdk_assertion_reference_count"] == 6 and prf["browser_verified_assertion_count"] == 30
        assert prf["pin_uv_protocol_for_independent_reference"] == 2
        assert prf["final_metrics"]["make_cred_ok"] == prf["final_metrics"]["store_creds"] == 6
        assert prf["final_metrics"]["remaining"] == 94 and prf["final_metrics"]["get_assert_ok"] >= 36
        assert prf["initial_metrics"]["pin_fail"] == 1 and prf["initial_metrics"]["errors"]["0x31"] == 1
        assert prf["final_metrics"]["pin_retries"] == 8
        assert all(not prf[key] for key in [
            "physical_device_access", "host_usb_passthrough", "virtual_authenticator_enabled",
            "webauthn_api_replaced", "browser_webauthn_service_callbacks_invoked_directly",
            "physical_touch_verified", "manufacturer_trust_reproduced",
            "all_browser_extensions_verified", "browser_large_blob_verified", "browser_attestation_consent_verified",
        ])
        assert prf["controller"] == composite["controller"]
        prf["emulator_binary_sha256"] = browser["emulator_binary_sha256"]
        prf["usb_bridge_binary_sha256"] = browser["usb_bridge_binary_sha256"]
        report["browser_prf_usb"] = prf
        att_start, att_end = "SKE_BROWSER_ATTESTATION_BEGIN", "SKE_BROWSER_ATTESTATION_END"
        assert console.count(att_start) == console.count(att_end) == 1
        attestation = json.loads(console.split(att_start, 1)[1].split(att_end, 1)[0].strip())
        assert attestation["passed"] and attestation["test_count"] == len(attestation["tests"]) == 40
        assert all(item["passed"] for item in attestation["tests"])
        assert all(attestation[key] for key in [
            "browser_attestation_consent_verified", "browser_granted_self_attestation_verified",
            "browser_denied_attestation_anonymized_verified", "browser_aaguid_retained_after_denial_verified",
            "browser_granted_and_denied_keys_after_restart_verified",
        ])
        assert attestation["direct_attestation_bypass_pref"] is False
        assert len(attestation["registrations"]) == 6 and len(attestation["assertions"]) == 12
        for alg in [-7, -8, -35]:
            rows = [row for row in attestation["registrations"] if row["algorithm"] == alg]
            assert len(rows) == 2 and {row["consent"] for row in rows} == {True, False}
            grant = next(row for row in rows if row["consent"])
            deny = next(row for row in rows if not row["consent"])
            assert grant["format"] == "packed" and grant["own_self_attestation_verified"]
            assert deny["format"] == "none" and deny["anonymization_verified"]
            assert grant["aaguid_hex"] == deny["aaguid_hex"] == attestation["own_aaguid_hex"]
        assert all(row["signature_verified"] and row["user_verified"] and row["user_handle_verified"] for row in attestation["assertions"])
        assert attestation["final_metrics"]["make_cred_ok"] == attestation["final_metrics"]["store_creds"] == 6
        assert attestation["final_metrics"]["get_assert_ok"] >= 12 and attestation["final_metrics"]["remaining"] == 94
        assert all(not attestation[key] for key in [
            "physical_device_access", "host_usb_passthrough", "virtual_authenticator_enabled",
            "webauthn_api_replaced", "browser_webauthn_service_callbacks_invoked_directly",
            "physical_touch_verified", "manufacturer_trust_reproduced",
        ])
        assert attestation["controller"] == composite["controller"]
        attestation["emulator_binary_sha256"] = browser["emulator_binary_sha256"]
        attestation["usb_bridge_binary_sha256"] = browser["usb_bridge_binary_sha256"]
        report["browser_attestation_usb"] = attestation
        blob_start, blob_end = "SKE_BROWSER_LARGE_BLOB_BEGIN", "SKE_BROWSER_LARGE_BLOB_END"
        assert console.count(blob_start) == console.count(blob_end) == 1
        largeblob = json.loads(console.split(blob_start, 1)[1].split(blob_end, 1)[0].strip())
        spec = importlib.util.spec_from_file_location('largeblob_gate', directory / 'validate-browser-largeblob.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        gate.validate(largeblob, require_repeat_guard=True)
        assert largeblob['controller'] == composite['controller']
        largeblob['emulator_binary_sha256'] = browser['emulator_binary_sha256']
        largeblob['usb_bridge_binary_sha256'] = browser['usb_bridge_binary_sha256']
        report['browser_largeblob_usb'] = largeblob
    assert runner_exit == 0, f"QEMU runner exited {runner_exit}"
    assert "SKE_NATIVE_GUEST_EXIT=0" in console
    assert report.get("passed") is True
    assert report.get("native_uhid_registration_verified") is True
    assert report.get("native_sdk_ctap_verified") is True
    assert report.get("native_lifecycle_restart_teardown_verified") is True
    assert report.get("test_count") == len(report["tests"])
    assert all(item["passed"] for item in report["tests"])
    report["build"] = json.loads((artifacts / "linux-build-result.json").read_text())
    report["guest_artifacts"] = json.loads(
        (artifacts / "guest-build-manifest.json").read_text()
    )
    if args.expect_composite:
        controller = report["composite_usb"]["controller"]
        assert controller["requested_ep_addresses_enabled"] is True
        assert report["composite_usb"]["reboot"]["controller"] == controller
        expected = report["guest_artifacts"]["usb_virtual_controller"]
        assert {k: v for k, v in controller.items() if k != "requested_ep_addresses_enabled"} == expected
        assert hashlib.sha256((directory / "dummy_hcd-addresses.patch").read_bytes()).hexdigest() == expected["files"]["dummy_hcd-addresses.patch"]
        usb_state = report['usb_state']
        assert usb_state['card_service_sha256'] == report['guest_artifacts']['card_service_sha256']
        assert usb_state['card_service_sha256'] == hashlib.sha256((directory.parent.parent / 'emucard/service.py').read_bytes()).hexdigest()
        for name, digest in report['guest_artifacts']['usb_state_helper_sha256'].items():
            assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest
            if name in usb_state['helper_sha256']:
                assert usb_state['helper_sha256'][name] == digest
        assert usb_power['card_service_sha256']==report['guest_artifacts']['card_service_sha256']
        for name,digest in report['guest_artifacts']['usb_power_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
            if name in usb_power['helper_sha256']:assert usb_power['helper_sha256'][name]==digest
        for name in ['verify-usb-state.py','usb-state-pending.py']:
            assert usb_power['helper_sha256'][name]==report['guest_artifacts']['usb_state_helper_sha256'][name]
        assert report['guest_artifacts']['usb_power_source_sha256']==hashlib.sha256((directory.parent.parent/'source/src/usb/linux.cpp').read_bytes()).hexdigest()
        assert usb_interrupt['card_service_sha256']==report['guest_artifacts']['card_service_sha256']

        assert usb_long_cutover['card_service_sha256']==report['guest_artifacts']['card_service_sha256']
        for name,digest in report['guest_artifacts']['usb_long_cutover_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
        assert usb_long_cutover['helper_sha256']==report['guest_artifacts']['usb_long_cutover_helper_sha256']['verify-usb-long-cutover.py']
        assert usb_long_cutover['shared_helper_sha256']==report['guest_artifacts']['usb_reboot_pending_helper_sha256']['verify-usb-reboot-pending.py']

        assert usb_long_cutover['native_io_observer_sha256']==report['guest_artifacts']['usb_long_cutover_helper_sha256']['native-ccid-io.py']
        assert usb_partial_interrupt['card_service_sha256']==report['guest_artifacts']['card_service_sha256']
        for name,digest in report['guest_artifacts']['usb_partial_interrupt_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
        assert usb_partial_interrupt['helper_sha256']==report['guest_artifacts']['usb_partial_interrupt_helper_sha256']['verify-usb-partial-interrupt.py']
        assert usb_partial_interrupt['native_io_observer_sha256']==report['guest_artifacts']['usb_partial_interrupt_helper_sha256']['native-ccid-io.py']
        assert usb_partial_interrupt['shared_helper_sha256']==usb_long_cutover['shared_helper_sha256']
        assert usb_partial_interrupt['long_cutover_helper_sha256']==usb_long_cutover['helper_sha256']
        assert stock_large['card_service_sha256']==report['guest_artifacts']['card_service_sha256']
        for name,digest in report['guest_artifacts']['stock_libccid_large_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
        assert stock_large['helper_sha256']==report['guest_artifacts']['stock_libccid_large_helper_sha256']['verify-stock-libccid-large.py']
        assert stock_large['shared_fido_helper_sha256']==report['guest_artifacts']['usb_reboot_pending_helper_sha256']['verify-usb-reboot-pending.py']
        assert hashlib.sha256((artifacts/'stock-driver-provenance.json').read_bytes()).hexdigest()==report['guest_artifacts']['stock_driver_provenance_sha256']
        assert stock_large['stock_driver_provenance']==json.loads((artifacts/'stock-driver-provenance.json').read_text())
        assert usb_large_partial_runtime['card_service_sha256']==report['guest_artifacts']['card_service_sha256']
        for name,digest in report['guest_artifacts']['usb_large_partial_runtime_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
        assert usb_large_partial_runtime['helper_sha256']==report['guest_artifacts']['usb_large_partial_runtime_helper_sha256']['verify-usb-large-partial-runtime.py']
        assert usb_large_partial_runtime['native_io_observer_sha256']==report['guest_artifacts']['usb_large_partial_runtime_helper_sha256']['native-ccid-io.py']
        assert usb_large_partial_runtime['shared_helper_sha256']==usb_long_cutover['shared_helper_sha256']
        assert usb_large_partial_runtime['long_cutover_helper_sha256']==usb_long_cutover['helper_sha256']
        assert usb_large_partial_runtime['queued_runtime_helper_sha256']==report['guest_artifacts']['usb_runtime_pending_helper_sha256']['verify-usb-runtime-pending.py']

        assert usb_reboot_pending['card_service_sha256']==report['guest_artifacts']['card_service_sha256']
        for name,digest in report['guest_artifacts']['usb_reboot_pending_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
        assert usb_reboot_pending['helper_sha256']==report['guest_artifacts']['usb_reboot_pending_helper_sha256']['verify-usb-reboot-pending.py']
        assert usb_runtime_pending['card_service_sha256']==report['guest_artifacts']['card_service_sha256']
        for name,digest in report['guest_artifacts']['usb_runtime_pending_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
            if name in usb_runtime_pending['helper_sha256']:assert usb_runtime_pending['helper_sha256'][name]==digest
        assert usb_runtime_pending['helper_sha256']['verify-usb-runtime.py']==report['guest_artifacts']['usb_runtime_helper_sha256']['verify-usb-runtime.py']
        for name in ['verify-usb-state.py','usb-state-pending.py']:
            assert usb_runtime_pending['helper_sha256'][name]==report['guest_artifacts']['usb_state_helper_sha256'][name]
        assert usb_runtime['card_service_sha256']==report['guest_artifacts']['card_service_sha256']
        for name,digest in report['guest_artifacts']['usb_runtime_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
            if name in usb_runtime['helper_sha256']:assert usb_runtime['helper_sha256'][name]==digest
        for name in ['verify-usb-state.py','usb-state-pending.py']:
            assert usb_runtime['helper_sha256'][name]==report['guest_artifacts']['usb_state_helper_sha256'][name]
        for name,digest in report['guest_artifacts']['usb_interrupt_helper_sha256'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==digest
            if name in usb_interrupt['helper_sha256']:assert usb_interrupt['helper_sha256'][name]==digest
        for name in ['verify-usb-state.py','usb-state-pending.py']:
            assert usb_interrupt['helper_sha256'][name]==report['guest_artifacts']['usb_state_helper_sha256'][name]
        chromium = report['guest_artifacts']['chromium_runtime']
        blob = report['browser_largeblob_usb']
        assert chromium['architecture'] == 'AArch64'
        assert chromium['version'] == '154.0.8037.92'
        assert chromium['package_version'] == '154.0.8037.92-1~deb13u1'
        assert chromium['stock_binary_unmodified'] is True
        assert chromium['apt_signed_repository_verification_used'] is True
        assert chromium['host_devices_or_browser_state_copied'] is False
        assert chromium['binary_sha256'] == blob['browser_binary_sha256']
        assert '@' + chromium['upstream_revision'] == blob['browser_version']['revision']
        assert chromium['debian_base_image_digest'] == 'sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5'
        for name, digest in chromium['helper_sha256'].items():
            assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest
        blob['helper_sha256'] = chromium['helper_sha256']
        blob['browser_runtime'] = chromium
    report["emulator_binary_sha256"] = hashlib.sha256(
        (artifacts / "build/swpasskeyd").read_bytes()
    ).hexdigest()
    report["runtime_command"] = command
    report["qemu_acceleration"] = "TCG, no KVM or host device passthrough"
    report['console_sha256']=hashlib.sha256(log_path.read_bytes()).hexdigest()
    report['runner_executed_this_invocation']=not bool(args.revalidate_console_sha256)
    report['existing_actual_execution_revalidated_after_host_gate_correction']=bool(args.revalidate_console_sha256)
    if args.revalidate_console_sha256:
        report['original_runner_report_sha256']=hashlib.sha256(prior_path.read_bytes()).hexdigest()
except Exception as exc:
    report.update(passed=False, runner_error=f"{type(exc).__name__}: {exc}",runner_traceback=traceback.format_exc())
finally:
    if not report.get('passed') and not args.revalidate_console_sha256:
        (artifacts/'linux-native-host-gate-failure.json').write_text(json.dumps(report,indent=2)+'\n')
    (artifacts / "linux-native-result.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )

print(
    json.dumps(
        {
            name: report.get(name)
            for name in [
                "passed",
                "runner_exit",
                "kernel",
                "sdk_version",
                "test_count",
                "native_uhid_registration_verified",
                "error",
                "runner_error",
            ]
        },
        indent=2,
    ),
    flush=True,
)
raise SystemExit(0 if report["passed"] else 1)
