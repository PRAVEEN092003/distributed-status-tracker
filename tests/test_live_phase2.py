"""Live HTTP end-to-end integration test for Phase 2."""

import http.cookiejar
import re
import time
import urllib.parse
import urllib.request
import json


def run_phase2_live_test(base_url="http://127.0.0.1:5000"):
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def get_csrf(url):
        res = opener.open(url)
        html = res.read().decode("utf-8")
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        if not m:
            m = re.search(r'content="([^"]+)"\s+name="csrf-token"', html)
        assert m, f"CSRF token missing on {url}"
        return m.group(1), html

    # 1. Register & Login
    csrf, _ = get_csrf(f"{base_url}/register")
    test_id = int(time.time())
    username = f"liveuser_{test_id}"
    email = f"live_{test_id}@tracker.local"

    reg_data = urllib.parse.urlencode({
        "csrf_token": csrf,
        "username": username,
        "email": email,
        "password": "Password123!",
        "confirm_password": "Password123!",
    }).encode("utf-8")
    opener.open(f"{base_url}/register", data=reg_data)

    csrf, _ = get_csrf(f"{base_url}/login")
    login_data = urllib.parse.urlencode({
        "csrf_token": csrf,
        "email": email,
        "password": "Password123!",
    }).encode("utf-8")
    opener.open(f"{base_url}/login", data=login_data)
    print(f"[OK] Registered and logged in as {username}")

    # 2. Add a Website (using https://httpbin.org or https://example.com)
    csrf, _ = get_csrf(f"{base_url}/websites")
    add_data = urllib.parse.urlencode({
        "csrf_token": csrf,
        "service_name": "Example Public Site",
        "service_url": "https://example.com",
        "check_interval": "60",
        "timeout": "5",
    }).encode("utf-8")
    res = opener.open(f"{base_url}/websites/add", data=add_data)
    websites_html = res.read().decode("utf-8")
    assert "Example Public Site" in websites_html
    print("[OK] Added website 'Example Public Site'")

    # Extract service ID
    id_match = re.search(r'/websites/(\d+)', websites_html)
    assert id_match, "Service ID link not found on websites page"
    service_id = id_match.group(1)
    print(f"[OK] Extracted Service ID: {service_id}")

    # 3. View website detail page
    res_detail = opener.open(f"{base_url}/websites/{service_id}")
    detail_html = res_detail.read().decode("utf-8")
    assert "Operational Status" in detail_html
    print("[OK] Service details page verified")

    # 4. Check dashboard live JSON API
    api_res = opener.open(f"{base_url}/api/dashboard/stats")
    stats_json = json.loads(api_res.read().decode("utf-8"))
    assert stats_json["status"] == "success"
    assert stats_json["stats"]["total_services"] == 1
    print(f"[OK] Dashboard live JSON API verified: {stats_json['stats']}")

    # 5. Check history page
    res_hist = opener.open(f"{base_url}/history")
    hist_html = res_hist.read().decode("utf-8")
    assert "Log Entries" in hist_html
    print("[OK] Monitoring history page verified")

    # 6. Manual Check Now
    csrf, _ = get_csrf(f"{base_url}/websites/{service_id}")
    check_data = urllib.parse.urlencode({"csrf_token": csrf}).encode("utf-8")
    res_check = opener.open(f"{base_url}/websites/{service_id}/check", data=check_data)
    check_html = res_check.read().decode("utf-8")
    assert "Check completed" in check_html
    print("[OK] Manual on-demand check succeeded")

    # 7. Toggle monitoring
    csrf, _ = get_csrf(f"{base_url}/websites/{service_id}")
    toggle_data = urllib.parse.urlencode({"csrf_token": csrf}).encode("utf-8")
    res_toggle = opener.open(f"{base_url}/websites/{service_id}/toggle", data=toggle_data)
    toggle_html = res_toggle.read().decode("utf-8")
    assert "paused" in toggle_html or "resumed" in toggle_html
    print("[OK] Toggle monitoring state succeeded")

    # 8. Delete website
    csrf, _ = get_csrf(f"{base_url}/websites/{service_id}")
    del_data = urllib.parse.urlencode({"csrf_token": csrf}).encode("utf-8")
    res_del = opener.open(f"{base_url}/websites/{service_id}/delete", data=del_data)
    del_html = res_del.read().decode("utf-8")
    assert "was successfully deleted" in del_html
    print("[OK] Deleted website successfully")

    print("=== ALL PHASE 2 LIVE HTTP TESTS PASSED ===")


if __name__ == "__main__":
    run_phase2_live_test()
