"""End-to-end HTTP integration test against running server."""

import http.cookiejar
import re
import time
import urllib.parse
import urllib.request


def run_live_tests(base_url="http://127.0.0.1:5000"):
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # 1. Fetch register page and extract CSRF token
    res = opener.open(f"{base_url}/register")
    html = res.read().decode("utf-8")
    csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    assert csrf_match, "CSRF token not found"
    csrf = csrf_match.group(1)
    print(f"[OK] Fetched register page, CSRF token: {csrf[:8]}...")

    test_id = int(time.time())
    test_user = f"user_{test_id}"
    test_email = f"user_{test_id}@tracker.local"

    # 2. Register user
    reg_data = urllib.parse.urlencode({
        "csrf_token": csrf,
        "username": test_user,
        "email": test_email,
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!",
    }).encode("utf-8")
    res = opener.open(f"{base_url}/register", data=reg_data)
    html = res.read().decode("utf-8")
    assert "Registration successful" in html, "Registration flash message not received"
    print("[OK] Registration completed and flash message received")

    # 3. Log in with the registered user
    login_csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', html).group(1)
    login_data = urllib.parse.urlencode({
        "csrf_token": login_csrf,
        "email": test_email,
        "password": "StrongPassword123!",
    }).encode("utf-8")
    res = opener.open(f"{base_url}/login", data=login_data)
    html = res.read().decode("utf-8")
    assert f'Welcome back, <span class="highlight-username">{test_user}</span>!' in html
    assert 'id="totalServicesCount">0<' in html
    print("[OK] Logged in successfully, Dashboard verified with real 0 counts")

    # 4. Access placeholder pages
    for path in ["/websites", "/history", "/incidents"]:
        res = opener.open(f"{base_url}{path}")
        assert res.status == 200, f"Failed on {path}"
    print("[OK] All module placeholder routes verified")

    # 5. Logout
    res = opener.open(f"{base_url}/logout")
    html = res.read().decode("utf-8")
    assert "successfully logged out" in html
    print("[OK] Logged out successfully")

    # 6. Verify dashboard is locked for unauthenticated client
    guest_cj = http.cookiejar.CookieJar()
    opener_guest = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(guest_cj))
    res_guest = opener_guest.open(f"{base_url}/dashboard")
    assert "/login" in res_guest.geturl()
    html_guest = res_guest.read().decode("utf-8")
    assert "Please log in to access this page" in html_guest
    print("[OK] Protected dashboard route redirect verified")

    print("=== ALL LIVE HTTP INTEGRATION TESTS PASSED ===")


if __name__ == "__main__":
    run_live_tests()
