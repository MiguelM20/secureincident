"""Manual three-service smoke check with synthetic Alice credentials only.

Run while the Gateway, Incident Service, and Report Service are running.
Prompts without echo, never prints bearer tokens or passwords.
"""

import getpass
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = "http://127.0.0.1:8000"


def call(method: str, path: str, *, payload=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        BASE + path, method=method, headers=headers,
        data=json.dumps(payload).encode() if payload is not None else None,
    )
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def main():
    password = getpass.getpass("Alice's local development password: ")
    try:
        login_status, login = call("POST", "/auth/login", payload={
            "username": "alice", "password": password,
        })
        if login_status != 200:
            raise SystemExit(f"Login failed, HTTP {login_status}")
        token = login["access_token"]
        created_status, report = call("POST", "/incidents/101/reports",
                                      payload={}, token=token)
        denied_status, _ = call("POST", "/incidents/102/reports", payload={}, token=token)
        path_status, _ = call("POST", "/incidents/101/reports",
                              payload={"filename": "../outside.txt"}, token=token)
        retrieved_status = 0
        if created_status == 201:
            retrieved_status, _ = call(
                "GET", f"/incidents/101/reports/{report['id']}", token=token,
            )
        for label, status, expected in [
            ("Create Alice's report", created_status, 201),
            ("Deny Alice on Bob's incident", denied_status, 404),
            ("Reject filename traversal", path_status, 422),
            ("Retrieve authorized report", retrieved_status, 200),
        ]:
            print(f"{label}: HTTP {status} (expected {expected})")
        if [created_status, denied_status, path_status, retrieved_status] != [201, 404, 422, 200]:
            raise SystemExit("Report workflow verification FAILED")
        print("Report workflow verification PASSED")
    except URLError as error:
        raise SystemExit("Gateway unreachable. Start all three service processes.") from error


if __name__ == "__main__":
    main()
