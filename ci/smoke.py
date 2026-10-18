"""No prompt, no token logging. CI smoke check against freshly seeded Docker services."""
import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = os.environ['SECUREINCIDENT_BASE_URL'].rstrip('/')
PASSWORD = os.environ['SEED_ALICE_PASSWORD']


def call(method, path, payload=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    request = Request(BASE + path, method=method, headers=headers,
                      data=json.dumps(payload).encode() if payload is not None else None)
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except HTTPError as response:
        return response.code, json.loads(response.read())


def main():
    status, data = call('POST', '/auth/login', {'username': 'alice', 'password': PASSWORD})
    assert status == 200, f'Login: {status}'
    token = data['access_token']
    created, record = call('POST', '/incidents/101/reports', {}, token)
    denied, _ = call('POST', '/incidents/102/reports', {}, token)
    invalid, _ = call('POST', '/incidents/101/reports', {'filename': '../escape.txt'}, token)
    retrieved = 0
    if created == 201:
        retrieved, _ = call('GET', f"/incidents/101/reports/{record['id']}", token=token)
    outcomes = [('Authorized report', created, 201), ('Cross-user denial', denied, 404),
                ('Path traversal denial', invalid, 422), ('Report retrieval', retrieved, 200)]
    for label, actual, expected in outcomes:
        print(f'{label}: HTTP {actual}, expected {expected}')
    if any(actual != expected for _, actual, expected in outcomes):
        raise SystemExit('CI SMOKE GATE FAILED')
    print('CI SMOKE GATE PASSED')


if __name__ == '__main__':
    main()
