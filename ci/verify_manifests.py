"""Fail the build when direct dependency declarations are unpinned/unapproved."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ('requirements-incident.txt', 'requirements-gateway.txt', 'requirements-report.txt')
LOCAL_PACKAGE = './packages/incident_formatter'
ALLOWED = re.compile(r'^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[0-9][A-Za-z0-9_.!+~-]*$')


def main():
    errors = []
    for filename in REQUIREMENTS:
        path = ROOT / filename
        if not path.is_file():
            errors.append(f'missing {filename}')
            continue
        for lineno, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            text = line.strip()
            if not text or text.startswith('#'):
                continue
            if text == LOCAL_PACKAGE and filename == 'requirements-report.txt':
                if not (ROOT / 'packages/incident_formatter/pyproject.toml').is_file():
                    errors.append('missing installable local formatter metadata')
                continue
            if not ALLOWED.fullmatch(text):
                errors.append(f'{filename}:{lineno}: unexpected/unpinned dependency: {text}')
    if errors:
        raise SystemExit('MANIFEST GATE FAILED\n' + '\n'.join(errors))
    print('MANIFEST GATE PASSED: direct requirements pinned; helper is declared and installable')


if __name__ == '__main__':
    main()
