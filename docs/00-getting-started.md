# 00 - Getting started (Git-first setup)

This repository intentionally starts with **design documents and a Git commit only**. Assignment I requires the initial SSDLC plan to be committed **before any feature implementation**.

## Open locally

1. Extract the ZIP archive preserving the `secureincident/` root folder, including its hidden `.git/` directory.
2. Open the extracted `secureincident/` directory in VS Code or your preferred editor.
3. Install Git if necessary, then verify the history:

   ```bash
   git status
   git log --oneline --max-count=3
   ```

   Expected: a clean working tree and the first commit called `docs: initial SSDLC plan and security architecture`.

4. Do **not** run `git init` again. The archived directory is already a Git repository.

## Publish to a new GitHub repository

Create an **empty private** repository named `secureincident` in GitHub, leaving the README, `.gitignore` and licence creation options unchecked. Run these commands in the extracted `secureincident/` directory, replacing `<YOUR_USERNAME>`:

```bash
git remote add origin https://github.com/<YOUR_USERNAME>/secureincident.git
git branch -M main
git push -u origin main
```

If `origin` already exists, verify it using `git remote -v` rather than adding it twice. GitHub may ask you to sign in using a credential manager.

## Subsequent workflow

Develop on feature branches or focused commits. Preserve the deliberately vulnerable versions as clearly identified experimental commits/tags in a local, synthetic-only lab. Never publish or deploy the vulnerable system on a public network. CI and the final branch must reject the selected vulnerabilities.

Next implementation milestone: three separately running FastAPI services with seeded accounts and a restricted authentication/authorization flow. Follow the definitions in `docs/01-requirements.md` and `docs/02-architecture-and-interfaces.md`.
