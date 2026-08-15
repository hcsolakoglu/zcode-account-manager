# GitHub publishing checklist

This repository must remain private unless the owner explicitly decides
otherwise.

## Repository creation

- Owner: `hcsolakoglu`
- Name: `zcode-auth`
- Visibility: private
- Default branch: `main`
- Description: `Secure cross-platform ZCode profile manager with atomic credentials.json and telemetry-state.json rotation.`
- Topics: `go`, `golang`, `cli`, `cross-platform`, `credential-management`,
  `account-switching`, `security`, `backup`, `zcode`

Do not initialize the GitHub repository with another README, license, or
`.gitignore`; the local repository already contains them.

## Before the first push

1. Confirm the repository-local Git author uses the account's exact GitHub
   noreply address, not a personal email.
2. Run `gitleaks dir . --redact` and the full CI-equivalent test suite.
3. Confirm `git status --short` excludes `outputs/`, `work/`, and local secrets.
4. Inspect the staged diff and commit metadata before committing.
5. Create the remote as private, add `origin`, and push `main` only after
   explicit approval.

## GitHub settings

- Keep Actions token permissions read-only by default.
- Enable Dependabot alerts and security updates.
- Enable secret scanning and push protection when available for the private
  repository.
- Enable private vulnerability reporting.
- Protect `main`: require pull requests, required CI checks, conversation
  resolution, and no force pushes or deletions.
- Do not commit generated binaries. Attach the five binaries, source archive,
  checksums, SBOM, and provenance to a signed SemVer release.

Private repositories are not search-engine indexed. The description, topics,
README wording, and release metadata become discovery signals only if the
repository is intentionally made public later.
