#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/cut_prerelease.sh <tag> <notes_file> [target_branch]

Example:
  scripts/cut_prerelease.sh 2026.02.21b12 release-notes/2026.02.21b12.md dev-passcodes

Rules enforced by this script:
  - Release notes file must exist and be non-empty.
  - First non-empty line must be a plain one-line summary (HACS-visible description).
  - First non-empty line cannot be a markdown header.
  - First non-empty line must be at least 20 characters.
  - manifest version must match the release tag.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

TAG="${1:-}"
NOTES_FILE="${2:-}"
TARGET_BRANCH="${3:-dev-passcodes}"
MANIFEST_PATH="custom_components/nest_yale_lock/manifest.json"

if [[ -z "${TAG}" || -z "${NOTES_FILE}" ]]; then
  echo "ERROR: Missing required arguments."
  usage
  exit 1
fi

if [[ ! -f "${NOTES_FILE}" ]]; then
  echo "ERROR: Notes file not found: ${NOTES_FILE}"
  exit 1
fi

if [[ ! -s "${NOTES_FILE}" ]]; then
  echo "ERROR: Notes file is empty: ${NOTES_FILE}"
  exit 1
fi

SHORT_DESC="$(awk 'NF { print; exit }' "${NOTES_FILE}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

if [[ -z "${SHORT_DESC}" ]]; then
  echo "ERROR: Notes file must start with a one-line HACS description."
  exit 1
fi

if [[ "${SHORT_DESC}" =~ ^# ]]; then
  echo "ERROR: First non-empty line must be plain text, not a markdown header."
  echo "       Current line: ${SHORT_DESC}"
  exit 1
fi

if (( ${#SHORT_DESC} < 20 )); then
  echo "ERROR: First non-empty line is too short (${#SHORT_DESC} chars)."
  echo "       Provide a descriptive HACS summary line (>=20 chars)."
  exit 1
fi

if [[ ! -f "${MANIFEST_PATH}" ]]; then
  echo "ERROR: manifest not found: ${MANIFEST_PATH}"
  exit 1
fi

if ! grep -q "\"version\": \"${TAG}\"" "${MANIFEST_PATH}"; then
  echo "ERROR: manifest version does not match tag ${TAG}."
  echo "       Update ${MANIFEST_PATH} version before cutting release."
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: GitHub CLI (gh) is not installed."
  exit 1
fi

if gh release view "${TAG}" >/dev/null 2>&1; then
  echo "ERROR: Release/tag already exists on GitHub: ${TAG}"
  exit 1
fi

echo "Creating prerelease ${TAG} (target=${TARGET_BRANCH})"
echo "HACS description: ${SHORT_DESC}"

gh release create "${TAG}" \
  --title "${TAG}" \
  --notes-file "${NOTES_FILE}" \
  --prerelease \
  --target "${TARGET_BRANCH}"

echo "Done."
