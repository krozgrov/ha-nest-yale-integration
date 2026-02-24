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
  - Release title is generated from tag + summary line.
  - Retention cleanup runs after publish.
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
BASELINE_CONFIG_PATH="baseline.config.json"

read_int_token() {
  local key="$1"
  local default_value="$2"
  if [[ ! -f "${BASELINE_CONFIG_PATH}" ]]; then
    echo "${default_value}"
    return 0
  fi

  python3 - "$key" "$default_value" "${BASELINE_CONFIG_PATH}" <<'PY'
import json
import sys

key = sys.argv[1]
default_raw = sys.argv[2]
path = sys.argv[3]

try:
    default_value = int(default_raw)
except Exception:
    print(default_raw)
    sys.exit(0)

try:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    value = data.get(key, default_value)
    if isinstance(value, bool):
        print(default_value)
    elif isinstance(value, (int, float)):
        print(int(value))
    elif isinstance(value, str) and value.isdigit():
        print(int(value))
    else:
        print(default_value)
except Exception:
    print(default_value)
PY
}

HA_RETAIN_STABLE="$(read_int_token HA_RETAIN_STABLE 2)"
HA_RETAIN_BETA="$(read_int_token HA_RETAIN_BETA 3)"

if ! [[ "${HA_RETAIN_STABLE}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: HA_RETAIN_STABLE must be a non-negative integer (got: ${HA_RETAIN_STABLE})."
  exit 1
fi
if ! [[ "${HA_RETAIN_BETA}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: HA_RETAIN_BETA must be a non-negative integer (got: ${HA_RETAIN_BETA})."
  exit 1
fi

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

GH_REPO="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
if [[ -z "${GH_REPO}" ]]; then
  echo "ERROR: Unable to resolve GitHub repository."
  exit 1
fi

if gh release view "${TAG}" --repo "${GH_REPO}" >/dev/null 2>&1; then
  echo "ERROR: Release/tag already exists on GitHub: ${TAG}"
  exit 1
fi

RELEASE_TITLE="${TAG} - ${SHORT_DESC}"
MAX_TITLE_LEN=120
if (( ${#RELEASE_TITLE} > MAX_TITLE_LEN )); then
  RELEASE_TITLE="${RELEASE_TITLE:0:$((MAX_TITLE_LEN - 3))}..."
fi

echo "Creating prerelease ${TAG} (target=${TARGET_BRANCH})"
echo "HACS description: ${SHORT_DESC}"
echo "Release title: ${RELEASE_TITLE}"

gh release create "${TAG}" \
  --repo "${GH_REPO}" \
  --title "${RELEASE_TITLE}" \
  --notes-file "${NOTES_FILE}" \
  --prerelease \
  --target "${TARGET_BRANCH}"

echo "Enforcing retention policy: stable=${HA_RETAIN_STABLE}, beta=${HA_RETAIN_BETA}"

release_rows="$(gh release list --repo "${GH_REPO}" --limit 200)"
beta_tags="$(printf '%s\n' "${release_rows}" | awk -F '\t' '$2 == "Pre-release" {print $3}')"
stable_tags="$(printf '%s\n' "${release_rows}" | awk -F '\t' '$2 != "Pre-release" {print $3}')"

if (( HA_RETAIN_BETA > 0 )); then
  old_beta_tags="$(printf '%s\n' "${beta_tags}" | tail -n +"$((HA_RETAIN_BETA + 1))")"
else
  old_beta_tags="${beta_tags}"
fi

if (( HA_RETAIN_STABLE > 0 )); then
  old_stable_tags="$(printf '%s\n' "${stable_tags}" | tail -n +"$((HA_RETAIN_STABLE + 1))")"
else
  old_stable_tags="${stable_tags}"
fi

cleanup_release_tag() {
  local release_tag="$1"
  [[ -z "${release_tag}" ]] && return 0
  echo "Removing old release/tag: ${release_tag}"
  gh release delete "${release_tag}" --repo "${GH_REPO}" --yes --cleanup-tag
  git tag -d "${release_tag}" >/dev/null 2>&1 || true
}

while IFS= read -r release_tag; do
  cleanup_release_tag "${release_tag}"
done <<< "${old_beta_tags}"

while IFS= read -r release_tag; do
  cleanup_release_tag "${release_tag}"
done <<< "${old_stable_tags}"

echo "Done."
