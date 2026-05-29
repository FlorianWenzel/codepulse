#!/usr/bin/env bash
# Upload a CodePulse report to the server and enforce the project's quality
# gate: exit non-zero when the gate status is ERROR. Driven by env vars so it
# is reusable from the GitHub Action and any other CI.
#
#   CODEPULSE_SERVER   base URL, e.g. https://codepulse.example.com   (required)
#   CODEPULSE_PROJECT  project key                                    (required)
#   REPORT             path to the internal JSON report               (required)
#   CODEPULSE_TOKEN    project analysis token (optional)
#   CODEPULSE_BRANCH   branch name (optional)
#   CODEPULSE_BASE     base branch for PR analysis (optional)
set -euo pipefail

: "${CODEPULSE_SERVER:?CODEPULSE_SERVER is required}"
: "${CODEPULSE_PROJECT:?CODEPULSE_PROJECT is required}"
: "${REPORT:?REPORT (path to report json) is required}"

url="${CODEPULSE_SERVER%/}/api/v1/analyses?project=${CODEPULSE_PROJECT}"
[ -n "${CODEPULSE_BRANCH:-}" ] && url="${url}&branch=${CODEPULSE_BRANCH}"
[ -n "${CODEPULSE_BASE:-}" ] && url="${url}&base=${CODEPULSE_BASE}"

auth=()
[ -n "${CODEPULSE_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${CODEPULSE_TOKEN}")

resp="$(curl -fsS "${auth[@]}" -H "Content-Type: application/json" \
  --data-binary @"${REPORT}" "${url}")"

status="$(printf '%s' "${resp}" | python3 -c \
  'import sys,json; print(json.load(sys.stdin).get("gate",{}).get("status",""))')"

echo "CodePulse quality gate: ${status:-unknown}"
if [ "${status}" = "ERROR" ]; then
  echo "Quality gate failed — see CodePulse for failing conditions." >&2
  exit 1
fi
echo "Quality gate passed."
