#!/usr/bin/env bash
#
# imPAC tfgate — the whole client, in one script.
#
# The evaluation happens on your own imPAC deployment. This script only moves bytes: it registers
# an evaluation, uploads the plan to a presigned URL, asks the server to start, polls until the
# server renders a verdict, then reproduces that verdict locally (files, console output,
# annotations, exit code). It decides nothing about policy.
#
# THE EXIT CONTRACT IS PUBLIC API AND IT IS FAIL-CLOSED:
#
#   0  PASS        server returned COMPLETE + PASS. The ONLY zero exit in this file.
#   1  BLOCKED     server returned COMPLETE + BLOCKED. A real policy verdict.
#   2  TOOL ERROR  no verdict was rendered: timeout, auth failure, non-2xx, FAILED status,
#                  malformed JSON, missing plan file. The plan has NOT been judged.
#
# Never collapse 1 and 2. Treat every non-zero as "policy failure" and a corrupt plan reads as a
# blocked deploy (noisy but safe); treat every non-zero as "tool flake" and retry-then-continue
# waves an unevaluated plan through (silent and fatal). Hence: every failure path here routes
# through die(), which exits 2 with a message naming what happened.

set -uo pipefail

# ---------------------------------------------------------------------------------------------
# Inputs (env, never argv — a token in a command line lands in process listings and in any log
# that echoes the command).
# ---------------------------------------------------------------------------------------------
API_URL="${INPUT_API_URL:-}"
PIPELINE_KEY="${INPUT_PIPELINE_KEY:-}"
PLAN_JSON="${INPUT_PLAN_JSON:-}"
# Where to look for the .tf source when resolving file:line. Findings carry a resource address but
# no source location — the server evaluates plan JSON and never sees the .tf files — so the runner
# is the only participant that can establish one. See scripts/render.py.
SOURCE_DIR="${INPUT_SOURCE_DIR:-.}"
BLOCK_ON="${INPUT_BLOCK_ON:-high}"
FRAMEWORKS="${INPUT_FRAMEWORKS:-}"
FRAMEWORK_BLOCK_ON="${INPUT_FRAMEWORK_BLOCK_ON:-}"
TIMEOUT_MINUTES="${INPUT_TIMEOUT_MINUTES:-10}"
POLL_INTERVAL_SECONDS="${INPUT_POLL_INTERVAL_SECONDS:-10}"
REPORT_PATH="${INPUT_REPORT_PATH:-report.json}"
SARIF_PATH="${INPUT_SARIF_PATH:-report.sarif}"

# AUTH HEADER SHAPE.
#
# The gate API matches the Authorization header value verbatim against the pipeline key, so the
# header must carry the BARE token:
#   Authorization: <token>            (correct)
#   Authorization: Bearer <token>     (401 — the lookup misses)
#
# The two overrides exist so a deployment that fronts the API with a proxy expecting a different
# header name or a prefix can be accommodated without changing this script.
AUTH_HEADER_NAME="${GATE_AUTH_HEADER_NAME:-Authorization}"
AUTH_HEADER_PREFIX="${GATE_AUTH_HEADER_PREFIX:-}"

# Where step outputs go. Outside Actions (local tests) this is a throwaway file.
GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/null}"

# ---------------------------------------------------------------------------------------------
# CI PROVIDER
#
# One script, two providers. The submit/poll/verdict/fail-closed logic is identical everywhere and
# must stay in ONE place: if it were forked per provider, the half that drifts is the half that
# decides whether a plan was judged at all.
#
# Only three things actually differ, and each is isolated behind a function below:
#   1. where the run's provenance comes from (GITHUB_* vs CI_*)
#   2. how a step output is published  (GITHUB_OUTPUT file vs a dotenv artifact)
#   3. how a log annotation is written (::workflow commands vs plain prefixed lines)
#
# Autodetected, because both runners set an unambiguous marker of their own. The override exists
# for a runner that sets neither (a container invoked by hand) or somehow sets both.
CI_PROVIDER="${INPUT_CI_PROVIDER:-auto}"
if [ "$CI_PROVIDER" = "auto" ]; then
    if [ -n "${GITLAB_CI:-}" ]; then
        CI_PROVIDER="gitlab"
    elif [ -n "${GITHUB_ACTIONS:-}" ]; then
        CI_PROVIDER="github"
    else
        # Not "fail": the gate must still run for someone driving the script directly, and the
        # GitHub emitters degrade to readable plain text anywhere. Provenance is simply absent,
        # which every consumer already tolerates.
        CI_PROVIDER="github"
    fi
fi
case "$CI_PROVIDER" in
    github|gitlab) ;;
    *)
        printf '::error title=imPAC tfgate::TOOL ERROR — unknown ci-provider %s (expected github or gitlab)\n' "$CI_PROVIDER"
        exit 2 ;;
esac

# GitLab has no $GITHUB_OUTPUT equivalent. Its idiom is a dotenv report artifact, which the job
# declares as artifacts:reports:dotenv so later jobs can consume the values as variables.
GATE_DOTENV="${INPUT_DOTENV_PATH:-gate.env}"

# Provenance, per provider. One field per call so the mapping reads as a table and a new provider
# is a new case rather than a new copy of the create-request builder.
#
# All best-effort: an absent variable yields an empty string, which the request builder omits
# rather than sending as "". This is DISPLAY CONTEXT ONLY — the server persists it against a
# closed allow-list and never branches on it, because everything here is controlled by whoever
# holds the pipeline key.
gate_prov() {
    if [ "$CI_PROVIDER" = "gitlab" ]; then
        case "$1" in
            # CI_PROJECT_PATH nests: "group/subgroup/project" is ordinary on GitLab.
            repo)        printf '%s' "${CI_PROJECT_PATH:-}" ;;
            ref)         printf '%s' "${CI_COMMIT_REF_NAME:-}" ;;
            sha)         printf '%s' "${CI_COMMIT_SHA:-}" ;;
            ref_name)    printf '%s' "${CI_COMMIT_REF_NAME:-}" ;;
            event)       printf '%s' "${CI_PIPELINE_SOURCE:-}" ;;
            # The user who started the PIPELINE, except on a manual job where GitLab reports
            # whoever started the JOB. Either way it is the human a reviewer wants, which is the
            # question this field answers.
            actor)       printf '%s' "${GITLAB_USER_LOGIN:-}" ;;
            # CI_PIPELINE_NAME is only set when the project defines workflow:name, which most do
            # not, so fall back to the stage rather than sending nothing.
            workflow)    printf '%s' "${CI_PIPELINE_NAME:-${CI_JOB_STAGE:-}}" ;;
            # ID is instance-unique and is what the pipeline URL needs; IID is the per-project
            # number a human recognises. Both are recorded.
            run_id)      printf '%s' "${CI_PIPELINE_ID:-}" ;;
            run_number)  printf '%s' "${CI_PIPELINE_IID:-}" ;;
            # No analogue: a GitLab retry creates a new job rather than incrementing an attempt.
            run_attempt) printf '%s' "" ;;
            job)         printf '%s' "${CI_JOB_NAME:-}" ;;
            # IID, not ID — the per-project number that appears in the MR URL. Set ONLY on
            # merge-request pipelines, so this is legitimately empty on a branch pipeline.
            pr)          printf '%s' "${CI_MERGE_REQUEST_IID:-}" ;;
            # The only reliable link base for a self-managed or Dedicated instance. Sent even on
            # gitlab.com, where it is redundant with repo, so the reader never guesses a host.
            project_url) printf '%s' "${CI_PROJECT_URL:-}" ;;
            *)           printf '%s' "" ;;
        esac
        return
    fi

    case "$1" in
        repo)        printf '%s' "${GITHUB_REPOSITORY:-}" ;;
        ref)         printf '%s' "${GITHUB_REF:-}" ;;
        sha)         printf '%s' "${GITHUB_SHA:-}" ;;
        ref_name)    printf '%s' "${GITHUB_REF_NAME:-}" ;;
        event)       printf '%s' "${GITHUB_EVENT_NAME:-}" ;;
        actor)       printf '%s' "${GITHUB_ACTOR:-}" ;;
        workflow)    printf '%s' "${GITHUB_WORKFLOW:-}" ;;
        run_id)      printf '%s' "${GITHUB_RUN_ID:-}" ;;
        run_number)  printf '%s' "${GITHUB_RUN_NUMBER:-}" ;;
        run_attempt) printf '%s' "${GITHUB_RUN_ATTEMPT:-}" ;;
        job)         printf '%s' "${GITHUB_JOB:-}" ;;
        # GitHub does not expose the PR number directly; it is derived from the ref in the
        # request builder, which sees the event name and the ref together.
        pr)          printf '%s' "" ;;
        # github.com is the only host, so there is no base to record.
        project_url) printf '%s' "" ;;
        *)           printf '%s' "" ;;
    esac
}

MAX_PLAN_BYTES=67108864   # 64 MiB — the server's documented cap. Refuse locally rather than
                          # burn an upload and collect a 400.

# ---------------------------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------------------------

log()    { printf '%s\n' "$*" >&2; }

# Annotations. GitHub parses ::workflow commands out of the log and hoists them into the job
# summary and the PR diff. GitLab parses nothing, so there the same text is written as a plain
# prefixed line — it lands in the job log, which is where a GitLab reviewer reads it.
#
# NOT emitted as a GitLab Code Quality or SAST artifact: those render in the merge-request widget
# rather than on the diff, need a fingerprint per finding, and pin us to their schema versioning.
# The console output the server renders is the primary human surface on both providers anyway.
annotate() {
    # $1 = error|warning|notice, $2 = message
    if [ "$CI_PROVIDER" = "gitlab" ]; then
        printf 'imPAC tfgate [%s]: %s\n' "$1" "$2"
    else
        printf '::%s title=imPAC tfgate::%s\n' "$1" "$2"
    fi
}

notice() { annotate notice "$*"; }

# Step outputs. On GitHub these are real step outputs another step can reference; on GitLab they
# are written to a dotenv file the job exposes via artifacts:reports:dotenv. Keys are upper-cased
# and dashes become underscores there, because a dotenv key must be a valid shell identifier —
# "exit-code" would be silently unusable as a variable.
emit_output() {
    if [ "$CI_PROVIDER" = "gitlab" ]; then
        local key
        key=$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')
        printf 'GATE_%s=%s\n' "$key" "$2" >> "$GATE_DOTENV"
    else
        printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
    fi
}

# Every abnormal termination goes through here. One place, one exit code, always a reason.
die() {
    annotate error "TOOL ERROR — $*"
    log "imPAC tfgate: TOOL ERROR — $*"
    log "imPAC tfgate: this is NOT a policy verdict. The plan has not been judged; do not merge on the strength of this run."
    emit_output "verdict" ""
    emit_output "exit-code" "2"
    exit 2
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "required command '$1' is not on PATH"
}

# Reads a dotted field out of a JSON file; empty string when absent, rc 3 when unparseable.
# python3 stdlib only: jq is NOT preinstalled on every runner image, and adding an install step
# to a gate is how a gate becomes flaky.
json_get() {
    JG_FILE="$1" JG_PATH="$2" python3 -c '
import json, os, sys
try:
    with open(os.environ["JG_FILE"]) as fh:
        doc = json.load(fh)
except Exception:
    sys.exit(3)
cur = doc
for part in os.environ["JG_PATH"].split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        sys.exit(0)
if cur is None:
    sys.exit(0)
if isinstance(cur, bool):
    sys.stdout.write("true" if cur else "false")
elif isinstance(cur, (dict, list)):
    sys.stdout.write(json.dumps(cur))
else:
    sys.stdout.write(str(cur))
'
}

# Best-effort extraction of the server's own error text, truncated so a stray HTML error page
# does not paste a kilobyte into the log.
# True when the body is an API-LEVEL failure: the /it family reports application
# errors with HTTP 200 as {"error": "...", "status": {...}} instead of a 4xx/5xx, so
# a 2xx alone is not proof of success.
#
# This runs AFTER unwrap_envelope (http() unwraps before returning), so a successful
# call has already been reduced to the handler's own payload. That matters for the one
# ambiguous case: a poll of a FAILED evaluation is a SUCCESSFUL call whose payload
# carries an "error" explaining why the worker failed. Post-unwrap both shapes have a
# top-level "error", so the discriminator is whether the body also looks like an
# evaluation row — a row has uid/status, an API error has only error + status object.
has_error_body() {
    HE_FILE="$BODY_FILE" python3 -c '
import json, os, sys
try:
    with open(os.environ["HE_FILE"]) as fh:
        doc = json.load(fh)
except Exception:
    sys.exit(1)
if not isinstance(doc, dict):
    sys.exit(1)
if not (isinstance(doc.get("error"), str) and doc["error"]):
    sys.exit(1)
# An evaluation row (uid, or a string status like REQUESTED/RUNNING/FAILED) is a
# successful response whose payload reports a worker-side failure. The poll loop
# renders that with the row own message, so do not intercept it here.
if doc.get("uid") or isinstance(doc.get("status"), str):
    sys.exit(1)
sys.exit(0)
' 2>/dev/null
}

server_error() {
    [ -s "$BODY_FILE" ] || { printf 'no response body.'; return 0; }
    SE_FILE="$BODY_FILE" python3 -c '
import json, os
raw = open(os.environ["SE_FILE"], "rb").read()[:4096].decode("utf-8", "replace")
try:
    doc = json.loads(raw)
    msg = None
    if isinstance(doc, dict):
        for key in ("error", "message", "Message", "detail", "errorMessage"):
            if isinstance(doc.get(key), str) and doc[key]:
                msg = doc[key]
                break
    if msg is None:
        msg = json.dumps(doc)[:400]
except Exception:
    msg = " ".join(raw.split())[:400]
print("server said: " + msg)
' 2>/dev/null || printf 'server response was not readable.'
}

# curl wrapper: body to $BODY_FILE, HTTP status to stdout. Deliberately NOT --fail — we want the
# body of a 4xx so the server's error message reaches the user instead of "curl exited 22".
BODY_FILE=""
http() {
    local method="$1" url="$2" data_file="${3:-}"
    local args=(-sS -X "$method" -o "$BODY_FILE" -w '%{http_code}'
                --connect-timeout 15 --max-time 120
                -H "${AUTH_HEADER_NAME}: ${AUTH_HEADER_PREFIX}${PIPELINE_KEY}"
                -H 'Accept: application/json')
    if [ -n "$data_file" ]; then
        args+=(-H 'Content-Type: application/json' --data-binary "@${data_file}")
    fi
    local code
    code=$(curl "${args[@]}" "$url" 2>/dev/null || true)
    unwrap_envelope
    printf '%s' "$code"
}

# The API wraps every successful result in an envelope: the payload arrives as
# {"data":{"uid":...},"status":{...}} rather than {"uid":...}. Errors arrive as
# {"error":"...","status":{...}} with the SAME HTTP 200 — the API signals application
# failure in the body rather than in the status line.
#
# Rewrite the body in place to whatever the payload actually is, so every reader
# downstream — json_get here, and render.py, which loads this same file — sees the
# result at the top level and needs to know nothing about the envelope. An unwrapped
# body (a presigned-S3 error, say) is left untouched.
unwrap_envelope() {
    [ -s "$BODY_FILE" ] || return 0
    UE_FILE="$BODY_FILE" python3 -c '
import json, os, sys
path = os.environ["UE_FILE"]
try:
    with open(path) as fh:
        doc = json.load(fh)
except Exception:
    sys.exit(0)                      # not JSON: leave it for the caller to report verbatim
if not isinstance(doc, dict):
    sys.exit(0)
# An application error is surfaced, not unwrapped: check_status/server_error read
# "error" from the top level and must keep seeing it.
if "error" in doc:
    sys.exit(0)
if "data" in doc and isinstance(doc["data"], dict):
    with open(path, "w") as fh:
        json.dump(doc["data"], fh)
' 2>/dev/null || true
}

# 401/403 get their own message: an auth failure looks nothing like a policy problem, and telling
# a user "the gate is broken" when their key is wrong wastes an afternoon.
check_status() {
    local code="$1" what="$2"
    # HTTP status is judged FIRST: 401/403 and 5xx have their own diagnostics below,
    # and an auth failure told "the request failed" instead of "your key is wrong"
    # wastes an afternoon. Only a 2xx falls through to the body check.
    case "$code" in
        2??)
            # The API reports APPLICATION failure in the body with HTTP 200, so a
            # 2xx alone is not proof of success — detect errors by body shape, not by
            # status code. Left unchecked, such a body would be
            # read as a valid response and fail further downstream complaining about a
            # missing field, hiding the server's actual message. unwrap_envelope
            # deliberately leaves these bodies alone so the "error" key is still here.
            if [ -s "$BODY_FILE" ] && has_error_body; then
                die "$what failed. $(server_error)"
            fi
            return 0 ;;
        401|403)
            die "$what was rejected with HTTP $code — the pipeline key is missing, revoked, expired, or not scoped CI_SCANNER. $(server_error)" ;;
        000|"")
            die "$what could not reach ${API_URL} (connection failed, DNS, or TLS). $(server_error)" ;;
        *)
            die "$what returned HTTP $code. $(server_error)" ;;
    esac
}

# ---------------------------------------------------------------------------------------------
# Validate inputs before touching the network
# ---------------------------------------------------------------------------------------------

need curl
need python3

[ -n "$API_URL" ]      || die "api-url is empty"
[ -n "$PIPELINE_KEY" ] || die "pipeline-key is empty — pass it from a secret, never a literal"
[ -n "$PLAN_JSON" ]    || die "plan-json is empty"
[ -f "$PLAN_JSON" ]    || die "plan file '$PLAN_JSON' does not exist — did 'terraform show -json' run?"
[ -s "$PLAN_JSON" ]    || die "plan file '$PLAN_JSON' is empty"

case "$BLOCK_ON" in
    critical|high|medium|low) ;;
    *) die "block-on must be one of critical|high|medium|low, got '$BLOCK_ON'" ;;
esac
if [ -n "$FRAMEWORK_BLOCK_ON" ]; then
    case "$FRAMEWORK_BLOCK_ON" in
        critical|high|medium|low) ;;
        *) die "framework-block-on must be one of critical|high|medium|low, got '$FRAMEWORK_BLOCK_ON'" ;;
    esac
fi
case "$TIMEOUT_MINUTES" in ''|*[!0-9.]*) die "timeout-minutes must be a number, got '$TIMEOUT_MINUTES'" ;; esac
case "$POLL_INTERVAL_SECONDS" in ''|*[!0-9.]*) die "poll-interval-seconds must be a number, got '$POLL_INTERVAL_SECONDS'" ;; esac

# Strip a trailing slash so the URLs below concatenate cleanly whichever way api-url was written.
API_URL="${API_URL%/}"
GATE_BASE="${API_URL}/it/v3/gate/evaluations"

WORK_DIR=$(mktemp -d) || { annotate error "TOOL ERROR — could not create a temporary directory"; exit 2; }
# Also removes the request bodies, which is where the presigned URL lives.
trap 'rm -rf "$WORK_DIR"' EXIT
BODY_FILE="${WORK_DIR}/body.json"

PLAN_SIZE=$(python3 -c 'import os,sys; sys.stdout.write(str(os.path.getsize(sys.argv[1])))' "$PLAN_JSON") \
    || die "could not size the plan file '$PLAN_JSON'"
[ "$PLAN_SIZE" -le "$MAX_PLAN_BYTES" ] \
    || die "plan file is ${PLAN_SIZE} bytes, over the ${MAX_PLAN_BYTES}-byte server limit"

# A plan that is not valid JSON would be rejected by the server after a pointless upload, and the
# resulting 4xx would read like an imPAC outage rather than a broken pipeline step. The usual
# cause is `terraform show -json` output polluted by the setup-terraform wrapper's stdout.
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$PLAN_JSON" 2>/dev/null \
    || die "plan file '$PLAN_JSON' is not valid JSON — if you use hashicorp/setup-terraform, set terraform_wrapper: false"

log "imPAC tfgate: evaluating '${PLAN_JSON}' (${PLAN_SIZE} bytes) on ${API_URL}"

# ---------------------------------------------------------------------------------------------
# 1. CREATE — register the evaluation, get a presigned PUT back
# ---------------------------------------------------------------------------------------------

CREATE_REQ="${WORK_DIR}/create.json"
GATE_PLAN_SIZE="$PLAN_SIZE" \
GATE_BLOCK_ON="$BLOCK_ON" \
GATE_FRAMEWORKS="$FRAMEWORKS" \
GATE_FRAMEWORK_BLOCK_ON="$FRAMEWORK_BLOCK_ON" \
GATE_CI="$CI_PROVIDER" \
GATE_REPO="$(gate_prov repo)" \
GATE_REF="$(gate_prov ref)" \
GATE_SHA="$(gate_prov sha)" \
GATE_REF_NAME="$(gate_prov ref_name)" \
GATE_EVENT="$(gate_prov event)" \
GATE_ACTOR="$(gate_prov actor)" \
GATE_WORKFLOW="$(gate_prov workflow)" \
GATE_RUN_ID="$(gate_prov run_id)" \
GATE_RUN_NUMBER="$(gate_prov run_number)" \
GATE_RUN_ATTEMPT="$(gate_prov run_attempt)" \
GATE_JOB="$(gate_prov job)" \
GATE_PR="$(gate_prov pr)" \
GATE_PROJECT_URL="$(gate_prov project_url)" \
GATE_OUT="$CREATE_REQ" \
python3 -c '
import json, os

body = {
    "plan_size": int(os.environ["GATE_PLAN_SIZE"]),
    "block_on": os.environ["GATE_BLOCK_ON"],
}

# CSV in, array out. Blank entries are dropped rather than sent as "" — an empty framework id
# would scope the report to nothing and silently produce an empty report.
frameworks = [f.strip() for f in os.environ["GATE_FRAMEWORKS"].split(",") if f.strip()]
if frameworks:
    body["frameworks"] = frameworks

if os.environ["GATE_FRAMEWORK_BLOCK_ON"]:
    body["framework_block_on"] = os.environ["GATE_FRAMEWORK_BLOCK_ON"]

# Provenance, best-effort: absent outside Actions, and omitted rather than sent empty. This is
# DISPLAY CONTEXT ONLY -- the server persists it against a closed allow-list and never branches
# on it, because everything here is controlled by whoever holds the pipeline key.
#
# GATE_ACTOR answers "who triggered this run", which is NOT the same question as "whose key was
# used": one org-wide pipeline key signs every run, so the key owner is constant and useless for
# attribution while the actor is the human a reviewer actually wants to find.
source = {}
for key, var in (
    ("repo", "GATE_REPO"),
    ("ref", "GATE_REF"),
    ("sha", "GATE_SHA"),
    ("actor", "GATE_ACTOR"),
    ("event", "GATE_EVENT"),
    ("workflow", "GATE_WORKFLOW"),
    ("run_id", "GATE_RUN_ID"),
    ("run_number", "GATE_RUN_NUMBER"),
    ("run_attempt", "GATE_RUN_ATTEMPT"),
    ("job", "GATE_JOB"),
    # Which CI system produced this run. The server validates the value and drops an
    # unrecognised one; it also treats ABSENT as github, so an older client stays correct.
    ("ci", "GATE_CI"),
    # Only GitLab sends this. The server requires https and drops anything else.
    ("project_url", "GATE_PROJECT_URL"),
):
    value = os.environ.get(var, "")
    if value:
        source[key] = value

# The change-request number, resolved per provider.
#
# GitLab hands it over directly as CI_MERGE_REQUEST_IID (merge-request pipelines only), so it
# arrives pre-resolved in GATE_PR and needs no parsing. GitHub does NOT expose it as a variable
# at all: on pull_request events GITHUB_REF_NAME is "<number>/merge", so the number has to be
# split out of the ref. Deliberately not applied to GitLab — CI_COMMIT_REF_NAME there is a plain
# branch name, and a branch that happens to contain a slash would yield a garbage MR number.
pr = os.environ.get("GATE_PR", "")
if pr:
    source["pr"] = pr
elif os.environ.get("GATE_CI", "github") == "github":
    ref_name = os.environ["GATE_REF_NAME"]
    if os.environ["GATE_EVENT"].startswith("pull_request") and "/" in ref_name:
        source["pr"] = ref_name.split("/")[0]

if source:
    body["source"] = source

with open(os.environ["GATE_OUT"], "w") as fh:
    json.dump(body, fh)
' || die "could not build the create request body"

CODE=$(http POST "$GATE_BASE" "$CREATE_REQ")
check_status "$CODE" "create (POST /it/v3/gate/evaluations)"

EVAL_UID=$(json_get "$BODY_FILE" "uid") || die "create returned a body that is not JSON. $(server_error)"
UPLOAD_URL=$(json_get "$BODY_FILE" "upload_url")
[ -n "$EVAL_UID" ]   || die "create succeeded but returned no uid. $(server_error)"
[ -n "$UPLOAD_URL" ] || die "create succeeded but returned no upload_url. $(server_error)"

log "imPAC tfgate: evaluation ${EVAL_UID} created"

# ---------------------------------------------------------------------------------------------
# 2. UPLOAD — presigned PUT
#
# The presigned URL carries its own auth in the query string. Sending our Authorization header
# to it as well would make S3 reject the request (SigV4 signs the header set), so this call
# deliberately does NOT reuse http().
# ---------------------------------------------------------------------------------------------

UP_CODE=$(curl -sS -X PUT -T "$PLAN_JSON" \
    -H 'Content-Type: application/json' \
    --connect-timeout 15 --max-time 600 \
    -o "$BODY_FILE" -w '%{http_code}' \
    "$UPLOAD_URL" 2>/dev/null || true)
case "$UP_CODE" in
    2??) ;;
    000|"") die "the plan upload could not reach the presigned URL (connection failed, DNS, or TLS)" ;;
    403)    die "the plan upload was refused with HTTP 403 — the presigned URL expired (300s TTL) or the content type did not match. $(server_error)" ;;
    *)      die "the plan upload returned HTTP ${UP_CODE}. $(server_error)" ;;
esac

log "imPAC tfgate: plan uploaded"

# ---------------------------------------------------------------------------------------------
# 3. START
# ---------------------------------------------------------------------------------------------

CODE=$(http POST "${GATE_BASE}/${EVAL_UID}/start")
check_status "$CODE" "start (POST /it/v3/gate/evaluations/${EVAL_UID}/start)"

log "imPAC tfgate: evaluation dispatched, waiting for the verdict"

# ---------------------------------------------------------------------------------------------
# 4. POLL
#
# A timeout is exit 2, not a pass. The server may well finish afterwards, but this run produced
# no verdict, and "we ran out of patience" must never read as "nothing blocked".
# ---------------------------------------------------------------------------------------------

DEADLINE=$(python3 -c 'import sys,time; sys.stdout.write(str(int(time.time() + float(sys.argv[1]) * 60)))' "$TIMEOUT_MINUTES")
POLL_SLEEP=$(python3 -c 'import sys; sys.stdout.write(str(max(1.0, float(sys.argv[1]))))' "$POLL_INTERVAL_SECONDS")
STATUS_FILE="${WORK_DIR}/status.json"
STATUS=""

while :; do
    NOW=$(python3 -c 'import sys,time; sys.stdout.write(str(int(time.time())))')
    if [ "$NOW" -ge "$DEADLINE" ]; then
        die "timed out after ${TIMEOUT_MINUTES} minute(s) waiting for evaluation ${EVAL_UID} (last status: ${STATUS:-unknown}). No verdict was rendered."
    fi

    CODE=$(http GET "${GATE_BASE}/${EVAL_UID}")
    check_status "$CODE" "poll (GET /it/v3/gate/evaluations/${EVAL_UID})"
    cp "$BODY_FILE" "$STATUS_FILE" || die "could not stage the poll response"

    STATUS=$(json_get "$STATUS_FILE" "status") \
        || die "poll returned a body that is not JSON. $(server_error)"
    case "$STATUS" in
        COMPLETE)
            break ;;
        FAILED)
            SERVER_ERR=$(json_get "$STATUS_FILE" "error")
            die "the server reported evaluation ${EVAL_UID} FAILED: ${SERVER_ERR:-no reason given}" ;;
        REQUESTED|RUNNING)
            log "imPAC tfgate: ${STATUS}…" ;;
        "")
            die "poll response carried no status field. $(server_error)" ;;
        *)
            die "poll returned an unrecognised status '${STATUS}' — this client does not know how to interpret it" ;;
    esac

    sleep "$POLL_SLEEP"
done

# ---------------------------------------------------------------------------------------------
# 5. MATERIALISE — report.json, report.sarif, console, annotations, outputs
#
# One python pass writes all the files and composes the workflow commands. Doing it in one place
# means the annotations are derived from exactly the bytes written to disk, so the Security tab,
# the log and the PR diff can never disagree.
# ---------------------------------------------------------------------------------------------

ANNOTATIONS="${WORK_DIR}/annotations.txt"
CONSOLE="${WORK_DIR}/console.txt"
SUMMARY="${WORK_DIR}/summary.txt"

GATE_CI="$CI_PROVIDER" \
GATE_STATUS_FILE="$STATUS_FILE" \
GATE_REPORT_PATH="$REPORT_PATH" \
GATE_SARIF_PATH="$SARIF_PATH" \
GATE_ANNOTATIONS="$ANNOTATIONS" \
GATE_CONSOLE="$CONSOLE" \
GATE_SUMMARY="$SUMMARY" \
GATE_SOURCE_DIR="$SOURCE_DIR" \
python3 "${GATE_SCRIPT_DIR:-$(dirname "$0")}/render.py"
PY_RC=$?
if [ "$PY_RC" -eq 9 ]; then
    die "the server returned COMPLETE but the response did not satisfy the response contract (see the MALFORMED line above)"
elif [ "$PY_RC" -ne 0 ]; then
    die "could not parse the COMPLETE response from evaluation ${EVAL_UID} (malformed JSON or unwritable workspace)"
fi

# render.py writes these; declared here so `set -u` catches a truncated summary rather than
# letting an empty verdict fall through, and so shellcheck can see where they come from.
verdict=""
exit_code=""
report_path=""
sarif_path=""
blocked_count=""
annotation_count=""
anchored_count=""
sarif_enriched_count=""
# shellcheck disable=SC1090  # a generated file; its contents are asserted below, not by shellcheck
. "$SUMMARY" || die "could not read the parsed verdict summary"

# Belt and braces: if the summary was truncated (disk full mid-write), the values above are still
# empty and this must fail closed rather than emit an empty verdict with a zero exit.
[ -n "$verdict" ] && [ -n "$exit_code" ] \
    || die "the parsed verdict summary was incomplete — refusing to report a verdict this client cannot read"

# THE SERVER'S CONSOLE, VERBATIM, on stdout. It is the primary human surface and it is rendered
# server-side so a cloud verdict reads identically to a local `tfgate` run — output parity is the
# point, so this client never composes its own summary of the findings.
if [ -s "$CONSOLE" ]; then
    cat "$CONSOLE"
else
    log "imPAC tfgate: the server returned no console output for ${EVAL_UID}"
fi

# Annotations after the console: GitHub hoists them into the job summary and the PR diff
# regardless of position, and keeping them last leaves the human-readable block uninterrupted.
if [ -s "$ANNOTATIONS" ]; then
    cat "$ANNOTATIONS"
fi

# Say plainly how many findings got a source anchor. An annotation with no file:line does not
# appear on the PR diff, so a run where nothing resolved looks — to a reviewer skimming the diff —
# exactly like a run with no findings. That has to be visible in the log.
if [ -n "$annotation_count" ] && [ "$annotation_count" != "0" ]; then
    log "imPAC tfgate: ${anchored_count}/${annotation_count} blocking finding(s) anchored to a source line from '${SOURCE_DIR}' (${sarif_enriched_count} SARIF result(s) located)"
    if [ "$anchored_count" = "0" ]; then
        annotate warning "No finding could be matched to a .tf file under ${SOURCE_DIR}, so none are anchored. Point source-dir at the terraform directory that produced this plan."
    fi
fi

emit_output "verdict" "$verdict"
emit_output "exit-code" "$exit_code"
emit_output "report-path" "$report_path"
emit_output "sarif-path" "$sarif_path"
emit_output "blocked-count" "$blocked_count"
emit_output "uid" "$EVAL_UID"

case "$exit_code" in
    0)
        notice "PASS — no blocking findings (evaluation ${EVAL_UID})."
        log "imPAC tfgate: PASS (${EVAL_UID})"
        exit 0 ;;
    1)
        annotate error "BLOCKED — ${blocked_count} blocking finding(s). Evaluation ${EVAL_UID}."
        log "imPAC tfgate: BLOCKED (${EVAL_UID}) — ${blocked_count} blocking finding(s)"
        exit 1 ;;
    *)
        # exit_code 2 from the server means it completed but could not judge. Route it through
        # die() so the fail-closed message is identical wherever it originates.
        die "the server completed evaluation ${EVAL_UID} with exit_code ${exit_code} — it could not render a policy judgment" ;;
esac
