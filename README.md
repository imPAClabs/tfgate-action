# imPAC tfgate

Gate Terraform plans against the live policies on **your** imPAC deployment.

tfgate is a thin client. It uploads your `terraform show -json` output to your own imPAC
deployment, the deployment evaluates the plan against the policies currently active there — the
imPAC rule corpus *and* any custom rules your team has written — and the verdict, the JSON report
and the SARIF come back to the pipeline. Nothing about the judgment happens on the runner, so
there is no rule corpus baked into a binary to go stale and no second place to configure severity
floors: the gate and the imPAC console are the same evaluator reading the same rules.

Both GitHub Actions and GitLab CI are supported. Same client, same server, same exit contract —
only the wrapper differs.

---

## Prerequisites

- An **imPAC deployment**, and its base API URL (e.g. `https://api.yourstack.impac.io`).
- A **pipeline key**, minted in the imPAC console under **Admin → Pipeline Keys**. It is scoped
  `CI_SCANNER`: it can submit plans for evaluation and read back its own results, nothing else.
  Store it as a CI secret — a repository/organisation secret on GitHub, a **masked and protected**
  CI/CD variable on GitLab. Never a literal in a pipeline file.
- A runner with `curl` and `python3`. The client is bash plus the Python 3 standard library only.

---

## GitHub Actions

```yaml
name: terraform-gate

on: [pull_request]

permissions:
  contents: read

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false      # the wrapper rewrites stdout and breaks `show -json`
      - run: |
          terraform init -input=false
          terraform plan -out=tfplan.bin -input=false
          terraform show -json tfplan.bin > plan.json

      - uses: imPAClabs/tfgate-action@v1
        with:
          api-url: https://api.yourstack.impac.io
          pipeline-key: ${{ secrets.IMPAC_PIPELINE_KEY }}
          plan-json: plan.json
          source-dir: .                 # scanned to put findings on the right line of the diff
```

To also publish findings to the GitHub **Security** tab, set `upload-sarif: true` and add
`security-events: write` to the job's `permissions`. Code-scanning upload is available on public
repositories, and on private or internal repositories only with GitHub Advanced Security. Without
it the upload step fails while the gate itself is unaffected — the job log and the inline
annotations still carry the whole verdict.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api-url` | yes | — | Base URL of your imPAC deployment. The action appends the `/it/v3/gate/*` paths itself. |
| `pipeline-key` | yes | — | `CI_SCANNER`-scoped imPAC pipeline key. Pass from a secret. |
| `plan-json` | yes | — | Path to `terraform show -json` output. |
| `source-dir` | no | `.` | Terraform source root, scanned to resolve `file:line` for annotations. Point it at the directory whose `.tf` files produced the plan. |
| `block-on` | no | `high` | Block on findings at or above this severity: `critical`, `high`, `medium`, `low`. |
| `frameworks` | no | — | Comma-separated framework ids to scope the report to. |
| `framework-block-on` | no | — | Severity floor applied to framework-mapped findings. |
| `timeout-minutes` | no | `10` | How long to wait for the verdict. A timeout is exit 2, never a pass. |
| `poll-interval-seconds` | no | `10` | Seconds between status polls. |
| `report-path` | no | `report.json` | Where to write the JSON report. |
| `sarif-path` | no | `report.sarif` | Where to write the SARIF report. |
| `upload-sarif` | no | `false` | Upload the SARIF to GitHub code scanning. |
| `sarif-category` | no | `impac-tfgate` | Code-scanning category for the upload. One category per logical scan — two uploads sharing a category supersede each other. |
| `ci-provider` | no | `auto` | `auto`, `github` or `gitlab`. Autodetected from the runner's own marker variable; set it only for a runner that sets neither. |

Scoping the report never weakens the gate: `frameworks` narrows what the report tallies, but a
blocking finding outside the scoped frameworks still blocks.

### Outputs

| Output | Description |
|---|---|
| `verdict` | `PASS` or `BLOCKED`. Empty when no verdict was rendered (exit 2). |
| `exit-code` | `0`, `1` or `2` — see [Exit codes](#exit-codes). |
| `report-path` | Path to the JSON report written into the workspace. |
| `sarif-path` | Path to the SARIF report written into the workspace. |

---

## GitLab CI

Include the template, pinned to a tag, and give it the two values it needs:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/imPAClabs/tfgate-action/v1/gitlab/tfgate.gitlab-ci.yml'

variables:
  IMPAC_API_URL: 'https://api.yourstack.impac.io'
  # IMPAC_PIPELINE_KEY: set as a MASKED, PROTECTED CI/CD variable in project settings.

terraform-plan:
  stage: build
  image:
    name: hashicorp/terraform:1.9
    entrypoint: [""]        # required: this image's ENTRYPOINT is `terraform` itself, so without
                            # the override GitLab's script lines are passed to terraform as
                            # arguments and the job fails before it runs anything
  script:
    - terraform init && terraform plan -out=tfplan
    - terraform show -json tfplan > plan.json
  artifacts:
    paths: ['plan.json']

terraform-gate:
  extends: .impac_tfgate
  needs: ['terraform-plan']
```

### Variables

Set these under `variables:` on your `terraform-gate` job, or globally.

| Variable | Default | Description |
|---|---|---|
| `IMPAC_API_URL` | — | **Required.** Base URL of your imPAC deployment. |
| `IMPAC_PIPELINE_KEY` | — | **Required.** Set as a masked, protected CI/CD variable — never in the YAML. |
| `IMPAC_PLAN_JSON` | `plan.json` | Path to the plan JSON, passed in as an artifact from the plan job. |
| `IMPAC_SOURCE_DIR` | `.` | Terraform source root, for resolving findings to `file:line`. |
| `IMPAC_BLOCK_ON` | `high` | Severity floor that blocks: `critical`, `high`, `medium`, `low`. |
| `IMPAC_FRAMEWORKS` | — | Comma-separated framework ids to scope the report to. |
| `IMPAC_FRAMEWORK_BLOCK_ON` | — | Severity floor applied to framework-mapped findings. |
| `IMPAC_TIMEOUT_MINUTES` | `10` | How long to wait for the verdict. |
| `IMPAC_POLL_INTERVAL_SECONDS` | `10` | Seconds between status polls. |
| `IMPAC_REPORT_PATH` | `report.json` | Where to write the JSON report. Kept as an artifact. |
| `IMPAC_SARIF_PATH` | `report.sarif` | Where to write the SARIF report. Kept as an artifact. |
| `IMPAC_DOTENV_PATH` | `gate.env` | Dotenv report artifact carrying the outputs. |
| `IMPAC_CLIENT_BASE` | `https://raw.githubusercontent.com/imPAClabs/tfgate-action` | Where the client scripts are fetched from. Repoint at an internal mirror for air-gapped runners. |
| `IMPAC_CLIENT_REF` | `v1` | Ref to fetch the client at. **Pin a tag, not a branch.** |

Outputs land in a dotenv artifact rather than as step outputs, so later jobs read them as ordinary
variables: `GATE_VERDICT`, `GATE_EXIT_CODE`, `GATE_REPORT_PATH`, `GATE_SARIF_PATH`,
`GATE_BLOCKED_COUNT`, `GATE_UID`.

The template's default image is `python:3.12-slim` and it installs `curl` in `before_script`. If
you override `image`, keep `python3` and `curl` available — the client exits with TOOL ERROR
rather than passing when either is missing.

GitLab's `include:` pulls YAML and nothing else, so the template fetches `scripts/gate.sh` and
`scripts/render.py` from the pinned ref and verifies them against `scripts/SHA256SUMS.txt` before
running. A digest mismatch is TOOL ERROR (exit 2), never a pass. The check applies to mirrors too,
so a mirror cannot substitute different bytes without failing closed.

---

## How failures are reported

**The job log.** tfgate prints the server's own console rendering of the verdict, byte for byte,
so a verdict read in CI is identical to the same plan evaluated in the imPAC console.

**Inline annotations (GitHub).** Every blocking finding is emitted as an `::error` workflow command
with `file=` and `line=`, so findings land on the changed lines of a pull-request diff. Each
annotation carries the rule, the severity, the resource address, the observed values from your
plan, and a one-line fix:

```
::error file=main.tf,line=28::AWS-RDS-INSTANCE-PUBLIC [CRITICAL] -- on aws_db_instance.public_db
  -- observed publicly_accessible = true -- RDS DB Instances should prohibit public access
  -- fix: publicly_accessible = false
```

On GitLab the same content is written as plain `imPAC tfgate [error]: file:line: …` lines in the
job log, since GitLab does not parse workflow commands onto the diff.

**SARIF.** Written to `sarif-path` / `IMPAC_SARIF_PATH`, with file and line locations resolved.
On GitHub it can be uploaded to code scanning with `upload-sarif: true`; on GitLab it is kept as
a job artifact.

Findings identify a **resource address** rather than a file and line — the server evaluates plan
JSON and never sees your `.tf` files, and Terraform's plan JSON does not record source locations.
The runner holds the checkout, so tfgate resolves the address by scanning `source-dir` for the
matching `resource "TYPE" "NAME"` block, stripping module prefixes and `count`/`for_each` index
suffixes. A finding that resolves to nothing still annotates, with the address in the message and
no line anchor.

---

## Exit codes

The exit contract is frozen and is public API.

| Code | Meaning | What your pipeline should do |
|---|---|---|
| **0** | PASS | proceed |
| **1** | BLOCKED | stop — the plan violates policy |
| **2** | TOOL ERROR | stop — **the plan was not judged at all** |

**The gate fails closed.** Exit 0 happens in exactly one circumstance: the server returned a
completed evaluation with a `PASS` verdict. Everything else that is not a clean `BLOCKED` is
exit 2 — a timeout, an unreachable API, a rejected or expired pipeline key, any non-2xx response,
a server-side evaluation failure, or a response that does not satisfy the contract. Each exits
with a message naming what happened.

Never collapse 1 and 2. Treat every non-zero as a policy failure and a corrupt plan file reads as
a blocked deploy — noisy, but safe. Treat every non-zero as a tool flake to retry past and an
unevaluated plan sails through, silently. On GitLab, leave `allow_failure` at its default of
`false` for the same reason.

---

## License

`action.yml`, the GitLab template and the scripts under `scripts/` are licensed under Apache-2.0
(see `LICENSE`). The imPAC platform that performs the evaluation, and the rule corpus it applies,
are not covered by that license and are provided under imPAC's commercial terms. See `NOTICE`.

## Support

Issues and feature requests: open an issue on this repository. For rule coverage, framework
mappings, or deployment configuration, contact imPAC support through your usual channel.
