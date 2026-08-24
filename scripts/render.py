#!/usr/bin/env python3
"""Turn a COMPLETE gate response into the four local surfaces.

Called by scripts/gate.sh with everything passed through the environment. Writes:

  GATE_REPORT_PATH   the report JSON, as returned by the server
  GATE_SARIF_PATH    the SARIF, location-enriched (see below), still valid 2.1.0
  GATE_CONSOLE       the server's console rendering, byte for byte
  GATE_ANNOTATIONS   ::error workflow commands, one per blocking finding
  GATE_SUMMARY       shell-sourceable verdict/exit_code/counts for gate.sh

Exit codes:
  0   files written, GATE_SUMMARY holds a valid verdict
  9   the response is COMPLETE but violates the response contract (gate.sh turns this into the
      fail-closed exit 2). Contract violations are printed to stderr prefixed "MALFORMED:".
  other  unwritable workspace or unparseable JSON — also fail-closed by gate.sh.

WHY FILE:LINE IS RESOLVED HERE AND NOT SERVER-SIDE
--------------------------------------------------
Findings carry no file or line, and they never will: the server evaluates plan JSON and has no
copy of the .tf source the plan was generated from. Terraform's plan JSON does not record the
source file or line of a resource block either. So the only place a source location can be
established is the runner, which is the one participant holding the checkout.

The resolver therefore joins on resource.address, which IS in every finding, by scanning the
workspace for the matching `resource "TYPE" "NAME"` block. That join is the whole mechanism: a
finding whose address does not resolve still annotates, just without a line anchor, because
dropping it would hide a blocking finding from the reviewer who has to act on it.

Python 3 standard library only: jq is not preinstalled on every runner image and installing a
JSON parser inside a security gate is how the gate becomes the flaky step everyone disables.
"""

import json
import os
import re
import sys

# Severity ordering, most severe first, for stable annotation ordering.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Directories never worth walking: provider mirrors contain thousands of vendored .tf files whose
# resource blocks are not this plan's source, and a false match there would anchor an annotation
# to a file the developer cannot edit.
SKIP_DIRS = {".terraform", ".git", "node_modules", ".venv", "__pycache__", "vendor"}

MAX_SCAN_FILES = 5000        # a safety valve on a pathological monorepo checkout
MAX_REMEDIATION_HINT = 160   # keep an annotation to roughly one screen line


# =================================================================================================
# Source resolution: resource.address -> (relative path, line)
# =================================================================================================

def parse_address(address, terraform_type=""):
    """Reduce a terraform resource address to (type, name).

    Handles the real shapes an address arrives in:

      aws_db_instance.public_db                      -> (aws_db_instance, public_db)
      module.db.aws_db_instance.public_db            -> (aws_db_instance, public_db)
      module.a.module.b.aws_db_instance.public_db    -> (aws_db_instance, public_db)
      aws_db_instance.public_db[0]                   -> (aws_db_instance, public_db)
      aws_db_instance.public_db["primary"]           -> (aws_db_instance, public_db)

    The last two dot-segments are type and name. terraform_type, when present, is authoritative
    and is cross-checked against the parse: a mismatch means the address was shaped in a way this
    parser does not understand, and guessing at that point would anchor an annotation to the wrong
    resource — worse than no anchor at all.
    """
    if not address:
        return "", ""

    # Strip a trailing for_each/count key. Only the LAST bracket group is an index; a quoted key
    # can itself contain a dot, so this runs before any splitting.
    text = re.sub(r'\[[^\]]*\]\s*$', '', address.strip())

    # Drop module.<name>. prefixes, repeatedly for nested modules.
    while True:
        stripped = re.sub(r'^module\.[^.]+\.', '', text)
        if stripped == text:
            break
        text = stripped

    parts = [p for p in text.split(".") if p]
    if len(parts) < 2:
        return "", ""
    rtype, rname = parts[-2], parts[-1]

    if terraform_type and rtype != terraform_type:
        # Trust terraform_type and try to recover the name as the segment following it.
        if terraform_type in parts:
            index = parts.index(terraform_type)
            if index + 1 < len(parts):
                return terraform_type, parts[index + 1]
        return "", ""

    return rtype, rname


def scan_tf_files(root):
    """Every .tf file under root, skipping vendored trees. Returns a list of absolute paths."""
    found = []
    if not root or not os.path.isdir(root):
        return found
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".terraform")]
        for filename in filenames:
            if filename.endswith(".tf"):
                found.append(os.path.join(dirpath, filename))
                if len(found) >= MAX_SCAN_FILES:
                    return found
    return found


def build_resource_index(root):
    """Map (type, name) -> list of (relative path, line number).

    One pass over the checkout, because a plan with fifty findings across ten resources would
    otherwise re-read every .tf file fifty times.

    The regex is whitespace-tolerant and quote-tolerant per HCL: `resource "aws_db_instance"
    "public_db" {` with any run of spaces or tabs between tokens. Single quotes are not valid HCL
    string delimiters, so only double quotes are accepted — matching a single-quoted lookalike
    would mean matching something that is not a resource block.
    """
    index = {}
    pattern = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"')
    for path in scan_tf_files(root):
        try:
            with open(path, "r", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    match = pattern.match(line)
                    if match:
                        key = (match.group(1), match.group(2))
                        try:
                            rel = os.path.relpath(path, root)
                        except ValueError:
                            rel = path
                        # Forward slashes: SARIF URIs and GitHub annotation paths both want them,
                        # and a Windows runner would otherwise emit backslashes GitHub ignores.
                        index.setdefault(key, []).append((rel.replace(os.sep, "/"), lineno))
        except OSError:
            # An unreadable file is not a reason to fail a gate; it just cannot contribute a match.
            continue
    return index


class Resolver:
    """Resolves resource addresses to source locations, once per address."""

    def __init__(self, root):
        self.root = root
        self.index = build_resource_index(root)
        self.cache = {}

    def resolve(self, address, terraform_type=""):
        """Returns (path, line, ambiguous). path == "" means unresolved."""
        key = (address, terraform_type)
        if key in self.cache:
            return self.cache[key]

        rtype, rname = parse_address(address, terraform_type)
        result = ("", 0, False)
        if rtype and rname:
            matches = self.index.get((rtype, rname)) or []
            if matches:
                # FIRST MATCH WINS, by sorted path so the choice is deterministic across runners
                # rather than dependent on filesystem walk order. Ambiguity is reported in the
                # message instead of being silently resolved.
                ordered = sorted(matches)
                path, line = ordered[0]
                result = (path, line, len(ordered) > 1)
        self.cache[key] = result
        return result


# =================================================================================================
# Annotations
# =================================================================================================

def escape_property(value):
    """Workflow-command property escaping. Inside the property list % \\r \\n : and , are all
    structural, so an unescaped one silently truncates the annotation."""
    return (value.replace("%", "%25")
                 .replace("\r", "%0D")
                 .replace("\n", "%0A")
                 .replace(":", "%3A")
                 .replace(",", "%2C"))


def escape_data(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def flatten_observed(observed):
    """`{"publicly_accessible": true}` -> `publicly_accessible = true`.

    The observed values are the single most useful thing in the annotation: they tell the developer
    what their plan actually says, not merely which rule fired."""
    if not isinstance(observed, dict) or not observed:
        return ""
    parts = []
    for key in sorted(observed.keys()):
        value = observed[key]
        if value is None:
            rendered = "null"
        elif isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, (int, float)):
            rendered = str(value)
        elif isinstance(value, str):
            rendered = value
        else:
            rendered = json.dumps(value)
        if len(rendered) > 60:
            rendered = rendered[:57] + "..."
        parts.append("{0} = {1}".format(key, rendered))
    return ", ".join(parts)


def first_sentence(text, limit):
    """A remediation excerpt is a paragraph; an annotation has room for a sentence."""
    if not text:
        return ""
    collapsed = " ".join(text.split())
    match = re.match(r'^(.{20,}?[.!?])(\s|$)', collapsed)
    candidate = match.group(1) if match else collapsed
    if len(candidate) > limit:
        candidate = candidate[:limit - 3].rstrip() + "..."
    return candidate


def remediation_hint(remediation):
    """A short, actionable hint. The snippet's `key = value # <- required by this policy` line is
    by far the most useful form when present — it is literally the fix."""
    if not isinstance(remediation, dict):
        return ""
    snippet = remediation.get("snippet")
    if isinstance(snippet, str) and snippet:
        for line in snippet.splitlines():
            if "required by this policy" in line:
                return "fix: " + " ".join(line.split()).replace("# <- required by this policy", "").strip()
    excerpt = remediation.get("text_excerpt")
    if isinstance(excerpt, str) and excerpt:
        hint = first_sentence(excerpt, MAX_REMEDIATION_HINT)
        if hint:
            return hint
    return ""


def finding_sort_key(finding):
    resource = finding.get("resource") or {}
    return (
        SEVERITY_RANK.get(str(finding.get("severity", "")).upper(), 99),
        str(resource.get("address") or ""),
        str(finding.get("rule_name") or finding.get("rule_id") or ""),
    )


def blocking_findings(report):
    """A finding is annotation-worthy IFF blocking is exactly True.

    The report's own `blocking` boolean is the server's decision, already accounting for block_on,
    severity, framework scoping and waivers. Re-deriving it client-side from severity would let the
    action and the platform disagree about what blocks — and the platform is right by definition.
    Anything other than True (False, missing, non-boolean) is not annotated.
    """
    findings = report.get("findings")
    if not isinstance(findings, list):
        return []
    blocking = [f for f in findings if isinstance(f, dict) and f.get("blocking") is True]
    return sorted(blocking, key=finding_sort_key)


def annotation_for(finding, resolver):
    """Render one blocking finding as a CI annotation.

    Returns (line, anchored). `anchored` says whether a real file:line was resolved —
    reported here rather than re-derived from the rendered string, because the two
    providers render differently and only this function knows what it did.
    """
    resource = finding.get("resource") or {}
    address = str(resource.get("address") or "")
    terraform_type = str(resource.get("terraform_type") or "")

    rule = str(finding.get("rule_name") or finding.get("rule_id") or "policy violation")
    severity = str(finding.get("severity") or "").upper()

    path, line, ambiguous = resolver.resolve(address, terraform_type)

    # Message: what fired, how bad, on what, what the plan says, and how to fix it.
    segments = []
    segments.append("{0} [{1}]".format(rule, severity) if severity else rule)
    if address:
        segments.append("on " + address)

    observed = flatten_observed(finding.get("observed"))
    if observed:
        segments.append("observed " + observed)

    expected = finding.get("expected_summary")
    if isinstance(expected, str) and expected.strip():
        segments.append(first_sentence(expected, 200))

    hint = remediation_hint(finding.get("remediation"))
    if hint:
        segments.append(hint)

    message = " -- ".join(s for s in segments if s)

    if ambiguous:
        message += " (NOTE: several .tf files declare this resource; anchored to {0})".format(path)

    props = ["title=imPAC tfgate"]
    if path:
        props.append("file=" + escape_property(path))
        props.append("line=" + str(line))
    else:
        # Unresolved: the address goes in the message so the developer can still find the block by
        # grep, and the annotation lands on the job log rather than the diff.
        if address:
            message += " (source location unresolved for {0}; annotation not anchored to a file)".format(address)
        else:
            message += " (no resource address in the finding; annotation not anchored to a file)"

    anchored = bool(path)

    # GitHub parses ::workflow commands out of the log and hoists them onto the PR diff.
    # GitLab parses nothing, so there the same content is written as a plain prefixed line
    # carrying file:line inline — it lands in the job log, which is where a GitLab reviewer
    # reads it. Deliberately NOT a Code Quality or SAST artifact: those render in the MR
    # widget rather than on the diff, require a per-finding fingerprint, and pin us to their
    # schema versioning. The server-rendered console output is the primary human surface on
    # both providers regardless.
    if os.environ.get("GATE_CI") == "gitlab":
        location = "{0}:{1}: ".format(path, line) if path else ""
        return "imPAC tfgate [error]: {0}{1}".format(location, message), anchored

    return "::error {0}::{1}".format(",".join(props), escape_data(message)), anchored


# =================================================================================================
# SARIF enrichment
# =================================================================================================

def sarif_address_of(result):
    """The resource address for a SARIF result.

    logicalLocations[].fullyQualifiedName is where the server puts it (kind == "resource"), and
    properties.terraform_type carries the type — a structured join key, so no message parsing.
    """
    address = ""
    for location in result.get("locations") or []:
        if not isinstance(location, dict):
            continue
        for logical in location.get("logicalLocations") or []:
            if isinstance(logical, dict) and isinstance(logical.get("fullyQualifiedName"), str):
                address = logical["fullyQualifiedName"]
                break
        if address:
            break
    if not address:
        props = result.get("properties")
        if isinstance(props, dict) and isinstance(props.get("address"), str):
            address = props["address"]
    return address


def sarif_terraform_type(result):
    props = result.get("properties")
    if isinstance(props, dict) and isinstance(props.get("terraform_type"), str):
        return props["terraform_type"]
    return ""


def enrich_sarif(sarif, resolver):
    """Inject artifactLocation/region into results that lack a real physical location.

    Results that ALREADY carry a usable physicalLocation are left untouched — if a future server
    build learns real locations, this must not overwrite them with a client-side guess.

    A result that resolves to nothing keeps whatever it had. SARIF permits a result with only a
    logicalLocation, so the document stays valid 2.1.0 either way; code scanning simply shows those
    without a line anchor.

    Returns the number of results enriched.
    """
    if not isinstance(sarif, dict):
        return 0
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        return 0

    enriched = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue

            locations = result.get("locations")
            if not isinstance(locations, list) or not locations:
                locations = [{}]
                result["locations"] = locations

            target = locations[0]
            if not isinstance(target, dict):
                continue

            physical = target.get("physicalLocation")
            if isinstance(physical, dict):
                artifact = physical.get("artifactLocation")
                region = physical.get("region")
                has_uri = isinstance(artifact, dict) and bool(artifact.get("uri"))
                has_line = isinstance(region, dict) and isinstance(region.get("startLine"), int) \
                    and region["startLine"] > 0
                if has_uri and has_line:
                    continue  # already located; leave the server's answer alone

            address = sarif_address_of(result)
            if not address:
                continue
            path, line, _ = resolver.resolve(address, sarif_terraform_type(result))
            if not path:
                continue

            target["physicalLocation"] = {
                "artifactLocation": {"uri": path},
                "region": {"startLine": line},
            }
            enriched += 1
    return enriched


# =================================================================================================
# Wiring
# =================================================================================================

def write_document(path, value):
    """Write a server-returned document. Returns the path written, or None when there was nothing
    to write."""
    if value is None or not path:
        return None
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w") as fh:
        if isinstance(value, str):
            fh.write(value if value.endswith("\n") else value + "\n")
        else:
            json.dump(value, fh, indent=2)
            fh.write("\n")
    return path


def as_mapping(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def coerce_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def refuse(message):
    sys.stderr.write("MALFORMED:" + message + "\n")
    sys.exit(9)


def main():
    with open(os.environ["GATE_STATUS_FILE"]) as fh:
        doc = json.load(fh)

    report = as_mapping(doc.get("report"))
    sarif = doc.get("sarif")
    if isinstance(sarif, str):
        try:
            sarif = json.loads(sarif)
        except ValueError:
            pass

    source_dir = os.environ.get("GATE_SOURCE_DIR") or "."
    resolver = Resolver(source_dir)

    blocking = blocking_findings(report)
    # annotation_for reports whether it anchored, rather than this counting "file=" in the
    # rendered string: that re-parse was provider-specific (it split on "::", which the GitLab
    # plain-text form does not contain) and turned a real BLOCKED verdict into a TOOL ERROR.
    rendered = [annotation_for(f, resolver) for f in blocking]
    lines = [line for line, _ in rendered]
    anchored = sum(1 for _, is_anchored in rendered if is_anchored)

    enriched = enrich_sarif(sarif, resolver) if isinstance(sarif, dict) else 0

    report_path = write_document(os.environ["GATE_REPORT_PATH"], doc.get("report"))
    sarif_path = write_document(os.environ["GATE_SARIF_PATH"], sarif)

    # The console text is the SERVER's rendering, reproduced byte for byte.
    console = doc.get("console")
    with open(os.environ["GATE_CONSOLE"], "w") as fh:
        if isinstance(console, str) and console:
            fh.write(console if console.endswith("\n") else console + "\n")

    with open(os.environ["GATE_ANNOTATIONS"], "w") as fh:
        for line in lines:
            fh.write(line + "\n")

    # THE VERDICT IS THE SERVER'S and this client refuses to invent one. A COMPLETE response with
    # no verdict, no usable exit_code, or a verdict that contradicts its own exit_code is
    # malformed: fail closed rather than default to zero.
    verdict = doc.get("verdict")
    verdict = verdict.strip().upper() if isinstance(verdict, str) else ""
    exit_code = coerce_int(doc.get("exit_code"))

    if verdict not in ("PASS", "BLOCKED"):
        refuse("COMPLETE response carried verdict {0!r}, expected PASS or BLOCKED".format(doc.get("verdict")))
    if exit_code is None:
        refuse("COMPLETE response carried no numeric exit_code")
    if exit_code not in (0, 1, 2):
        refuse("COMPLETE response carried exit_code {0!r}, outside the frozen 0/1/2 contract".format(exit_code))
    if (verdict == "PASS") != (exit_code == 0):
        refuse("COMPLETE response is self-contradictory: verdict {0} with exit_code {1}".format(verdict, exit_code))

    blocked_count = coerce_int(doc.get("blocked_count"))
    if blocked_count is None:
        decision = report.get("decision")
        if isinstance(decision, dict) and isinstance(decision.get("blocked_by"), list):
            blocked_count = len(decision["blocked_by"])
    findings_count = coerce_int(doc.get("findings_count"))
    if findings_count is None and isinstance(report.get("findings"), list):
        findings_count = len(report["findings"])

    # Sourced by gate.sh, so every value is single-quoted: a path can contain anything, and an
    # unquoted assignment would be re-evaluated by the shell.
    with open(os.environ["GATE_SUMMARY"], "w") as fh:
        fh.write("verdict='{0}'\n".format(verdict))
        fh.write("exit_code='{0}'\n".format(exit_code))
        fh.write("blocked_count='{0}'\n".format(blocked_count if blocked_count is not None else len(blocking)))
        fh.write("findings_count='{0}'\n".format(findings_count if findings_count is not None else ""))
        fh.write("annotation_count='{0}'\n".format(len(lines)))
        fh.write("anchored_count='{0}'\n".format(anchored))
        fh.write("sarif_enriched_count='{0}'\n".format(enriched))
        fh.write("report_path='{0}'\n".format(report_path or ""))
        fh.write("sarif_path='{0}'\n".format(sarif_path or ""))


if __name__ == "__main__":
    main()
