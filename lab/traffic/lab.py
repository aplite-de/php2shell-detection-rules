#!/usr/bin/env python3
"""Traffic generator for the php2shell detection lab.

Purpose: produce the *log artifacts* the blog post detects on. It sends, to the
lab's own containers only, the categories of request the write-up describes
(multipart bodies that drive PHP into a memory_limit fatal; an upload-progress
follow-up) plus benign baseline traffic for a false-positive comparison.

Out of scope on purpose: no heap grooming, no worker targeting, no payload, no
attempt at code execution. The lab validates detection, not exploitation
(detection only, see README). curl does the HTTP work so request framing
stays transparent and inspectable.

Every request is recorded to /logs/markers.jsonl as ground truth for log review.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

# Lab services only; refuse anything else.
TARGETS = {
    "apache-vuln":  {"stack": "apache", "base": "http://apache-vuln"},
    "apache-fixed": {"stack": "apache", "base": "http://apache-fixed"},
    "nginx-vuln":   {"stack": "nginx",  "base": "http://nginx-vuln"},
    "nginx-fixed":  {"stack": "nginx",  "base": "http://nginx-fixed"},
}
MARKERS = os.environ.get("LAB_MARKERS", "/logs/markers.jsonl")
# Status, HTTP version, bytes uploaded, total time: the fields we correlate to logs.
WRITE_OUT = "HTTP %{http_code} h%{http_version} up=%{size_upload}B t=%{time_total}s\n"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def marker(**fields):
    fields["ts"] = now()
    with open(MARKERS, "a") as fh:
        fh.write(json.dumps(fields) + "\n")
    tag = f"{fields.get('scenario','?'):18} {fields.get('target',''):12}"
    print(f"[{fields['ts']}] {tag} -> ", end="", flush=True)


def curl(args, body=None):
    """Run curl, print the one-line outcome, return (rc, stdout)."""
    cmd = ["curl", "-sS", "-o", "/dev/null", "-w", WRITE_OUT, "--max-time", "30", *args]
    proc = subprocess.run(cmd, input=body, capture_output=True)
    out = proc.stdout.decode(errors="replace")
    err = proc.stderr.decode(errors="replace").strip()
    sys.stdout.write(out if out else (err + "\n"))
    return proc.returncode, out


def multipart_empty_parts(boundary, parts, nesting):
    """A multipart/form-data body of many empty file parts whose field names are
    deeply nested AND unique per part, so the parser allocates a fresh chain of
    hash tables for each one instead of reusing a shared array. Small on the
    wire, expensive to parse: this is what drives the heap past memory_limit.
    No file content is sent."""
    chunks = []
    for i in range(parts):
        # Unique path per part: files[<i>][l0][l1]...[l{nesting-1}].
        # Each level is a distinct HashTable; the leaf index makes the whole
        # chain unique so nothing is shared between parts.
        path = f"files[{i}]" + "".join(f"[l{d}]" for d in range(nesting))
        chunks.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{path}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n\r\n"
        )
    chunks.append(f"--{boundary}--\r\n")
    return "".join(chunks).encode()


def upload_progress_part(boundary):
    """Step B shape: a multipart request carrying the upload-progress field, no
    file part. Drives the follow-up code path."""
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"lab\r\n"
        f"--{boundary}--\r\n"
    ).encode()


# ---- scenarios -------------------------------------------------------------

def scn_multipart_startup_fatal(t, cfg, args):
    """Step A: multipart parse fatal during request startup. The rfc1867 parser
    runs before any script, on both SAPIs.
      mod_php  -> Apache error.log 'Allowed memory size ... in Unknown on line 0'.
      nginx+FPM-> worker dies mid-response; nginx logs a 502 'upstream sent
                  unexpected FastCGI record', FPM master logs the child exit and
                  the fatal text."""
    boundary = "lab" + os.urandom(8).hex()
    body = multipart_empty_parts(boundary, args.parts, args.nesting)
    marker(scenario="multipart_startup_fatal", target=t, stack=cfg["stack"],
           parts=args.parts, nesting=args.nesting, body_bytes=len(body),
           expect="memory fatal, Unknown on line 0", benign=False)
    return curl([
        "-X", "POST", f"{cfg['base']}/index.php",
        "-H", f"Content-Type: multipart/form-data; boundary={boundary}",
        "--data-binary", "@-",
    ], body=body)[0]


def scn_mod_php_fatal_chunked(t, cfg, args):
    """Same as above but with chunked transfer (no Content-Length): exercises the
    lengthless-body Level 1 signal."""
    boundary = "lab" + os.urandom(8).hex()
    body = multipart_empty_parts(boundary, args.parts, args.nesting)
    marker(scenario="multipart_startup_chunked", target=t, stack=cfg["stack"],
           parts=args.parts, nesting=args.nesting, body_bytes=len(body),
           expect="memory fatal + no content-length", benign=False)
    return curl([
        "-X", "POST", f"{cfg['base']}/index.php",
        "-H", f"Content-Type: multipart/form-data; boundary={boundary}",
        "-H", "Transfer-Encoding: chunked",
        "--data-binary", "@-",
    ], body=body)[0]


def scn_fpm_decoder_fatal(t, cfg, args):
    """Step A, FPM: post-startup fatal in an app decoder (unserialize/session_decode).
    Expected log: nginx error.log FastCGI stderr 'PHP message: PHP Fatal error:
    Allowed memory size' with client/request/server; FPM fpm.log child survives."""
    if cfg["stack"] != "nginx":
        return 0
    # A serialized array that expands hugely on decode (nested repetition).
    depth = args.nesting + 6
    payload = "a:1:{i:0;" * depth + "s:1:\"x\";" + "}" * depth
    marker(scenario="fpm_decoder_fatal", target=t, stack=cfg["stack"],
           depth=depth, expect="FastCGI stderr memory fatal, worker survives", benign=False)
    return curl([
        "-X", "POST", f"{cfg['base']}/app.php",
        "--data-urlencode", f"data={payload}",
    ])[0]


def scn_upload_progress(t, cfg, args):
    """Step B shape: upload-progress follow-up. On its own it is a benign-looking
    request; detection relies on correlation with a preceding fatal."""
    sid = "lab" + os.urandom(13).hex()
    boundary = "lab" + os.urandom(8).hex()
    body = upload_progress_part(boundary)
    path = "/upload.php" if cfg["stack"] == "nginx" else "/index.php"
    marker(scenario="upload_progress", target=t, stack=cfg["stack"],
           expect="200, small multipart, upload-progress field", benign=False)
    # Session id goes in the cookie (never logged), per the lab's logging rules.
    return curl([
        "-X", "POST", f"{cfg['base']}{path}",
        "-b", f"PHPSESSID={sid}",
        "-H", f"Content-Type: multipart/form-data; boundary={boundary}",
        "--data-binary", "@-",
    ], body=body)[0]


# ---- benign baseline (false-positive comparison) ---------------------------

def scn_benign_browse(t, cfg, args):
    marker(scenario="benign_browse", target=t, stack=cfg["stack"],
           expect="200 GET", benign=True)
    return curl(["-X", "GET", f"{cfg['base']}/index.php"])[0]


def scn_benign_upload(t, cfg, args):
    """A normal file upload: one real file part, modest size."""
    boundary = "lab" + os.urandom(8).hex()
    content = b"x" * (64 * 1024)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="report.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    path = "/upload.php" if cfg["stack"] == "nginx" else "/index.php"
    marker(scenario="benign_upload", target=t, stack=cfg["stack"],
           body_bytes=len(body), expect="200, normal multipart upload", benign=True)
    return curl([
        "-X", "POST", f"{cfg['base']}{path}",
        "-H", f"Content-Type: multipart/form-data; boundary={boundary}",
        "--data-binary", "@-",
    ], body=body)[0]


def scn_benign_memory_fatal(t, cfg, args):
    """A genuine application memory fatal: the false positive for Level 0 error-log
    detection. Fatal reports a real file and line, not 'Unknown on line 0'."""
    marker(scenario="benign_memory_fatal", target=t, stack=cfg["stack"],
           expect="memory fatal WITH real file:line (not Unknown)", benign=True)
    return curl(["-X", "GET", f"{cfg['base']}/heavy.php"])[0]


SCENARIOS = {
    "multipart_startup_fatal": scn_multipart_startup_fatal,
    "multipart_startup_chunked": scn_mod_php_fatal_chunked,
    "fpm_decoder_fatal": scn_fpm_decoder_fatal,
    "upload_progress": scn_upload_progress,
    "benign_browse": scn_benign_browse,
    "benign_upload": scn_benign_upload,
    "benign_memory_fatal": scn_benign_memory_fatal,
}

# Which scenarios make sense per stack.
STACK_SCENARIOS = {
    "apache": ["multipart_startup_fatal", "multipart_startup_chunked", "upload_progress",
               "benign_browse", "benign_upload", "benign_memory_fatal"],
    "nginx":  ["multipart_startup_fatal", "fpm_decoder_fatal", "upload_progress",
               "benign_browse", "benign_upload", "benign_memory_fatal"],
}


def resolve_targets(names):
    if not names or names == ["all"]:
        return list(TARGETS)
    bad = [n for n in names if n not in TARGETS]
    if bad:
        sys.exit(f"unknown target(s): {', '.join(bad)}. known: {', '.join(TARGETS)}")
    return names


def main():
    ap = argparse.ArgumentParser(description="php2shell lab traffic (detection, not exploitation)")
    ap.add_argument("--target", action="append", help="lab service, repeatable; default all")
    ap.add_argument("--scenario", action="append",
                    help="scenario name, repeatable; default = all valid for the stack")
    ap.add_argument("--repeat", type=int, default=1, help="repeat each scenario N times")
    ap.add_argument("--parts", type=int, default=1100, help="empty multipart parts (step A)")
    ap.add_argument("--nesting", type=int, default=60, help="field-name nesting depth (step A)")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = ap.parse_args()

    if args.list:
        for name in SCENARIOS:
            print(name)
        return

    for t in resolve_targets(args.target):
        cfg = TARGETS[t]
        wanted = args.scenario or STACK_SCENARIOS[cfg["stack"]]
        for name in wanted:
            if name not in SCENARIOS:
                sys.exit(f"unknown scenario: {name}")
            if args.scenario is None and name not in STACK_SCENARIOS[cfg["stack"]]:
                continue
            for _ in range(args.repeat):
                SCENARIOS[name](t, cfg, args)

    print(f"\nmarkers -> {MARKERS}")


if __name__ == "__main__":
    main()
