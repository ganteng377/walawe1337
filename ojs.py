import sys, re, argparse
import concurrent.futures as cf
import requests
from urllib.parse import urlparse, urljoin
from html import unescape
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ===================== Konfigurasi dasar & header =====================

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.8",
    "Connection": "keep-alive",
}

CONNECT_TIMEOUT = 6
READ_TIMEOUT = 18
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)

# ===================== Utilitas HTTP & pooling =====================

def make_session(pool_size: int = 100, retries_total: int = 3) -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    retry = Retry(
        total=retries_total, connect=2, read=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry,
                          pool_connections=pool_size,
                          pool_maxsize=pool_size)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def safe_get(session: requests.Session, url: str, **kw):
    try:
        return session.get(
            url,
            headers=kw.get("headers", HEADERS),
            verify=False,
            timeout=kw.get("timeout", TIMEOUT),
            allow_redirects=kw.get("allow_redirects", True),
        )
    except requests.exceptions.RequestException:
        return None

def safe_post(session: requests.Session, url: str, **kw):
    try:
        return session.post(
            url,
            headers=kw.get("headers", HEADERS),
            data=kw.get("data"),
            verify=False,
            timeout=kw.get("timeout", TIMEOUT),
            allow_redirects=kw.get("allow_redirects", False),
        )
    except requests.exceptions.RequestException:
        return None

# ===================== Helper URL & parser =====================

def norm_base(url: str) -> str:
    url = url.strip()
    if "://" not in url: url = "https://" + url
    p = urlparse(url)
    path = (p.path or "")
    if "/index.php" in path:
        path = path.split("/index.php", 1)[0]
    path = path.rstrip("/")
    return f"{p.scheme}://{p.netloc}{path}"

def with_index(base: str) -> str:
    return f"{base}/index.php"

def first_ok(session: requests.Session, urls: list[str], want_csrf=False):
    for u in urls:
        r = safe_get(session, u)
        if not r:
            continue
        if want_csrf:
            token = get_csrf(r.text)
            if token:
                return u.rstrip("/"), r, token
        else:
            if r.status_code == 200:
                return u.rstrip("/"), r, None
    return None, None, None

def get_csrf(html: str) -> str | None:
    if not html: return None
    m = re.search(r'<input[^>]*name=["\']csrfToken["\'][^>]*value=["\']([^"\']+)["\']', html, flags=re.I)
    if m: return unescape(m.group(1))
    m = re.search(r'<meta[^>]*name=["\']csrf[-_]?token["\'][^>]*content=["\']([^"\']+)["\']', html, flags=re.I)
    return unescape(m.group(1)) if m else None

def is_logged_in_redirect(resp: requests.Response) -> bool:
    return resp is not None and resp.status_code in (302, 303)

def looks_like_site_admin(html: str) -> bool:
    if not html: return False
    h = html.lower()
    for n in ["system information","phpinfo","server information",'pkp_page_title',"administration"]:
        if n in h: return True
    return False

def looks_like_journal_settings(html: str) -> bool:
    if not html: return False
    h = html.lower()
    for n in ["journal settings","workflow settings","masthead","/management/settings/","id=\"journalsettings\"","name=\"journaltitle\"","submission settings","distribution settings"]:
        if n in h: return True
    return False

def looks_like_profile(html: str) -> bool:
    if not html: return False
    h = html.lower()
    return ("user" in h and "profile" in h) or "public profile" in h or "pkp_page_title" in h

def same_host(href: str, base: str) -> bool:
    try:
        u = urlparse(urljoin(base, href))
        b = urlparse(base)
        return (u.scheme in ("http","https")) and (u.netloc == b.netloc)
    except Exception:
        return False

# ===================== Builders =====================

def build_login_candidates(base: str) -> list[str]:
    wb = with_index(base)
    return [f"{wb}/index/login", f"{base}/index/login", f"{base}/login", f"{wb}/login"]

def build_profile_candidates(base: str) -> list[str]:
    wb = with_index(base)
    return [f"{wb}/index/user/profile", f"{base}/index/user/profile", f"{base}/user/profile"]

def build_admininfo_candidates(base: str) -> list[str]:
    wb = with_index(base)
    return [f"{wb}/index/admin/systemInfo", f"{base}/index/admin/systemInfo", f"{base}/admin/systemInfo"]

def build_journal_mgmt_candidates(base: str, jpath: str) -> list[str]:
    wb = with_index(base)
    return [
        f"{wb}/{jpath}/management/settings/context",
        f"{base}/{jpath}/management/settings/context",
        f"{wb}/{jpath}/management",
        f"{base}/{jpath}/management",
    ]

# ===================== Context discovery =====================

def fetch_contexts_via_api(session: requests.Session, base: str) -> list[str]:
    api_candidates = [
        f"{with_index(base)}/api/v1/contexts",
        f"{with_index(base)}/api/v1/contexts/",
        f"{base}/api/v1/contexts",
        f"{base}/api/v1/contexts/",
    ]
    s = requests.Session()
    s.headers.update({**HEADERS, "Accept": "application/json"})
    s.mount("http://", HTTPAdapter(max_retries=Retry(total=0)))
    s.mount("https://", HTTPAdapter(max_retries=Retry(total=0)))

    for api_url in api_candidates:
        try:
            r = s.get(api_url, verify=False, timeout=TIMEOUT, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except ValueError:
            continue
        items = data.get("items") or data.get("itemsByPage") or data
        out = []
        if isinstance(items, list):
            for it in items:
                p = (it.get("path") or it.get("urlPath") or it.get("url_path") or "").strip()
                if p: out.append(p)
        elif isinstance(items, dict) and "items" in items:
            for it in items["items"]:
                p = (it.get("path") or it.get("urlPath") or it.get("url_path") or "").strip()
                if p: out.append(p)
        if out:
            return sorted(set(out))
    return []

def validate_context(session: requests.Session, base: str, slug: str) -> bool:
    tests = [f"{with_index(base)}/{slug}/about", f"{base}/{slug}/about", f"{with_index(base)}/{slug}", f"{base}/{slug}"]
    markers = ["pkp_page_index","pkp_page_about","current issue","about the journal","editorial team","issn","submissions","browse issues"]
    for u in tests:
        r = safe_get(session, u)
        if r and r.status_code == 200:
            h = (r.text or "").lower()
            if any(m in h for m in markers):
                return True
    return False

def scrape_journal_paths_validated(session: requests.Session, base: str, html: str) -> list[str]:
    if not html: return []
    allowed_next = r"(?:user|management|issue|article|about|index|reviewer|submissions|submission|editor|workflow)"
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, flags=re.I)
    hrefs = [unescape(h) for h in hrefs if same_host(h, base) or h.startswith("/")]
    slugs = set()
    for h in hrefs:
        m = re.search(r'/index\.php/([A-Za-z0-9._-]+)/' + allowed_next + r'/?', h)
        if m: slugs.add(m.group(1).lower())
        else:
            m2 = re.search(r'/([A-Za-z0-9._-]+)/' + allowed_next + r'/?', h)
            if m2: slugs.add(m2.group(1).lower())
    valid = []
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(validate_context, session, base, s): s for s in slugs}
        for fut in cf.as_completed(futs):
            if fut.result():
                valid.append(futs[fut])
    return sorted(set(valid))

# ===================== Login =====================

def login(session: requests.Session, base: str, username: str, password: str) -> bool:
    chosen_login, r_login, csrf = first_ok(session, build_login_candidates(base), want_csrf=True)
    if not csrf or not chosen_login:
        return False
    r2 = safe_post(session, chosen_login + "/signIn", data={
        "csrfToken": csrf, "source": "", "username": username.strip(), "password": password.strip(), "remember": "1",
    }, allow_redirects=False)
    if r2 and is_logged_in_redirect(r2):
        return True
    prof_u, prof_r, _ = first_ok(session, build_profile_candidates(base))
    if prof_r and looks_like_profile(prof_r.text) and not ("name=\"username\"" in prof_r.text.lower()):
        return True
    if any(k.lower().startswith(("pkp_", "ojssession")) for k in session.cookies.keys()):
        return True
    return False

# ===================== Cek role =====================

def build_and_check_journal(session: requests.Session, base: str, jpath: str) -> tuple[str, bool, str]:
    for tu in build_journal_mgmt_candidates(base, jpath):
        rj = safe_get(session, tu)
        if rj and rj.status_code == 200 and looks_like_journal_settings(rj.text):
            return jpath, True, tu
    return jpath, False, ""

def check_roles(entry: str, pool_journal: int = 12):
    try:
        raw_url, user, pw = [x.strip() for x in entry.split(":", 2)]
    except ValueError:
        print(f"[SKIP] Format salah: {entry}")
        return

    base = norm_base(raw_url)
    s = make_session(pool_size=100, retries_total=3)

    if not login(s, base, user, pw):
        print(f"[NOT LOGIN] {base} ({user})")
        return

    au, ra, _ = first_ok(s, build_admininfo_candidates(base))
    if ra and ra.status_code == 200 and looks_like_site_admin(ra.text):
        print(f"[SITE ADMIN] {base} ({user}) → {au}")
        try:
            with open("AdminSite.txt", "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except Exception:
            pass
    else:
        print(f"[BUKAN Site Admin] {base} ({user})")

    journals = fetch_contexts_via_api(s, base)
    if not journals:
        prof_u, rp, _ = first_ok(s, build_profile_candidates(base))
        journals = scrape_journal_paths_validated(s, base, rp.text if rp else "")

    if not journals:
        print(f"[INFO] {base} — tidak menemukan daftar jurnal yang valid")
        return

    found_any = False
    with cf.ThreadPoolExecutor(max_workers=pool_journal) as ex:
        futs = [ex.submit(build_and_check_journal, s, base, j) for j in journals]
        for fut in cf.as_completed(futs):
            jpath, ok, url_ok = fut.result()
            if ok:
                print(f"[JOURNAL MANAGER/EDITOR] {base}/{jpath} ({user}) → {url_ok}")
                try:
                    with open("AdminJournal.txt", "a", encoding="utf-8") as f:
                        f.write(f"{entry}|{jpath}\n")
                except Exception:
                    pass
                found_any = True
            else:
                print(f"[NO MGMT ACCESS] {base}/{jpath} ({user})")

    if not found_any:
        print(f"[ROLE BIASA] {base} ({user}) — tidak ada akses manajemen jurnal terdeteksi")

# ===================== Main =====================

def main():
    ap = argparse.ArgumentParser(description="Cek role OJS (cepat).")
    ap.add_argument("listfile", help="file berisi 'url:username:password' per baris")
    ap.add_argument("--workers", type=int, default=16, help="jumlah worker paralel untuk target")
    ap.add_argument("--per-journal", type=int, default=12, help="jumlah worker paralel per target saat cek jurnal")
    args = ap.parse_args()

    with open(args.listfile, "r", encoding="utf-8") as f:
        entries = [ln.strip() for ln in f if ln.strip()]

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(check_roles, e, args.per_journal) for e in entries]
        for _ in cf.as_completed(futs):
            pass

if __name__ == "__main__":
    main()