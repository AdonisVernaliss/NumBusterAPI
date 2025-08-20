#!/usr/bin/env python3
import sys, os, json, time, hashlib, argparse, random, string, csv
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
try:
    import httpx
    HAVE_HTTPX = True
except:
    HAVE_HTTPX = False
import requests

DEFAULT_HOST = "securesignalwall.com"

def now_ts() -> str:
    return str(int(time.time()))

def rand_cnonce(n: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def canonical_param_string(params: Dict[str, str], order: Optional[List[str]] = None, exclude: Optional[List[str]] = None) -> str:
    ex = set(exclude or [])
    items = [(k, v) for k, v in params.items() if k not in ex and v is not None]
    if order:
        order_index = {k: i for i, k in enumerate(order)}
        items.sort(key=lambda kv: (order_index.get(kv[0], 10**9), kv[0]))
    else:
        items.sort(key=lambda kv: kv[0])
    return "&".join(f"{k}={v}" for k, v in items)

def compute_signature(method: str, host: str, path: str, params: Dict[str, str], sig_order: Optional[List[str]] = None) -> str:
    qs = canonical_param_string(params, order=sig_order, exclude=["signature"])
    s = f"{method.upper()}{host}{path}{qs}"
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return h

def short(v: Any, maxlen: int = 120) -> str:
    s = str(v) if v is not None else ""
    return s if len(s) <= maxlen else s[:maxlen] + "..."

def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_csv(path: str, rows: List[Dict[str, Any]], fieldnames: List[str]):
    write_header = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            w.writeheader()
        for r in rows:
            w.writerow(r)

def do_request_http2(method: str, url: str, headers: Dict[str, str], params: Dict[str, str], data: Optional[str] = None, timeout: int = 20):
    if HAVE_HTTPX:
        with httpx.Client(http2=True, timeout=timeout) as client:
            if method.upper() == "GET":
                r = client.get(url, params=params, headers=headers)
            else:
                r = client.post(url, params=params, headers=headers, content=(data.encode("utf-8") if data else None))
            return r.status_code, r.headers, r.text
    else:
        return None, None, None

def do_request(method: str, url: str, headers: Dict[str, str], params: Dict[str, str], data: Optional[str] = None, timeout: int = 20, force_http2: bool = False):
    if force_http2:
        sc, hdrs, text = do_request_http2(method, url, headers, params, data, timeout)
        if sc is not None:
            return sc, hdrs, text
    if method.upper() == "GET":
        r = requests.get(url, params=params, headers=headers, timeout=timeout)
    else:
        r = requests.post(url, params=params, data=(data if data else None), headers=headers, timeout=timeout)
    return r.status_code, r.headers, r.text

def minimal_osint_from_search(data: Dict[str, Any], phone: str) -> Dict[str, Any]:
    d = data.get("data") or {}
    avg = d.get("averageProfile") or {}
    phone_obj = d.get("phone") or {}
    common = d.get("common") or {}
    metrics = d.get("metrics") or {}
    res = {
        "phone_input": phone,
        "name": f"{avg.get('firstName','')} {avg.get('lastName','')}".strip(),
        "carrier": phone_obj.get("carrier", ""),
        "region": phone_obj.get("region", ""),
        "contacts_count": metrics.get("contactsCount", 0),
        "see_more": common.get("seeMoreLink", ""),
    }
    return res

def minimal_osint_from_theoscope_access(data: Dict[str, Any], phone: str) -> Dict[str, Any]:
    d = data.get("data") or {}
    return {
        "phone_input": phone,
        "country_code": d.get("country_code"),
        "theoscope_own_profile": d.get("theoscope_own_profile"),
        "theoscope_other_profile": d.get("theoscope_other_profile"),
    }

def minimal_from_tiers_access(data: Dict[str, Any]) -> Dict[str, Any]:
    d = data.get("data") or {}
    return {
        "country_code": d.get("country_code"),
        "verification_level": d.get("verification_level"),
        "platform": d.get("platform"),
        "locale": d.get("locale"),
    }

def minimal_from_pricing(data: Dict[str, Any]) -> Dict[str, Any]:
    d = data.get("data") or {}
    return {
        "pricing": short(d, 300)
    }

def minimal_from_purchased(data: Dict[str, Any], phone: str) -> Dict[str, Any]:
    d = data.get("data")
    n = 0
    if isinstance(d, list):
        n = len(d)
    return {
        "phone_input": phone,
        "purchases_count": n
    }

def build_headers(creds: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Accept-Encoding": creds.get("accept_encoding", "gzip, deflate, br"),
        "User-Agent": creds.get("ua", "okhttp/4.10.0"),
        "Connection": "Keep-Alive",
        "Host": DEFAULT_HOST,
    }

def dispatch_endpoint(ep_name: str, phone: Optional[str], cfg: Dict[str, Any], creds: Dict[str, Any], force_http2: bool, mode: str) -> Dict[str, Any]:
    ep = cfg["endpoints"][ep_name]
    method = ep["method"].upper()
    path = ep["path"]
    host = DEFAULT_HOST
    headers = build_headers(creds)
    access_token = creds.get("access_token") or ""
    params = {}
    for k, v in (ep.get("static_params") or {}).items():
        params[k] = v
    if "{phone}" in path and phone:
        path = path.replace("{phone}", phone)
    else:
        if ep.get("phone_param") and phone:
            params[ep["phone_param"]] = phone
    params["access_token"] = access_token
    if mode == "replay":
        raw = creds.get("raw", {}).get(ep_name, {})
        if "timestamp" in raw:
            params["timestamp"] = str(raw["timestamp"])
        if ep.get("cnonce_required"):
            params["cnonce"] = raw.get("cnonce", rand_cnonce(32))
        if "signature" in raw:
            params["signature"] = raw["signature"]
        body = raw.get("body")
    else:
        params["timestamp"] = now_ts()
        if ep.get("cnonce_required"):
            params["cnonce"] = rand_cnonce(32)
        sig_order = ep.get("sign_order")
        sign = compute_signature(method, host, path, params, sig_order=sig_order)
        params["signature"] = sign
        body = ep.get("post_body")
    url = f"https://{host}{path}"
    sc, hdrs, text = do_request(method, url, headers, params, data=body, timeout=20, force_http2=force_http2)
    if sc is None:
        sc, hdrs, text = do_request(method, url, headers, params, data=body, timeout=20, force_http2=False)
    try:
        j = json.loads(text)
    except:
        j = {"status_code": sc, "raw": text}
    if ep_name == "search":
        return {"endpoint": ep_name, "http": sc, **minimal_osint_from_search(j, phone or "")}
    if ep_name == "theoscope_access":
        return {"endpoint": ep_name, "http": sc, **minimal_osint_from_theoscope_access(j, phone or "")}
    if ep_name == "tiers_access":
        return {"endpoint": ep_name, "http": sc, **minimal_from_tiers_access(j)}
    if ep_name == "tiers_pricing":
        return {"endpoint": ep_name, "http": sc, **minimal_from_pricing(j)}
    if ep_name == "purchased_by_phone":
        return {"endpoint": ep_name, "http": sc, **minimal_from_purchased(j, phone or "")}
    if ep_name == "ping":
        return {"endpoint": ep_name, "http": sc, "ok": (sc == 200)}
    return {"endpoint": ep_name, "http": sc, "raw": j}

def run_for_phone(phone: str, cfg: Dict[str, Any], creds: Dict[str, Any], force_http2: bool, mode: str) -> List[Dict[str, Any]]:
    results = []
    order = cfg.get("sequence", [])
    for ep_name in order:
        out = dispatch_endpoint(ep_name, phone, cfg, creds, force_http2, mode)
        results.append(out)
        time.sleep(cfg.get("rate_delay", 0.3))
    return results

def format_minimal_output(res: List[Dict[str, Any]]):
    items = {}
    for r in res:
        if r.get("endpoint") == "search":
            items["Name"] = r.get("name", "")
            items["Carrier"] = r.get("carrier", "")
            items["Region"] = r.get("region", "")
            items["Contacts"] = r.get("contacts_count", 0)
            items["SeeMore"] = r.get("see_more", "")
        if r.get("endpoint") == "theoscope_access":
            items["Theo_Own"] = r.get("theoscope_own_profile")
            items["Theo_Other"] = r.get("theoscope_other_profile")
            items["Country"] = r.get("country_code")
        if r.get("endpoint") == "purchased_by_phone":
            items["Purchases"] = r.get("purchases_count", 0)
    for k in ["Name", "Carrier", "Region", "Contacts", "SeeMore", "Theo_Own", "Theo_Other", "Country", "Purchases"]:
        if k in items:
            print(f"{k}: {items[k]}")

def main():
    ap = argparse.ArgumentParser(description="NumBuster OSINT extractor (minimal output).")
    ap.add_argument("phone_or_file", help="phone number or path to file with numbers")
    ap.add_argument("--cfg", default="endpoints.json")
    ap.add_argument("--creds", default="creds.json")
    ap.add_argument("--http2", action="store_true")
    ap.add_argument("--mode", choices=["replay", "compute"], default="replay")
    ap.add_argument("--save-csv", help="append results to CSV file")
    ap.add_argument("--save-jsonl", help="append results to JSONL file")
    args = ap.parse_args()

    cfg = load_json(args.cfg)
    creds = load_json(args.creds)
    phones = []
    if os.path.exists(args.phone_or_file) and os.path.isfile(args.phone_or_file):
        with open(args.phone_or_file, "r", encoding="utf-8") as f:
            for line in f:
                p = "".join(ch for ch in line.strip() if ch.isdigit())
                if p:
                    phones.append(p)
    else:
        phones.append("".join(ch for ch in args.phone_or_file if ch.isdigit()))

    all_rows = []
    for p in phones:
        res = run_for_phone(p, cfg, creds, args.http2, args.mode)
        format_minimal_output(res)
        row = {"phone": p}
        for r in res:
            if r.get("endpoint") == "search":
                row.update({
                    "name": r.get("name",""),
                    "carrier": r.get("carrier",""),
                    "region": r.get("region",""),
                    "contacts": r.get("contacts_count",0),
                    "see_more": r.get("see_more",""),
                })
            if r.get("endpoint") == "theoscope_access":
                row.update({
                    "theo_own": r.get("theoscope_own_profile"),
                    "theo_other": r.get("theoscope_other_profile"),
                    "country": r.get("country_code"),
                })
            if r.get("endpoint") == "purchased_by_phone":
                row.update({
                    "purchases": r.get("purchases_count",0)
                })
        all_rows.append(row)

    if args.save_csv and all_rows:
        fields = sorted({k for row in all_rows for k in row.keys()})
        save_csv(args.save_csv, all_rows, fields)
    if args.save_jsonl and all_rows:
        with open(args.save_jsonl, "a", encoding="utf-8") as f:
            for row in all_rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    main()