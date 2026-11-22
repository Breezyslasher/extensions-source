#!/usr/bin/env python3
"""Replays every DC Universe Infinite API call the extension makes and checks the responses.

Auth checks run only when DCUI_SESSION (the value of the site's `session` cookie) is set.
Tokens, signed URL query strings and account identifiers are never printed or saved.
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

BASE = "https://www.dcuniverseinfinite.com"
API = BASE + "/api"
CONSUMER_KEY = "DA59dtVXYLxajktV"
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
TOKEN = os.environ.get("DCUI_SESSION", "").strip()
OUT_DIR = os.environ.get("REPORT_DIR", "dcui-report")
FREE_COLLECTIONS = ["edt-dcgo-free-to-read", "gtk-johnstewart-free-to-read"]
SECRET_KEYS = {"user_guid", "guid", "email", "jwt", "session_id", "username", "first_name", "last_name"}

results = []


def check(name, ok, detail="", required=True):
    status = "PASS" if ok else ("FAIL" if required else "WARN")
    results.append({"name": name, "status": status, "detail": detail})
    print(f"[{status}] {name}: {detail}", flush=True)
    return ok


def info(name, detail):
    results.append({"name": name, "status": "INFO", "detail": detail})
    print(f"[INFO] {name}: {detail}", flush=True)


def redact(obj, depth=0):
    if isinstance(obj, dict):
        return {k: ("<redacted>" if k in SECRET_KEYS else redact(v, depth + 1)) for k, v in obj.items()}
    if isinstance(obj, list):
        out = [redact(v, depth + 1) for v in obj[:2]]
        if len(obj) > 2:
            out.append(f"... {len(obj) - 2} more")
        return out
    if isinstance(obj, str):
        if obj.startswith("http") and "?" in obj:
            return obj.split("?", 1)[0] + "?<query redacted>"
        if obj.count(".") == 2 and obj.startswith("eyJ"):
            return "<jwt redacted>"
    return obj


def save_sample(name, data):
    os.makedirs(os.path.join(OUT_DIR, "samples"), exist_ok=True)
    with open(os.path.join(OUT_DIR, "samples", f"{name}.json"), "w") as f:
        json.dump(redact(data), f, indent=2)


def redact_full(obj):
    """Redact secrets without dropping any fields or list entries."""
    if isinstance(obj, dict):
        return {
            k: ("<redacted>" if k in SECRET_KEYS else redact_full(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_full(v) for v in obj]
    if isinstance(obj, str):
        if obj.startswith("http") and "?" in obj:
            return obj.split("?", 1)[0] + "?<query redacted>"
        if obj.count(".") == 2 and obj.startswith("eyJ"):
            return "<jwt redacted>"
    return obj


def save_download_response(name, request_url, status, headers, raw, quality):
    """Save the full manifest structure while removing signed URL query tokens."""
    os.makedirs(os.path.join(OUT_DIR, "responses"), exist_ok=True)
    parsed = as_json(raw)
    payload = {
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "request": {
            "method": "GET",
            "url": request_url,
            "quality": quality,
        },
        "response": {
            "status": status,
            "content_type": headers.get("Content-Type", "") if headers else "",
            "json": redact_full(parsed) if parsed is not None else None,
            "body_text": None if parsed is not None else raw.decode("utf-8", "replace"),
        },
    }
    path = os.path.join(OUT_DIR, "responses", f"{name}.json")
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    images = parsed.get("images", []) if isinstance(parsed, dict) else []
    info(f"{name}_saved",
         f"HTTP {status}; saved complete manifest structure ({len(images)} images) "
         f"to responses/{name}.json; signed URL query strings redacted")


def save_enc_sample(name, data, headers, status, truncated=False):
    """Save a bounded .enc response for format identification; never log its URL or contents."""
    os.makedirs(os.path.join(OUT_DIR, "samples"), exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    path = os.path.join(OUT_DIR, "samples", f"{safe_name}.enc")
    if truncated:
        info(f"{name}_sample", f"HTTP {status}; response exceeded 8 MiB, not saved")
        return
    with open(path, "wb") as f:
        f.write(data)
    info(f"{name}_sample",
         f"saved {len(data)} bytes; content-type={headers.get('Content-Type', 'unknown')}; "
         f"sha256={hashlib.sha256(data).hexdigest()}; "
         f"first_32_bytes={data[:32].hex()}; artifact file=samples/{safe_name}.enc")


def http(method, url, body=None, auth="none", extra=None, json_body=True, max_bytes=None):
    headers = {"User-Agent": UA}
    if url.startswith(API):
        headers.update({
            "Accept": "application/json, text/plain, */*",
            "Referer": BASE + "/",
            "Origin": BASE,
            "x-consumer-key": CONSUMER_KEY,
        })
    else:
        headers["Referer"] = BASE + "/"
    if TOKEN and auth in ("both", "token"):
        headers["Authorization"] = f"Token {TOKEN}"
    if TOKEN and auth in ("both", "cookie"):
        headers["Cookie"] = f"session={TOKEN}"
    if extra:
        headers.update(extra)
    data = None
    if body is not None:
        data = json.dumps(body).encode() if json_body else body
        headers["Content-Type"] = "application/json;charset=UTF-8"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.headers, r.read(max_bytes + 1 if max_bytes else -1)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(max_bytes + 1 if max_bytes else -1)
    except Exception as e:  # network failure, timeout
        return 0, {}, str(e).encode()


def jpeg_size(data):
    try:
        i = 2
        while i < len(data) - 9:
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3):
                return (data[i + 7] << 8) | data[i + 8], (data[i + 5] << 8) | data[i + 6]
            i += 2 + ((data[i + 2] << 8) | data[i + 3])
    except Exception:
        pass
    return None, None


def as_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None


def search_body(page, q=None, q_key="q", sort_field="first_released", sort_dir="desc", era=None):
    body = {"page": page, "per_page": 20, "document_types": ["comicseries"]}
    if q:
        body[q_key] = q
    body["filters"] = {"comicseries": {"eras": era} if era else {}}
    body["sort_field"] = {"comicseries": sort_field}
    body["sort_direction"] = {"comicseries": sort_dir}
    body["apply_transform"] = True
    return body


def search(name, **kw):
    code, _, raw = http("POST", f"{API}/search_proxy/1/search", search_body(**kw))
    data = as_json(raw)
    if code != 200 or not isinstance(data, dict):
        snippet = raw[:150].decode("utf-8", "replace").replace("\n", " ")
        check(name, False, f"HTTP {code}, body: {snippet}")
        return None, None
    save_sample(name, data)
    items = next(iter((data.get("records") or {}).values()), [])
    page_info = next(iter((data.get("info") or {}).values()), {})
    return items, page_info


def decode_jwt(jwt):
    part = jwt.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def rights(book_uuid, auth):
    code, _, raw = http("GET", f"{API}/5/1/rights/comic/{book_uuid}?trans=en", auth=auth)
    if code != 200:
        return code, None, None
    jwt = raw.decode().strip().strip('"')
    try:
        return code, jwt, decode_jwt(jwt)
    except Exception:
        return code, None, None


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f"Auth token provided: {'yes' if TOKEN else 'no (auth checks skipped)'}\n")

    # Popular / Latest
    p1, info1 = search("popular_page1", page=1)
    if p1 is None:
        info("blocked", "Search endpoint unreachable from this runner; stopping.")
        return finish()
    check("popular_page1", len(p1) > 0 and all(i.get("uuid") and i.get("title") for i in p1),
          f"{len(p1)} series, page info {info1}")
    missing = [k for k in ("slug", "base_asset_url", "description") if any(k not in i for i in p1)]
    check("popular_fields", not missing, f"missing on some records: {missing}" if missing else "uuid/title/slug/base_asset_url/description present", required=False)
    check("popular_has_next", info1.get("current_page", 1) < info1.get("num_pages", 1),
          f"current_page={info1.get('current_page')} num_pages={info1.get('num_pages')} -> hasNextPage")

    # Does a browse (comicseries) record carry any access/premium signal we could use to
    # hide fully-locked series cheaply (without fetching each series' chapters)?
    rec = p1[0]
    info("series_record_keys", f"comicseries record fields: {sorted(rec.keys())}")
    for k in ("included_with_premium", "exclusive_to_plans", "available_plans",
              "available_via_walls_plans", "asset_is_purchasable", "program_schedule"):
        present = [k in r for r in p1]
        info("series_access_field", f"{k}: present_on={sum(present)}/{len(p1)}, sample={rec.get(k)}")

    p2, info2 = search("popular_page2", page=2)
    if p2 is not None:
        overlap = {i["uuid"] for i in p1} & {i["uuid"] for i in p2}
        check("popular_page2", len(p2) > 0 and not overlap and info2.get("current_page") == 2,
              f"{len(p2)} series, current_page={info2.get('current_page')}, overlap with page1={len(overlap)}")

    # Login probe: confirm the request shape is accepted and only the captcha blocks it.
    # Sends a well-formed login with throwaway credentials and NO captcha field, then
    # reports exactly how the server responds (fields echoed, not real credentials).
    login_fields_code, _, login_fields_raw = http("GET", f"{API}/users/login?trans=en")
    lf = as_json(login_fields_raw) or {}
    declared = list((lf.get("fields") or {}).keys())
    info("login_declared_fields", f"HTTP {login_fields_code}, fields the endpoint advertises: {declared}")
    # Try each documented-field variation (no captcha) and show the raw response.
    probe_variants = [
        ("email_only", {"email": "probe@example.com", "password": "not-a-real-password"}),
        ("require_jwt_false", {"email": "probe@example.com", "password": "not-a-real-password", "require_jwt": False}),
        ("require_jwt_true", {"email": "probe@example.com", "password": "not-a-real-password", "require_jwt": True}),
        ("username_field", {"username": "probe", "password": "not-a-real-password"}),
    ]
    probe_codes = []
    for label, probe_body_json in probe_variants:
        code, _, raw = http("POST", f"{API}/users/login?trans=en", body=probe_body_json)
        body_text = raw.decode("utf-8", "replace")[:200].replace("\n", " ")
        probe_codes.append(code)
        info(f"login_probe_{label}", f"fields {list(probe_body_json)} -> HTTP {code}; body: {body_text}")
    check("login_requires_captcha", all(c != 200 for c in probe_codes),
          f"every documented-field login without a captcha was rejected (statuses: {probe_codes})",
          required=False)

    # Search: verify which key actually filters
    base_uuids = {i["uuid"] for i in p1}
    for key in ("q", "query"):
        res, rinfo = search(f"search_{key}", page=1, q="batman", q_key=key)
        if res is None:
            continue
        hits = sum("batman" in (i.get("title") or "").lower() for i in res)
        ratio = hits / len(res) if res else 0
        changed = {i["uuid"] for i in res} != base_uuids
        works = bool(res) and changed and ratio >= 0.5
        check(f"search_key_{key}", works,
              f"{len(res)} results, {hits} titles contain 'batman', total={rinfo.get('total_result_count')}",
              required=(key == "q"))

    # Era filter
    era, _ = search("filter_era_golden", page=1, era="golden-age")
    if era is not None:
        check("filter_era", len(era) > 0 and {i["uuid"] for i in era} != base_uuids,
              f"{len(era)} results, sample: {[i.get('title') for i in era[:3]]}")

    # Extra filter keys: probe which ones actually narrow comicseries results.
    base_total = info1.get("total_result_count", 0)

    def filter_probe(name, filt):
        body = {"page": 1, "per_page": 20, "document_types": ["comicseries"],
                "filters": {"comicseries": filt},
                "sort_field": {"comicseries": "first_released"},
                "sort_direction": {"comicseries": "desc"}, "apply_transform": True}
        code, _, raw = http("POST", f"{API}/search_proxy/1/search", body)
        d = as_json(raw) or {}
        pinfo = next(iter((d.get("info") or {}).values()), {})
        items = next(iter((d.get("records") or {}).values()), [])
        total = pinfo.get("total_result_count")
        works = isinstance(total, int) and 0 < total < base_total
        check(name, works,
              f"filter {filt} -> total={total} (base {base_total}); sample={[i.get('title') for i in items[:3]]}",
              required=False)

    filter_probe("filter_art_vertical", {"art_style_tags": "Vertical"})
    filter_probe("filter_char_name", {"character_tags": "Batman"})
    filter_probe("filter_char_slug", {"character_tags": "batman"})
    filter_probe("filter_imprint", {"imprints": "DC Black Label"})

    # Sort
    srt, _ = search("sort_title_asc", page=1, sort_field="title", sort_dir="asc")
    if srt:
        titles = [(i.get("title") or "").casefold() for i in srt]
        in_order = sum(a <= b for a, b in zip(titles, titles[1:]))
        check("sort_title_asc", in_order >= 0.9 * (len(titles) - 1), f"first titles: {[i.get('title') for i in srt[:3]]}")

    # Series details: pick the popular series with the most issues to exercise pagination
    best, best_count, best_detail = None, -1, None
    for item in p1[:10]:
        code, _, raw = http("GET", f"{API}/comics/1/series/{item['uuid']}/?trans=en")
        d = as_json(raw)
        if code == 200 and isinstance(d, dict) and d.get("books_count", 0) > best_count:
            best, best_count, best_detail = item, d.get("books_count", 0), d
    if not check("series_details", best_detail is not None and bool(best_detail.get("title")),
                 f"'{best_detail.get('title') if best_detail else None}' books_count={best_count}"):
        return finish()
    save_sample("series_details", best_detail)
    tags = best_detail.get("tags", [])
    check("series_tags", isinstance(tags, list) and all("name" in t for t in tags),
          f"{len(tags)} tags, categories seen: {sorted({c for t in tags for c in t.get('categories', [])})}", required=False)

    # Cover image exactly as the extension builds it
    cover = f"{best['base_asset_url']}/box.jpg?w=600&auto=format,compress"
    code, headers, raw = http("GET", cover)
    ctype = headers.get("Content-Type", "") if headers else ""
    check("cover_image", code == 200 and ctype.startswith("image/"), f"HTTP {code}, {ctype}, {len(raw)} bytes")

    # Chapter list: /series/{uuid}/books/issue paginated
    books, page, num_pages, total = [], 1, 1, 0
    while page <= num_pages:
        code, _, raw = http("GET", f"{API}/comics/1/series/{best['uuid']}/books/issue?page={page}&trans=en")
        d = as_json(raw)
        if code != 200 or not isinstance(d, dict):
            check("chapter_list", False, f"page {page}: HTTP {code}")
            return finish()
        if page == 1:
            save_sample("chapter_list_page1", d)
        num_pages, total = d.get("num_pages", 1), d.get("total", 0)
        books.extend(d.get("values", []))
        page += 1
    check("chapter_list", len(books) > 0 and len(books) == total,
          f"{len(books)} books over {num_pages} page(s), API total={total}")
    bad = [b for b in books if not (b.get("uuid") and b.get("slug") and b.get("title"))]
    check("chapter_fields", not bad, f"{len(bad)} books missing uuid/slug/title")
    dated = [b.get("publish_date") or b.get("release_date") for b in books]
    check("chapter_dates", all(d and re.match(r"^\d{4}-\d{2}-\d{2}$", d) for d in dated),
          f"sample dates: {dated[:3]} (extension parses yyyy-MM-dd)")
    authors = sorted({a.get("name") for b in books for a in b.get("authors", []) if a.get("name")})
    artists = sorted({a.get("name") for b in books for a in b.get("pencillers", []) if a.get("name")})
    check("series_creators", bool(authors), f"{len(authors)} authors, {len(artists)} pencillers across issues "
          f"(extension builds author/artist from these), e.g. {authors[:2]}")
    nums = [b.get("issue_number") for b in books]
    floats = [float(n) for n in nums if n and re.match(r"^-?\d+(\.\d+)?$", n)]
    check("chapter_numbers", len(floats) == len(nums), f"sample issue_number: {nums[:5]}", required=False)
    ascending = all(a <= b for a, b in zip(dated, dated[1:]) if a and b)
    check("chapter_order_ascending", ascending,
          "API returns oldest first, so the extension's reversed() gives newest first" if ascending
          else "API is NOT oldest-first; the extension's reversed() will show chapters in the wrong order")

    # Free-to-read collections: find a book a free account should be able to read
    free_books = []
    for slug in FREE_COLLECTIONS:
        code, _, raw = http("GET", f"{API}/5/2/collection-items/slug/{slug}?page_size=20&trans=en")
        d = as_json(raw)
        if code == 200 and d is not None:
            save_sample(f"collection_{slug}", d)
            free_books += re.findall(r"urn:book:([0-9a-f-]{36})", raw.decode("utf-8", "replace"))
        info(f"collection_{slug}", f"HTTP {code}, {len(set(free_books))} free book uuids found so far")
    free_books = list(dict.fromkeys(free_books))
    premium_book = books[-1]["uuid"]

    # List some free-to-read titles anyone can read, and whether rights says can_read anonymously.
    for uuid in free_books[:6]:
        code, _, raw = http("GET", f"{API}/comics/1/book/{uuid}/?trans=en")
        d = as_json(raw) or {}
        title = d.get("title") or d.get("series_title")
        rc, _, payload = rights(uuid, auth="none")
        can_read = payload.get("rights", {}).get("can_read") if payload else None
        info("free_title", f"'{title}' -> rights can_read(anonymous)={can_read}")

    code, _, payload = rights(free_books[0] if free_books else premium_book, auth="none")
    info("rights_anonymous", f"HTTP {code}, can_read={payload and payload.get('rights', {}).get('can_read')}")

    # Image quality: for a free-readable book, compare the SD vs HD download manifests and
    # measure the actual thumbnail pixel size (the only unencrypted image we can use).
    readable = None
    for uuid in free_books[:8]:
        _, jwt, payload = rights(uuid, auth="none")
        if jwt and payload and payload.get("rights", {}).get("can_read"):
            readable = (uuid, jwt)
            break
    if readable:
        uuid, jwt = readable
        for q in ("SD", "HD"):
            manifest_url = f"{API}/comics/1/book/download/?page=1&quality={q}&trans=en"
            code, manifest_headers, raw = http("GET", manifest_url,
                                               auth="none", extra={"x-auth-jwt": jwt})
            if q == "HD":
                save_download_response("download_HD_page1", manifest_url, code,
                                       manifest_headers, raw, q)
            d = as_json(raw) or {}
            imgs = d.get("images", [])
            if not imgs:
                info(f"image_{q}", f"HTTP {code}, no images; body: {raw[:120].decode('utf-8', 'replace')}")
                continue
            first = imgs[0]
            turl = first.get("thumbnail_url")
            surl = first.get("signed_url", "")
            tcode, _, tbytes = http("GET", turl) if turl else (0, {}, b"")
            tw, th = jpeg_size(tbytes)
            enc_name = surl.split("?")[0].rsplit("/", 1)[-1]
            info(f"image_{q}",
                 f"manifest page dims {first.get('width')}x{first.get('height')}; "
                 f"thumbnail {len(tbytes)}B {tw}x{th}px (HTTP {tcode}); encrypted file: {enc_name}")
            if surl:
                ecode, eheaders, ebytes = http("GET", surl, max_bytes=8 * 1024 * 1024)
                too_large = len(ebytes) > 8 * 1024 * 1024
                if ecode == 200 and not too_large:
                    save_enc_sample(f"page_{q}", ebytes, eheaders, ecode)
                else:
                    info(f"page_{q}_sample",
                         f"download not saved; HTTP {ecode}; "
                         f"over_8MiB={too_large}; received_at_least={len(ebytes)} bytes")

    if not TOKEN:
        info("auth", "DCUI_SESSION secret not set; skipping authenticated checks")
        return finish()

    # Which auth form does the server accept?
    for mode in ("both", "cookie", "token"):
        code, _, raw = http("GET", f"{API}/users/me/profile?trans=en", auth=mode)
        check(f"profile_auth_{mode}", code == 200, f"HTTP {code}", required=(mode == "both"))

    code, headers, _ = http("POST", f"{API}/users/set_cookie?trans=en", body=b"", auth="both", json_body=False)
    set_cookies = headers.get_all("Set-Cookie") if headers else []
    info("set_cookie", f"HTTP {code}, returns session cookie: {any(c.startswith('session=') for c in set_cookies or [])}")

    readable = None
    for uuid in free_books[:5] + [premium_book]:
        code, jwt, payload = rights(uuid, auth="both")
        if payload is None:
            check(f"rights_{uuid[:8]}", False, f"HTTP {code}, could not decode rights JWT")
            continue
        can_read = payload.get("rights", {}).get("can_read")
        signed_in = bool(payload.get("user_guid"))
        kind = "premium" if uuid == premium_book else "free"
        check(f"rights_signed_in_{kind}_{uuid[:8]}", signed_in, f"can_read={can_read}, server sees account={signed_in}")
        if can_read and readable is None:
            readable = (uuid, jwt)

    if not readable:
        check("download_manifest", False, "no book returned can_read=true; cannot test page loading", required=False)
        return finish()

    uuid, jwt = readable

    # Compare SD and HD using the authenticated account session. The earlier
    # anonymous probe can legitimately receive a lower-tier asset even when
    # the request parameter says HD, so it must not be used to judge HD support.
    for q in ("SD", "HD"):
        manifest_url = f"{API}/comics/1/book/download/?page=1&quality={q}&trans=en"
        qcode, qheaders, qraw = http(
            "GET", manifest_url, auth="both", extra={"x-auth-jwt": jwt},
        )
        if q == "HD":
            save_download_response(
                "download_HD_authenticated_page1", manifest_url,
                qcode, qheaders, qraw, q,
            )
        qdata = as_json(qraw) or {}
        qimages = qdata.get("images", [])
        if qcode != 200 or not qimages:
            info(f"authenticated_image_{q}",
                 f"HTTP {qcode}; no image entries returned")
            continue
        qfirst = qimages[0]
        qurl = qfirst.get("signed_url")
        qname = f"page_{q}_authenticated"
        if qurl:
            qfile_code, qfile_headers, qfile_bytes = http("GET", qurl, max_bytes=8 * 1024 * 1024)
            too_large = len(qfile_bytes) > 8 * 1024 * 1024
            if qfile_code == 200 and not too_large:
                save_enc_sample(qname, qfile_bytes, qfile_headers, qfile_code)
            else:
                info(f"{qname}_sample",
                     f"not saved; HTTP {qfile_code}; over_8MiB={too_large}; "
                     f"received_at_least={len(qfile_bytes)} bytes")
        info(f"authenticated_image_{q}",
             f"manifest HTTP {qcode}; first page dimensions "
             f"{qfirst.get('width')}x{qfirst.get('height')}; "
             f"asset path={qurl.split('?')[0].rsplit('/', 1)[-1] if qurl else 'missing signed_url'}")

    pages, page, num_pages = [], 1, 1
    while page <= num_pages:
        code, _, raw = http("GET", f"{API}/comics/1/book/download/?page={page}&quality=SD&trans=en",
                            auth="both", extra={"x-auth-jwt": jwt})
        d = as_json(raw)
        if code != 200 or not isinstance(d, dict):
            check("download_manifest", False, f"page {page}: HTTP {code}")
            return finish()
        if page == 1:
            save_sample("download_manifest_page1", d)
            check("download_matches_book", d.get("uuid") == uuid, "manifest uuid matches the book the JWT was issued for")
        num_pages = d.get("num_pages", 1)
        pages.extend(d.get("images", []))
        page += 1
    with_thumb = [p for p in pages if p.get("thumbnail_url")]
    check("download_manifest", len(pages) > 0 and len(with_thumb) == len(pages),
          f"{len(pages)} pages over {num_pages} manifest page(s), {len(with_thumb)} with thumbnail_url")
    numbers = [p.get("page_number") for p in pages]
    check("page_order", numbers == sorted(numbers), f"page_number sequence starts {numbers[:5]}", required=False)

    code, _, _ = http("GET", f"{API}/comics/1/book/download/?page=1&quality=SD&trans=en", extra={"x-auth-jwt": jwt})
    info("download_jwt_only", f"HTTP {code} with x-auth-jwt but no session (shows whether the JWT alone is enough)")

    if with_thumb:
        code, headers, raw = http("GET", with_thumb[0]["thumbnail_url"])
        ctype = headers.get("Content-Type", "") if headers else ""
        is_jpeg = raw[:3] == b"\xff\xd8\xff"
        check("page_image", code == 200 and is_jpeg,
              f"HTTP {code}, {ctype}, {len(raw)} bytes, JPEG magic={is_jpeg}")
        dims = [(p.get("width"), p.get("height")) for p in pages[:1]]
        info("page_image_size", f"manifest lists full page as {dims}; thumbnail fetched is {len(raw)} bytes")

    return finish()


def finish():
    failed = [r for r in results if r["status"] == "FAIL"]
    with open(os.path.join(OUT_DIR, "report.json"), "w") as f:
        json.dump(results, f, indent=2)
    lines = ["## DCUI API check", "", "| Status | Check | Detail |", "|---|---|---|"]
    lines += [f"| {r['status']} | {r['name']} | {r['detail'].replace('|', '/')} |" for r in results]
    summary = "\n".join(lines) + "\n"
    with open(os.path.join(OUT_DIR, "summary.md"), "w") as f:
        f.write(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(summary)
    print(f"\n{len(results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
