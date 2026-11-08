#!/usr/bin/env python3
"""
Nightscout MCP server — read-only by default, with one optional,
append-only write tool.

Exposes glucose, treatments, profile and device status from a Nightscout
instance to MCP clients (e.g. the Claude apps) over HTTP.

Security model:
  - Every request must carry a static bearer token (MCP_BEARER). The server
    REFUSES TO START without one: this thing serves personal health data over
    the public internet, and an unset environment variable must not be the
    difference between authenticated and open.
  - Nightscout is read with a least-privilege *readable* access token
    (NS_TOKEN), never the admin API_SECRET.
  - Writing is OFF unless NS_WRITE_TOKEN is set. When it is, exactly one tool
    is registered: `log_treatment`, which can only APPEND an insulin and/or
    carb record. There is no update, no delete, and no way to send profile
    switches or temporary targets — the event types a looping app (AAPS,
    Loop) may act on. The write token should be a separate subject with the
    `careportal` role, so writing can be revoked without breaking reads.
  - The Nightscout token travels as a query parameter (Nightscout's own API
    convention), so upstream errors are sanitised before they surface — an
    unsanitised httpx error embeds the full request URL, token included, into
    logs and client-visible messages.

Env:
  NS_URL          required   e.g. https://your-nightscout.example.com
  NS_TOKEN        optional   Nightscout readable access token (subject-<hex>)
  NS_WRITE_TOKEN  optional   careportal-role token; enables log_treatment
  MCP_BEARER      required   bearer token callers must present
  PORT            optional   listen port (default 8787)
  NS_UNITS        optional   mg/dl (default) or mmol -- display unit for stats
  TRUSTED_PROXY_IPS  optional  see main()
"""
import hmac
import json
import os
import statistics
import time
from collections import deque
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo

import httpx
from fastmcp import FastMCP
from fastmcp.apps import AppConfig, ResourceCSP
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

NS_URL = os.environ["NS_URL"].rstrip("/")
NS_TOKEN = os.environ.get("NS_TOKEN", "")
# Unset (the default) means no write tool exists at all — not "exists and
# fails". A tool the model can see invites calls; one it cannot see cannot be
# talked into anything.
NS_WRITE_TOKEN = os.environ.get("NS_WRITE_TOKEN", "")

# Required, and deliberately so.
#
# This was once optional, falling back to "the URL path is unguessable" —
# a workaround from when Claude connectors supported only OAuth or no auth.
# Static bearer headers are supported now (see README), so the workaround has
# no reason to exist, and secret-URL-only auth is a poor trade for health data:
# URLs leak through logs, proxies and browser history in a way headers do not.
#
# Failing at startup rather than at request time is the point. A server that
# boots happily and silently serves unauthenticated CGM data is exactly the
# failure a deployment forgets to notice.
MCP_BEARER = os.environ.get("MCP_BEARER", "")
if not MCP_BEARER:
    raise SystemExit(
        "MCP_BEARER is required — refusing to start an unauthenticated server "
        "that exposes personal health data. Set it to a long random string."
    )
PORT = int(os.environ.get("PORT", "8787"))
UNITS = os.environ.get("NS_UNITS", "mg/dl").lower()

MMOL = 18.0156  # mg/dL per mmol/L


def _fmt(mgdl: float) -> float:
    """Return a value in the configured display unit."""
    if UNITS.startswith("mmol"):
        return round(mgdl / MMOL, 1)
    return round(mgdl)


async def _ns_get(path: str, params: dict | None = None) -> object:
    """GET from Nightscout, raising errors that cannot carry the token.

    Nightscout authenticates by query parameter, so the credential is in the
    request URL. httpx's own `raise_for_status` puts that URL in the exception
    message, which then travels into logs and back to the MCP client — so the
    error is rebuilt here naming only the path and status.
    """
    params = dict(params or {})
    if NS_TOKEN:
        params["token"] = NS_TOKEN
    async with httpx.AsyncClient(timeout=20) as c:
        try:
            r = await c.get(f"{NS_URL}{path}", params=params)
        except httpx.RequestError as exc:
            raise RuntimeError(f"Nightscout request to {path} failed: {type(exc).__name__}") from None
        if r.status_code >= 400:
            raise RuntimeError(f"Nightscout returned {r.status_code} for {path}") from None
        try:
            return r.json()
        except ValueError:
            raise RuntimeError(f"Nightscout returned non-JSON for {path}") from None


async def _ns_post_treatment(doc: dict) -> object:
    """POST one treatment with the write token, errors sanitised as in _ns_get.

    Hard-wired to /api/v1/treatments on purpose: there is no generic POST
    helper in this module, so no future tool can reuse it to reach profiles,
    entries or devicestatus by accident.
    """
    async with httpx.AsyncClient(timeout=20) as c:
        try:
            r = await c.post(
                f"{NS_URL}/api/v1/treatments",
                params={"token": NS_WRITE_TOKEN},
                json=doc,
            )
        except httpx.RequestError as exc:
            raise RuntimeError(f"Nightscout write failed: {type(exc).__name__}") from None
        if r.status_code in (401, 403):
            raise RuntimeError(
                f"Nightscout refused the write ({r.status_code}) — NS_WRITE_TOKEN "
                "needs a subject with the careportal role"
            ) from None
        if r.status_code >= 400:
            raise RuntimeError(f"Nightscout returned {r.status_code} for the write") from None
        try:
            return r.json()
        except ValueError:
            return None


# ---- bearer auth gate (everything except /health) -------------------------
class BearerAuth(BaseHTTPMiddleware):
    """Static bearer gate.

    `/health` is deliberately open so container orchestrators can probe it; it
    returns a fixed `{"ok": true}` and reads nothing, so there is nothing to
    leak through it.

    The comparison is constant-time. A plain `!=` on a secret leaks its length
    and matching prefix through response timing, which is a slow but real way
    to recover a token from a server anyone on the internet can call.
    """

    async def dispatch(self, request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        if not hmac.compare_digest(auth, f"Bearer {MCP_BEARER}"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def _tir_stats(vals: list[float]) -> dict:
    """Time-in-range, average, GMI and CV for a list of mg/dL readings.

    Shared by `time_in_range` and `compare_periods` so the two can never
    disagree about what "in range" means — a comparison built on a second copy
    of these thresholds would eventually compare two different questions.
    """
    n = len(vals)
    if not n:
        return {"readings": 0}

    def pct(lo, hi):
        return round(100 * sum(1 for v in vals if lo <= v < hi) / n, 1)

    mean = statistics.mean(vals)
    sd = statistics.pstdev(vals) if n > 1 else 0
    return {
        "readings": n,
        "units": UNITS,
        "average": _fmt(mean),
        "gmi_a1c_percent": round(3.31 + 0.02392 * mean, 1),
        "cv_percent": round(100 * sd / mean, 1) if mean else None,
        "very_low_lt54": pct(0, 54),
        "low_54_70": pct(54, 70),
        "in_range_70_180": pct(70, 180),
        "high_180_250": pct(180, 250),
        "very_high_ge250": pct(250, 10000),
    }


async def _sgv_since(days: float, until_days_ago: float = 0) -> list[dict]:
    """Raw SGV entries in a window, newest-first as Nightscout returns them."""
    now = datetime.now(timezone.utc)
    start = int((now - timedelta(days=days + until_days_ago)).timestamp() * 1000)
    end = int((now - timedelta(days=until_days_ago)).timestamp() * 1000)
    return await _ns_get(
        "/api/v1/entries/sgv.json",
        {"count": 200000, "find[date][$gte]": start, "find[date][$lt]": end},
    )


async def _local_tz() -> timezone | ZoneInfo:
    """The Nightscout profile's timezone, so "3am" means the user's 3am.

    Binning by UTC hour would silently shift every pattern by the offset, which
    is the kind of wrong that still looks like a plausible chart.
    """
    try:
        p = await _ns_get("/api/v1/profile.json")
        name = (p[0].get("store", {}).get(p[0].get("defaultProfile", ""), {}) or {}).get("timezone")
        if name:
            return ZoneInfo(name)
    except Exception:
        pass
    return timezone.utc


mcp = FastMCP("nightscout-readonly")


@mcp.tool
async def get_current_glucose() -> dict:
    """Latest glucose reading with trend direction and age."""
    e = await _ns_get("/api/v1/entries/sgv.json", {"count": 1})
    if not e:
        return {"error": "no readings"}
    r = e[0]
    mgdl = r.get("sgv")
    return {
        "glucose": _fmt(mgdl),
        "units": UNITS,
        "mgdl": mgdl,
        "direction": r.get("direction"),
        "time": r.get("dateString"),
        "device": r.get("device"),
    }


@mcp.tool
async def get_recent_glucose(hours: float = 3) -> dict:
    """Glucose readings from the past `hours` (default 3)."""
    since = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp() * 1000)
    e = await _ns_get(
        "/api/v1/entries/sgv.json",
        {"count": 5000, "find[date][$gte]": since},
    )
    pts = [
        {"t": x.get("dateString"), "glucose": _fmt(x["sgv"]), "direction": x.get("direction")}
        for x in e
        if x.get("sgv") is not None
    ]
    return {"units": UNITS, "count": len(pts), "readings": pts}


@mcp.tool
async def time_in_range(hours: float = 24) -> dict:
    """Time-in-range, average, GMI (est. A1C) and CV% over the past `hours`."""
    since = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp() * 1000)
    e = await _ns_get(
        "/api/v1/entries/sgv.json",
        {"count": 100000, "find[date][$gte]": since},
    )
    vals = [x["sgv"] for x in e if x.get("sgv")]
    if not vals:
        return {"error": "no readings in window"}
    return {"hours": hours, **_tir_stats(vals)}


@mcp.tool
async def get_recent_treatments(hours: float = 12) -> dict:
    """Insulin boluses, carbs and other treatments from the past `hours`."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    t = await _ns_get(
        "/api/v1/treatments.json",
        {"count": 1000, "find[created_at][$gte]": since},
    )
    out = [
        {
            "time": x.get("created_at"),
            "type": x.get("eventType"),
            "insulin": x.get("insulin"),
            "carbs": x.get("carbs"),
            "notes": x.get("notes"),
        }
        for x in t
    ]
    return {"count": len(out), "treatments": out}


@mcp.tool
async def get_insulin_on_board() -> dict:
    """Current IOB/COB from the latest device status (Loop/AAPS)."""
    d = await _ns_get("/api/v1/devicestatus.json", {"count": 1})
    if not d:
        return {"error": "no device status"}
    s = d[0]
    loop = s.get("loop", {})
    return {
        "time": s.get("created_at"),
        "device": s.get("device"),
        "iob": (loop.get("iob") or {}).get("iob") if isinstance(loop.get("iob"), dict) else loop.get("iob"),
        "cob": (loop.get("cob") or {}).get("cob") if isinstance(loop.get("cob"), dict) else loop.get("cob"),
        "raw": loop or s.get("openaps") or {},
    }


@mcp.tool
async def get_profile() -> dict:
    """Active treatment profile (basal, ISF, carb ratio, targets)."""
    p = await _ns_get("/api/v1/profile.json")
    if not p:
        return {"error": "no profile"}
    return p[0]


@mcp.tool
async def server_status() -> dict:
    """Nightscout version, name and configured thresholds."""
    return await _ns_get("/api/v1/status.json")


@mcp.tool
async def get_site_ages() -> dict:
    """How long since the cannula, sensor, insulin and pump battery were changed.

    The question with a deadline: what is due for replacement.
    """
    try:
        props = await _ns_get("/api/v2/properties/cage,sage,iage,bage")
    except RuntimeError:
        return {"error": "site-age plugins (cage/sage/iage/bage) not enabled on this Nightscout"}
    labels = {
        "cage": "cannula",
        "sage": "sensor",
        "iage": "insulin",
        "bage": "pump_battery",
    }
    out = {}
    for key, label in labels.items():
        v = props.get(key) or {}
        # `found` false means the plugin is on but has never seen the event —
        # reporting age 0 there would read as "just changed", the opposite.
        if not v or v.get("found") is False:
            out[label] = {"known": False}
            continue
        out[label] = {
            "known": True,
            "days": v.get("days"),
            "hours": v.get("hours"),
            "age_hours": v.get("age"),
            "changed_at": v.get("treatmentDate"),
        }
    return out


@mcp.tool
async def get_device_status() -> dict:
    """Pump reservoir and battery, uploader battery, and loop health.

    What is about to fail. `get_insulin_on_board` reads the same record but
    only for IOB/COB; this is the hardware side of it.
    """
    d = await _ns_get("/api/v1/devicestatus.json", {"count": 1})
    if not d:
        return {"error": "no device status"}
    s = d[0]
    pump = s.get("pump") or {}
    loop = s.get("loop") or {}
    battery = pump.get("battery") or {}
    return {
        "time": s.get("created_at"),
        "device": s.get("device"),
        "uploader_battery_percent": (s.get("uploader") or {}).get("battery"),
        "pump": {
            "reservoir_units": pump.get("reservoir"),
            "battery_percent": battery.get("percent"),
            "battery_voltage": battery.get("voltage"),
            "status": (pump.get("status") or {}).get("status"),
            "last_seen": pump.get("clock"),
        },
        "loop": {
            "last_success": loop.get("timestamp"),
            # A recommendation the loop made is reported as loop STATE, never
            # surfaced as a suggestion to act on — this server does not advise.
            "enacted": bool(loop.get("enacted")),
            "failure": (loop.get("failureReason") or None),
        },
    }


@mcp.tool
async def glucose_patterns(days: int = 14) -> dict:
    """Glucose by hour of day over `days` — when highs and lows actually happen.

    The retrospective question a graph is bad at answering: not "what is my
    glucose", but "what time of day do I reliably go low". Binned in the
    Nightscout profile's own timezone, so the hours mean what the user means.
    """
    e = await _sgv_since(days)
    tz = await _local_tz()
    buckets: dict[int, list[float]] = {h: [] for h in range(24)}
    for x in e:
        v = x.get("sgv")
        ts = x.get("date")
        if not v or not ts:
            continue
        hour = datetime.fromtimestamp(ts / 1000, tz).hour
        buckets[hour].append(v)

    total = sum(len(v) for v in buckets.values())
    if not total:
        return {"error": f"no readings in the past {days} days"}

    hours = []
    for h in range(24):
        vals = buckets[h]
        if not vals:
            hours.append({"hour": h, "readings": 0})
            continue
        vals_sorted = sorted(vals)
        n = len(vals_sorted)
        hours.append({
            "hour": h,
            "readings": n,
            "median": _fmt(statistics.median(vals_sorted)),
            "p25": _fmt(vals_sorted[max(0, int(n * 0.25) - 1)]),
            "p75": _fmt(vals_sorted[min(n - 1, int(n * 0.75))]),
            "percent_below_70": round(100 * sum(1 for v in vals if v < 70) / n, 1),
            "percent_above_180": round(100 * sum(1 for v in vals if v > 180) / n, 1),
        })

    worst_low = max((h for h in hours if h.get("readings")), key=lambda h: h["percent_below_70"])
    worst_high = max((h for h in hours if h.get("readings")), key=lambda h: h["percent_above_180"])
    return {
        "days": days,
        "timezone": str(tz),
        "units": UNITS,
        "readings": total,
        "by_hour": hours,
        "most_low_hour": {"hour": worst_low["hour"], "percent_below_70": worst_low["percent_below_70"]},
        "most_high_hour": {"hour": worst_high["hour"], "percent_above_180": worst_high["percent_above_180"]},
    }


@mcp.tool
async def compare_periods(days: int = 7) -> dict:
    """Compare the last `days` against the `days` before that.

    Answers "did the change help?" — which needs two windows measured the same
    way, so both go through the same stats helper as `time_in_range`.
    """
    recent = [x["sgv"] for x in await _sgv_since(days) if x.get("sgv")]
    prior = [x["sgv"] for x in await _sgv_since(days, until_days_ago=days) if x.get("sgv")]
    if not recent or not prior:
        return {"error": "not enough history to compare two windows"}

    a, b = _tir_stats(prior), _tir_stats(recent)

    def delta(key):
        if a.get(key) is None or b.get(key) is None:
            return None
        return round(b[key] - a[key], 1)

    return {
        "days_per_window": days,
        "previous": a,
        "recent": b,
        # Deltas are recent-minus-previous: positive means the number went up,
        # which is good for in_range and bad for the rest. Direction is left to
        # the reader on purpose; this server reports, it does not judge.
        "change": {
            k: delta(k)
            for k in (
                "average",
                "gmi_a1c_percent",
                "cv_percent",
                "very_low_lt54",
                "low_54_70",
                "in_range_70_180",
                "high_180_250",
                "very_high_ge250",
            )
        },
    }


# ---- optional append-only write tool ---------------------------------------
#
# Registered only when NS_WRITE_TOKEN is set (see the bottom of this block).
# Every limit below exists because the record lands in the same treatments
# collection a looping app reads to compute insulin-on-board: a wrong entry is
# not a cosmetic error there.
INSULIN_MIN, INSULIN_MAX = 0.5, 25.0   # units; pen doses, recorded not dosed
CARBS_MIN, CARBS_MAX = 1, 250          # grams
MAX_AGE = timedelta(hours=24)          # backfilling further than this is a job for a human
FUTURE_SKEW = timedelta(minutes=5)     # tolerate clock drift, refuse the future
DUP_WINDOW = timedelta(minutes=10)     # "did I already log that?" radius
WRITES_PER_HOUR = 12                   # a person logs a handful; a loop logs hundreds
_ENTERED_BY = "Claude (nightscout-mcp)"
_write_times: deque[float] = deque()


def _parse_when(when: str | None, tz, now: datetime) -> datetime:
    """Turn the caller's time into an aware UTC datetime.

    Accepts ISO 8601 (with or without offset; naive means the Nightscout
    profile's local time), 'YYYY-MM-DD HH:MM' local, or bare 'HH:MM' meaning
    its most recent past occurrence — said at 01:00, "23:00" is last night,
    not tonight.
    """
    if not when or not when.strip():
        return now
    s = when.strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        hm = datetime.strptime(s, "%H:%M")
    except ValueError:
        raise ValueError(
            "`at` must be 'YYYY-MM-DD HH:MM' (local), 'HH:MM', or ISO 8601"
        ) from None
    local_now = now.astimezone(tz)
    cand = local_now.replace(hour=hm.hour, minute=hm.minute, second=0, microsecond=0)
    if cand - local_now > FUTURE_SKEW:
        cand -= timedelta(days=1)
    return cand.astimezone(timezone.utc)


def _iso_ms(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


async def log_treatment(
    insulin_units: float | None = None,
    insulin_name: Literal["NovoRapid", "Fiasp", "Other"] | None = None,
    carbs_g: float | None = None,
    at: str | None = None,
    notes: str | None = None,
    allow_duplicate: bool = False,
) -> dict:
    """Append an insulin and/or carb RECORD to Nightscout. Writes nothing else.

    A record of something that already happened — it doses nothing. Call it
    only when the user has said, in their own words, that they took this
    insulin or ate these carbs, and read the exact entry back to them first.
    Never call it on your own estimate alone or to "fix" existing data; it
    cannot edit or delete, and a wrong record skews insulin-on-board in apps
    such as AAPS.

    Args:
      insulin_units: 0.5–25 in 0.5 steps.
      insulin_name: which insulin (NovoRapid / Fiasp / Other); kept in notes.
      carbs_g: 1–250.
      at: when it happened, in the Nightscout profile's local time:
          'YYYY-MM-DD HH:MM', or 'HH:MM' (its most recent past occurrence),
          or ISO 8601 with offset. Omit for "now". Must be within 24 h.
      notes: optional, up to 200 characters (e.g. "high-fat meal").
      allow_duplicate: a matching record within ±10 min is refused unless
          this is true — set it only after the user confirms both are real.
    """
    if insulin_units is None and carbs_g is None:
        raise ValueError("give insulin_units, carbs_g, or both")
    if insulin_units is not None:
        if not (INSULIN_MIN <= insulin_units <= INSULIN_MAX):
            raise ValueError(f"insulin_units must be {INSULIN_MIN}–{INSULIN_MAX}")
        if abs(insulin_units * 2 - round(insulin_units * 2)) > 1e-9:
            raise ValueError("insulin_units must be in 0.5-unit steps")
    if carbs_g is not None:
        if not (CARBS_MIN <= carbs_g <= CARBS_MAX):
            raise ValueError(f"carbs_g must be {CARBS_MIN}–{CARBS_MAX}")
        carbs_g = round(carbs_g, 1)
    notes = (notes or "").strip()
    if len(notes) > 200:
        raise ValueError("notes must be 200 characters or fewer")

    tz = await _local_tz()
    now = datetime.now(timezone.utc)
    when = _parse_when(at, tz, now)
    if when - now > FUTURE_SKEW:
        raise ValueError("that time is in the future — only past events can be recorded")
    if now - when > MAX_AGE:
        raise ValueError("that is more than 24 hours ago — enter it in AAPS/Nightscout directly")

    mono = time.monotonic()
    while _write_times and mono - _write_times[0] > 3600:
        _write_times.popleft()
    if len(_write_times) >= WRITES_PER_HOUR:
        raise RuntimeError(f"write limit reached ({WRITES_PER_HOUR}/hour); try again later")

    # Duplicate guard. Fails closed: if we cannot read, we do not write.
    nearby = await _ns_get(
        "/api/v1/treatments.json",
        {
            "count": 200,
            "find[created_at][$gte]": _iso_ms(when - DUP_WINDOW),
            "find[created_at][$lte]": _iso_ms(when + DUP_WINDOW),
        },
    )
    dups = [
        {"time": x.get("created_at"), "insulin": x.get("insulin"), "carbs": x.get("carbs")}
        for x in (nearby or [])
        if (insulin_units is not None and abs((x.get("insulin") or 0) - insulin_units) < 0.01)
        or (carbs_g is not None and abs((x.get("carbs") or 0) - carbs_g) < 0.05)
    ]
    if dups and not allow_duplicate:
        return {
            "status": "refused_possible_duplicate",
            "message": "a matching record already exists within ±10 minutes; nothing was written",
            "existing": dups,
        }

    local = when.astimezone(tz)
    base = {
        "created_at": _iso_ms(when),
        "date": int(when.timestamp() * 1000),
        "utcOffset": int((local.utcoffset() or timedelta()).total_seconds() // 60),
        "enteredBy": _ENTERED_BY,
    }
    note_text = " · ".join(p for p in (insulin_name if insulin_units is not None else None, notes) if p)
    # One record per item, eventType "Meal Bolus" — the same shape AAPS itself
    # uploads, so it is read back the same way.
    docs = []
    if insulin_units is not None:
        docs.append({**base, "eventType": "Meal Bolus", "insulin": insulin_units, "notes": note_text})
    if carbs_g is not None:
        docs.append({**base, "eventType": "Meal Bolus", "carbs": carbs_g, "notes": notes})

    created = await _ns_post_treatment(docs if len(docs) > 1 else docs[0])
    _write_times.append(mono)
    created_list = created if isinstance(created, list) else ([created] if created else [])
    return {
        "status": "logged",
        "time_local": local.strftime("%Y-%m-%d %H:%M"),
        "timezone": str(tz),
        "records": [
            {
                "id": c.get("_id") if isinstance(c, dict) else None,
                "insulin": d.get("insulin"),
                "carbs": d.get("carbs"),
                "notes": d.get("notes"),
            }
            for c, d in zip(created_list or [{}] * len(docs), docs)
        ],
        "reminder": "record only — nothing was dosed",
    }


if NS_WRITE_TOKEN:
    mcp.tool(log_treatment)


# ---- interactive dashboard (MCP Apps) --------------------------------------
#
# The tool returns DATA; the resource below returns the view that draws it. That
# split is the whole point of the extension: the host renders the HTML in a
# sandboxed iframe, and the same JSON the chart draws from is what the model
# reads to answer questions about it. A picture the model cannot see would make
# the conversation worse, not better.
#
# The view is served from disk rather than embedded so it stays editable as HTML,
# and it loads NO external origin — an empty CSP. A CDN in the render path for
# glucose data is a third party in a place that does not need one.
_UI = Path(__file__).parent / "ui" / "glucose.html"


@mcp.tool(
    app=AppConfig(
        resource_uri="ui://nightscout/glucose.html",
        csp=ResourceCSP(connect_domains=[], resource_domains=[]),
    )
)
async def glucose_dashboard(days: int = 14) -> str:
    """Glucose overview for the past `days`: time-in-range, GMI, CV, and the
    hourly low/high pattern. Renders as an interactive chart where the client
    supports it, and returns the same numbers as JSON either way."""
    e = await _sgv_since(days)
    tz = await _local_tz()
    vals = [x["sgv"] for x in e if x.get("sgv")]
    if not vals:
        return json.dumps({"error": f"no readings in the past {days} days"})

    buckets: dict[int, list[float]] = {h: [] for h in range(24)}
    for x in e:
        if x.get("sgv") and x.get("date"):
            buckets[datetime.fromtimestamp(x["date"] / 1000, tz).hour].append(x["sgv"])

    by_hour = []
    for h in range(24):
        b = buckets[h]
        by_hour.append(
            {
                "hour": h,
                "readings": len(b),
                "median": _fmt(statistics.median(b)) if b else None,
                "percent_below_70": round(100 * sum(1 for v in b if v < 70) / len(b), 1) if b else 0,
                "percent_above_180": round(100 * sum(1 for v in b if v > 180) / len(b), 1) if b else 0,
            }
        )

    withdata = [h for h in by_hour if h["readings"]]
    worst = max(withdata, key=lambda h: h["percent_below_70"]) if withdata else None
    return json.dumps(
        {
            "days": days,
            "units": UNITS,
            "timezone": str(tz),
            "summary": _tir_stats(vals),
            "by_hour": by_hour,
            "most_low_hour": (
                {"hour": worst["hour"], "percent_below_70": worst["percent_below_70"]}
                if worst
                else None
            ),
        }
    )


@mcp.resource("ui://nightscout/glucose.html", mime_type="text/html")
def glucose_view() -> str:
    """The dashboard markup. Static, self-contained, no network of its own."""
    return _UI.read_text(encoding="utf-8")


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


def main():
    app = mcp.http_app(middleware=[Middleware(BearerAuth)])
    import uvicorn

    # X-Forwarded-* is only trustworthy from a proxy you control. The previous
    # value here was "*", which trusts the header from any caller — fine when
    # nothing but Traefik can reach the port, and a spoofing hole the moment
    # the container is exposed directly. Default to trusting nobody and let a
    # deployment name its proxy explicitly.
    trusted = os.environ.get("TRUSTED_PROXY_IPS", "").strip()
    uvicorn.run(
        app,
        host=os.environ.get("BIND_HOST", "0.0.0.0"),
        port=PORT,
        proxy_headers=bool(trusted),
        forwarded_allow_ips=trusted or None,
    )


if __name__ == "__main__":
    main()
