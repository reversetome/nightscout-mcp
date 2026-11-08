# nightscout-mcp

**Ask Claude about your Nightscout CGM data.** Read-only — it cannot change
anything in Nightscout.

<img src="docs/usage.png" alt="A terminal session: asking what glucose has been doing overnight and getting an hour-by-hour breakdown showing a consistent 3am low, then asking what needs changing and getting sensor age and pump battery" width="940">

> **Not a medical device.** Don't make treatment decisions from it. Readings
> can be stale, missing or wrong, and an LLM can misread them.
>
> *(Illustrative session — invented numbers, not a capture of anyone's data.)*

## Connect it

Point your client at your deployed server and send a bearer token. Standing the
server up is [further down](#setup).

**Claude** (web, desktop, mobile) — Customize → Connectors → **Add custom connector**

| field | value |
|---|---|
| URL | `https://your-host.example.com/mcp` |
| header | `authorization` |
| value | `Bearer <your MCP_BEARER>` |

Include the word `Bearer` and the space — Claude sends the value verbatim and
adds no prefix of its own. Request-header auth is a Claude beta; if you don't
see a **Request headers** section, ask Anthropic for access.

**Claude Code**

```bash
claude mcp add --transport http nightscout https://your-host.example.com/mcp \
  --header "Authorization: Bearer <your MCP_BEARER>"
```

**Anything else that speaks MCP** — this is a standard streamable-HTTP server.
Give it the `/mcp` URL and an `Authorization: Bearer …` header. Verified with
Claude, Claude Code and FastMCP's own client; nothing in it is Claude-specific.

## Tools

**Right now**

| Tool | Returns |
|---|---|
| `get_current_glucose` | Latest reading, trend direction, and how old it is |
| `get_recent_glucose` | Readings over the last N hours (default 3) |
| `get_insulin_on_board` | Active insulin and carbs on board (Loop/AAPS) |
| `get_device_status` | Pump reservoir and battery, uploader battery, loop health |
| `get_site_ages` | Age of cannula, sensor, insulin and pump battery |

**Over time**

| Tool | Returns |
|---|---|
| `time_in_range` | Low / in-range / high split, average, GMI, CV% (default 24h) |
| `glucose_patterns` | Glucose by hour of day — *when* you actually run low or high |
| `compare_periods` | The last N days against the N before, with deltas |
| `get_recent_treatments` | Boluses, carbs and site changes (default 12h) |

**Interactive**

| Tool | Returns |
|---|---|
| `glucose_dashboard` | The overview as a chart where the client supports it, JSON everywhere |

<img src="docs/dashboard.png" alt="Dashboard: average, time in range, GMI and CV as stat cards; a time-in-range bar; and percent-below-70 by hour of day with 3am highlighted" width="760">

Built on [MCP Apps](https://modelcontextprotocol.io/extensions/apps/overview),
so the tool returns **data** and the host renders the view in a sandboxed
iframe. That split matters: the same JSON the chart draws from is what the
model reads, so Claude can answer questions *about* the chart. An image it
cannot see would make the conversation worse, not better.

The range buttons don't fetch anything — they ask the host to call the tool
again. The iframe holds no credential and never talks to Nightscout. There is
also no charting CDN: the view is ~120 lines of hand-written HTML with an empty
CSP, because a third party in the render path for glucose data is not a
dependency worth taking for rounded corners.

Requires a client that supports the MCP Apps extension. Everywhere else the
same tool returns the same JSON and nothing is lost.

**Reference**

| Tool | Returns |
|---|---|
| `get_profile` | Basal rates, ISF, carb ratio, targets |
| `server_status` | Nightscout version and configured thresholds |

`glucose_patterns` is the one worth knowing about. "What is my glucose" is a
question a graph already answers; "what time of day do I reliably go low" is
one it doesn't, and it's the kind of thing a model is good at picking out of
two weeks of readings. Hours are binned in your Nightscout profile's own
timezone, so 3am means your 3am.

By default there are no write tools and the server cannot change anything in
Nightscout.

### Optional: `log_treatment` (append-only)

If — and only if — `NS_WRITE_TOKEN` is set, one extra tool appears so you can
say "I took 6u NovoRapid at 19:30" and have it recorded:

- **Append only.** It creates insulin and/or carb records. It cannot edit or
  delete anything, and it cannot send profile switches or temporary targets —
  the event types a looping app may act on.
- **Records, not doses.** It logs what already happened; it never doses and
  never suggests an amount.
- **Guard rails.** 0.5–25 u in 0.5 steps, 1–250 g, a time within the past
  24 h (never the future), a refusal if a matching record exists within
  ±10 minutes, and at most 12 writes per hour.
- **Separate credential.** Use its own subject with the `careportal` role, so
  deleting that subject turns writing off without breaking reads.

Records are tagged `enteredBy: Claude (nightscout-mcp)`. If you loop with a
pump, think twice: an app that accepts carbs from Nightscout may act on them.

### Deliberately not exposed

Nightscout's **bolus wizard preview** (`bwp`) returns a *suggested insulin
amount*. Surfacing it would turn this from something that displays your data
into something that suggests treatment — a different thing entirely, both for
you and for how such software is regulated. Same reasoning for anything that
computes a correction. Every tool here is a read.

## Security

This serves personal health data over the public internet, so the defaults are
deliberately strict:

- **A bearer token is required, and the server refuses to start without one.**
  There is no "unauthenticated if you forget the variable" mode — that is the
  failure a deployment never notices.
- **Least privilege upstream.** It reads Nightscout with a *readable* access
  token, never the admin `API_SECRET`. Unless you opt in with
  `NS_WRITE_TOKEN`, even a total compromise of this server cannot write to
  your Nightscout; with it, the most it can do is append treatment records.
- **Constant-time token comparison**, so response timing can't be used to
  recover the bearer a character at a time.
- **Errors are sanitised.** Nightscout authenticates by query parameter, so the
  token is in the request URL; upstream failures are re-raised naming only the
  path and status, keeping the credential out of logs and client-visible errors.
- **Forwarded headers are trusted only from proxies you name**, via
  `TRUSTED_PROXY_IPS`. Unset means trust nobody.
- **Runs as a non-root user** in the container.

`/health` is the one unauthenticated route. It returns a fixed `{"ok": true}`
and reads nothing.

## Setup
<a id="setup"></a>

### 1. Make a read-only Nightscout token

In Nightscout: **Admin Tools → Subjects → Add**. Give it the `readable` role
only. You get a token like `claude-1a2b3c4d5e6f7890`.

Do **not** use your `API_SECRET`. Nothing here writes, so handing it write
access buys you nothing and costs you everything if the token leaks.

### 2. Configure

```bash
cp .env.example .env
# edit .env — at minimum NS_URL, NS_TOKEN, MCP_BEARER
```

Generate the bearer with something you didn't invent yourself:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Run

```bash
docker build -t nightscout-mcp .
docker run -d --name nightscout-mcp --env-file .env -p 8787:8787 nightscout-mcp
```

Or without Docker:

```bash
pip install -r requirements.txt
set -a && source .env && set +a
python server.py
```

### 4. Put it behind HTTPS

The server speaks plain HTTP and expects TLS to be terminated in front of it
(Traefik, Caddy, nginx, Cloudflare Tunnel — anything). Claude connects from
Anthropic's servers, not from your device, so the URL must be reachable from
the public internet.

If your proxy sets `X-Forwarded-*`, name it:

```
TRUSTED_PROXY_IPS=172.18.0.0/16
```

### 5. Connect it to Claude

In Claude: **Customize → Connectors → Add custom connector**

- **URL**: `https://your-host.example.com/mcp/`
- Open **Request headers**, add `authorization` with value
  `Bearer <your MCP_BEARER>`

Enter the value including the word `Bearer` and the space — Claude sends the
header verbatim and adds no prefix of its own.

> Request-header auth is a Claude beta. If you don't see a **Request headers**
> section, ask Anthropic for access. Claude Code can use the same server today
> via its own MCP configuration.

## Units

`NS_UNITS=mg/dl` (default) or `mmol`. This only affects how values are
presented; Nightscout is always read in mg/dL and converted on the way out.

## Relationship to Nightscout

This is an independent project. It is not affiliated with, endorsed by, or part
of the Nightscout Foundation.

Nightscout itself ([cgm-remote-monitor](https://github.com/nightscout/cgm-remote-monitor))
is licensed **AGPL-3.0**. This server contains no Nightscout code and links no
Nightscout library — it only makes HTTP requests to a running instance's REST
API. Consuming an API at arm's length does not create a derivative work, and
the AGPL's network clause is conditioned on modifying the covered program,
which this does not do. So Nightscout's copyleft does not extend here, and this
project is separately licensed.

If you fork this and vendor any Nightscout source into it, that reasoning stops
applying to your fork.

## License

MIT — see [LICENSE](LICENSE).

Chosen for reach: this is a small connector whose value is that anyone can run
it in ten minutes. Copyleft would protect nobody in the common case, which is
one person self-hosting it for their own data.
