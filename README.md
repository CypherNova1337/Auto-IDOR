# IDOR-Auto

**IDOR-Auto** is an access-control testing tool for finding IDOR / BOLA
(Broken Object-Level Authorization) vulnerabilities — including the complex ones
that status-code scanners miss.

It does **not** guess vulnerabilities from HTTP status codes. Instead it performs
**differential access testing**: it drives several distinct identities against the
same objects and proves whether one identity can obtain another's data. A finding
means *"user A read user B's object"*, not *"the endpoint returned 200"*.

> For authorized security testing only — pentests, bug bounty within scope, and
> your own applications. See [Disclaimer](#disclaimer).

---

## Why this is different from a status-code scanner

The classic approach ("append an id, flag every `200`") drowns you in false
positives: plenty of endpoints legitimately return `200`. IDOR-Auto reasons about
*access* using three reference responses for every object id:

| Reference | Meaning |
|-----------|---------|
| **owner** | the victim identity reading *its own* object — the authorized truth |
| **attacker** | another identity trying to read the victim's object — the test |
| **denied** | the anonymous baseline — what *properly refused* looks like |

An IDOR is reported only when the **attacker's response matches the owner's and
differs from the denied baseline**. If the attacker gets the same thing an
anonymous user gets, the endpoint is simply *public* — reported as
`not-vulnerable`, not as a false alarm.

On top of that it understands the parts of real IDORs that trip up naive tools:

- **Canary / secret oracle** — the strongest signal. Tell it a string that is
  private to a victim (email, account name, API key). If that value ever appears
  in another identity's response, it's a confirmed leak (HIGH confidence),
  regardless of body similarity.
- **Injection anywhere** — the id can live in the URL path, a query parameter, a
  request header, a cookie, or anywhere inside a JSON / form body (any depth).
- **Wrapped / obfuscated ids** — try the same logical id `raw`, `base64`,
  `base64url`, `hex`, or URL-encoded so you reach references the app expects
  encoded.
- **Method tampering** — replay the same request under other HTTP methods.
- **Raw request import** — paste a request straight from Burp; IDOR-Auto parses
  it and auto-locates the identifier to attack.
- **Identifier detection** — classifies values (int / uuid / objectid / hex /
  base64 / jwt) and ranks which are worth attacking.

---

## Installation

Requires Python 3.8+.

```bash
git clone https://github.com/CypherNova1337/IDOR-Auto.git
cd IDOR-Auto
pip install -r requirements.txt        # requests (+ PyYAML for YAML configs)
```

Optionally install it as a command:

```bash
pip install .          # provides the `auto-idor` command
```

Everywhere below, `auto-idor` and `python3 -m auto_idor` are interchangeable.

---

## Quick start

### 1. Ad-hoc test between two users

Give each user their auth and the ids they legitimately own. `{id}` marks where
the object reference goes.

```bash
auto-idor quick \
  -u https://api.example.com/api/v1/invoices/{id} \
  --token-a "ALICE_JWT" --owns-a 1001,1002 --secret-a "alice@corp.example" \
  --token-b "BOB_JWT"   --owns-b 2001,2002 --secret-b "bob@corp.example"
```

Example output:

```
[VULNERABLE/HIGH] quick: user-a -> user-b's id=2001 [GET]  attacker=200 owner=200 anon=401
        victim's private data leaked to attacker: 'bob@corp.example'
        leaked canary: 'bob@corp.example'
```

Non-bearer auth? Use `-H/--header-a`, `--cookie-a` (and the `-b` equivalents):

```bash
auto-idor quick -u https://api/doc/{id} \
  -H "X-Api-Key: AAA" --cookie-a "session=xxx" --owns-a 10,11 \
  --header-b "X-Api-Key: BBB" --cookie-b "session=yyy" --owns-b 20,21
```

### 2. From a raw Burp request

Save the request to a file (Burp → *Copy to file*), then:

```bash
# See what IDOR-Auto would attack:
auto-idor detect -r request.txt

# Run it (auto-marks the best identifier, or pin one with --mark):
auto-idor quick -r request.txt --mark 2001 \
  --token-a ALICE --owns-a 1001 --token-b BOB --owns-b 2001
```

`detect` output:

```
[*] GET https://api.example.com/api/v1/invoices/2001?ref=abc123def456
[*] 2 identifier candidate(s), best first:

    query[ref] = 'abc123def456' (hex, score 0.95)
    path[3] = '2001' (int, score 0.65)
```

### 3. Full scan from a config file

For complex targets (nested body ids, multiple endpoints, many identities), use a
config. Generate a starter:

```bash
auto-idor init idor.yaml     # writes a commented example
auto-idor run -c idor.yaml
```

---

## Config reference

YAML (needs PyYAML) or JSON — both accepted. See [`examples/`](examples/).

```yaml
base_url: https://api.example.com

# transport (all optional)
threads: 8                 # concurrent workers
timeout: 15                # per-request seconds
delay: 0.0                 # throttle: seconds between requests per worker
verify_tls: true
# proxy: http://127.0.0.1:8080     # route through Burp / mitmproxy
include_anonymous: true            # add the no-auth "denied" baseline
# high_threshold: 0.95             # similarity to call it the same object
# medium_threshold: 0.6

identities:
  - name: alice
    headers:
      Authorization: "Bearer ALICE_TOKEN"
    cookies:
      session: alices-cookie
    owns: [1001, 1002]                       # ids alice legitimately owns
    secrets: ["alice@corp.example"]          # canaries private to alice
  - name: bob
    headers:
      Authorization: "Bearer BOB_TOKEN"
    owns: [2001, 2002]
    secrets: ["bob@corp.example"]

rules:
  # Path-based reference.
  - name: get-invoice
    request:
      method: GET
      path: /api/v1/invoices/{id}

  # Id nested in a JSON body, base64-wrapped, also replayed as GET.
  - name: order-detail
    request:
      method: POST
      path: /api/v1/orders/detail
      headers:
        Content-Type: application/json
      json:
        filter:
          orderId: "{id}"
    encodings: [raw, base64]
    method_tamper: [GET]
```

**How the matrix is built:** for every rule, each identity's `owns` ids are read
by that identity (owner baseline) and by the anonymous baseline, then every *other*
identity attempts to read them. Baselines are fetched once and cached.

> **YAML tip:** write `path: /api/v1/invoices/{id}` in block style (its own line).
> Inside a flow mapping `{ ... }`, quote it: `path: "/api/v1/invoices/{id}"`.

### Request fields

| Field | Purpose |
|-------|---------|
| `method` | HTTP method |
| `path` | URL path (absolute `http…` URLs also allowed); may contain `{id}` |
| `query` | query params (values may contain `{id}`) |
| `headers` | per-request headers (values may contain `{id}`) |
| `cookies` | per-request cookies |
| `json` | JSON body; `{id}` may appear at any depth |
| `form` | `application/x-www-form-urlencoded` body |
| `body` | raw request body string |

### Rule options

| Option | Default | Purpose |
|--------|---------|---------|
| `id_token` | `{id}` | placeholder substituted with the object id |
| `encodings` | `[raw]` | any of `raw, base64, base64url, hex, urlencode, double-urlencode` |
| `method_tamper` | `[]` | extra methods to replay the same request with |
| `extra_ids` | `[]` | rule-level ids to test in addition to each victim's `owns` |

---

## Reading the results

Each result line reports a verdict and confidence:

- **`VULNERABLE`** — the attacker obtained the victim's object (canary leak, or
  body matches the owner and differs from the denied baseline).
- **`SUSPICIOUS`** — the attacker got a success but the content only partially
  matches; verify manually.
- **`not-vulnerable`** — properly denied, or the endpoint is public.
- **`inconclusive`** — the owner couldn't read its own object, so no baseline.

By default only `VULNERABLE` / `SUSPICIOUS` are printed; add `--all` to see
everything. `-o findings.json` writes structured results (with per-comparison
similarity scores and any leaked canaries) for triage or CI. The process exits
`2` when anything needs a human's attention, `0` otherwise.

### Common flags

```
--threads N            concurrent workers (default 8)
--delay S              seconds between requests per worker (throttle)
--timeout S            per-request timeout
--proxy URL            route through Burp/mitmproxy (http://127.0.0.1:8080)
--insecure             skip TLS verification
--follow-redirects     follow redirects
--no-anonymous         omit the anonymous baseline
-o, --output FILE      write findings as JSON
--all                  also show not-vulnerable / inconclusive
-q, --quiet            suppress progress
```

---

## Tests

```bash
python -m unittest discover -s tests
```

The suite covers the oracle's verdicts, identifier detection, raw-request
parsing, and an end-to-end scan against an in-process mock API (no network
required).

---

## Disclaimer

This tool sends unauthorized-access *attempts* by design. Only run it against
systems you own or are explicitly authorized to test. A `VULNERABLE` verdict is a
strong, evidence-backed lead — confirm the impact (what data was exposed, to whom)
before reporting. The authors accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
