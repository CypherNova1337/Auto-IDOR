# Auto-IDOR

Proves one user can read another user's data — instead of guessing from status codes.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square)

## What it does

An application shows you your own invoice at:

```
https://app.example/api/invoices/1042
```

Change `1042` to `1041` and you might get somebody else's. That's IDOR — broken
object-level authorisation — and it's one of the most common serious bugs on the
web, because the check that should say "is this yours?" is easy to forget on one
endpoint out of two hundred.

The usual way to test it is to swap the number and look at the status code. That
approach produces two kinds of wrong answer. A `200` that returns an empty
object isn't a bug. A `403` for an id that doesn't exist isn't proof the check
works. Status codes describe the response, not who was allowed to see what.

Auto-IDOR tests it differently. You give it two real accounts. It logs in as
both, asks each of them for objects belonging to the other, and compares what
comes back against what each user legitimately sees. A finding means **user A
received user B's data** — the actual content, confirmed — rather than "an
endpoint returned 200."

## Why you'd use it

- **Findings are provable.** Each one is a comparison between two identities, so
  the report writes itself and a triager can reproduce it.
- **Fewer false positives**, because it never infers authorisation from a status
  code.
- **Checks the anonymous case too** — sometimes the endpoint needs no session at
  all.
- **Takes a raw Burp request**, so you can test the exact call you just watched
  the app make.
- **Tries encodings and method changes**, catching checks that are enforced on
  `GET` but not `PUT`, or bypassed by a URL-encoded id.

## Install

```bash
git clone https://github.com/CypherNova1337/Auto-IDOR
cd Auto-IDOR
pip install -r requirements.txt
pip install .
```

Needs Python 3.8 or newer.

## Usage

Start with two accounts and one endpoint:

```bash
auto-idor quick \
  -u 'https://app.example/api/invoices/{id}' \
  --token-a "$USER_A_JWT" --token-b "$USER_B_JWT" \
  --owns-a 1041,1042 --owns-b 2001,2002
```

`{id}` is the slot it swaps. `--owns-a` and `--owns-b` say which ids each user
legitimately owns, which is what lets it tell a real crossover from a normal
response.

**Test a request you captured in Burp**

```bash
auto-idor quick -r request.txt --mark 1042 \
  --cookie-a 'session=aaa' --cookie-b 'session=bbb'
```

`--mark` is the value in the saved request to treat as the id.

**Find the injectable ids in a request first**

```bash
auto-idor detect -r request.txt
```

**Run a full scan across many endpoints**

```bash
auto-idor init > scan.yaml   # write a config to start from
auto-idor run -c scan.yaml -o findings/
```

**Send it through Burp**

```bash
auto-idor run -c scan.yaml --proxy http://127.0.0.1:8080
```

## Commands

| Command | What it's for |
|---|---|
| `quick` | Ad-hoc test of one endpoint with two identities |
| `run` | Full scan driven by a config file |
| `detect` | Find id-shaped values in a raw request worth testing |
| `init` | Write an example config to start from |

### Common options

| Flag | Default | What it does |
|---|---|---|
| `-u` | — | Target URL containing `{id}` |
| `-r` | — | Raw HTTP request file (`-` for stdin) |
| `--mark` | — | Value in the raw request to use as the id slot |
| `--token-a` / `--token-b` | — | Bearer token per identity |
| `--cookie-a` / `--cookie-b` | — | Cookies per identity (repeatable) |
| `-H` / `--header-b` | — | Extra headers per identity (repeatable) |
| `--owns-a` / `--owns-b` | — | Ids each user legitimately owns |
| `--secret-a` / `--secret-b` | — | A string only that user should ever see |
| `--encodings` | — | Encoding variants to try on the id |
| `--method-tamper` | — | Also retry with other HTTP methods |
| `--no-anonymous` | off | Skip the unauthenticated baseline |
| `--threads` | `8` | Concurrent workers |
| `--delay` | `0` | Seconds between requests per worker |
| `--proxy` | — | Proxy URL, e.g. Burp |
| `--all` | off | Keep going instead of stopping at the first hit |
| `-o` | — | Output directory |

## Good to know

- **`--secret-a` / `--secret-b` make it much sharper.** Give it a string only
  that user should ever see — a name, an email, an account number — and a
  crossover becomes unambiguous rather than inferred.
- **Two accounts are required.** With one identity there's nothing to compare
  against, and you're back to guessing from status codes.
- **It writes as well as reads.** With `--method-tamper` it will try `PUT` and
  `DELETE`. Don't point that at production data you care about.
- **Sequential ids aren't the only kind.** UUIDs can be just as vulnerable if
  the check is missing — you just need to know a valid one, which is what
  `--owns-b` is for.

## Authorised use

Only against applications you own or that are in scope for an engagement or
bounty programme. This tool deliberately accesses one account's data using
another's session; doing that without permission is unauthorised access, not
testing.

## License

MIT — see [LICENSE](LICENSE).
