# 🧇 WAFFLE
### Web Access Filter & Firewall for Local Environments

> *A proxy-based site blocker that actually shows you a block page instead of pretending the internet is broken.*

Built by a teenager who got tired of his own bad habits and decided to write code about it instead.
Tested on Firefox. Chrome is being difficult. We don't talk about Chrome.



## Does it work?

**It works.**

If it doesn't — speak it out loud. Say "WAFFLE please work" three times.
If that still doesn't work, open an issue.



## Chrome Notice 🚨

Look, Chrome isn't being a good girl. I mean if you can set the proxies into chrome somehow, it should work.
I tested with `google-chrome-stable --proxy="http://127.0.0.1:8080/` it doesnt work ok?
I tested with Firefox. It works perfectly on Firefox.

Any browser works — just set your proxy to `127.0.0.1:8080` and reload WAFFLE after installation. That's literally it. Stop using Chrome anyway.



## What is this

WAFFLE is a local HTTP/HTTPS proxy that:
- Blocks websites you tell it to block
- Shows a proper **block page** instead of a cryptic connection error
- Does SSL interception so HTTPS sites get the block page too (not just "not secure")
- Runs as a background daemon
- Lives at `~/.config/waffle/`
- Asks zero cloud services for permission

It's basically a bouncer for your browser. Except the bouncer is a Python script and the club is the internet.



## Installation

### Option A — Download the binary (just works, no Python needed)

Grab the latest release for your platform from the [Releases page](../../releases).

**Linux:**
```bash
chmod +x waffle
sudo mv waffle /usr/local/bin/waffle
bash setup.sh
```

**Windows:**
```bat
:: Run as Administrator
setup.bat
```

**macOS:**
```bash
chmod +x waffle
sudo mv waffle /usr/local/bin/waffle
bash setup.sh
```



### Option B — Clone the repo (for people who like reading code)

```bash
git clone https://github.com/AstroJr0/waffle.git
cd waffle

# Linux / macOS
bash setup.sh

# Windows
setup.bat
```

The setup script handles everything — CA generation, Chrome NSS install, certutil, the works.



## Usage

```bash
waffle --activate                    # start the daemon
waffle --deactivate                  # stop it
waffle --status                      # is it running? how many sites blocked?
waffle --toggle                      # flip it on/off

waffle -a example.com                # block a site (https:// added automatically)
waffle -a https://example.com        # same thing
waffle -r example.com                # unblock it
waffle --list                        # see everything you've blocked

waffle --reload                      # restart daemon after config changes
```


## First-time SSL setup (do this once)

Without this, blocked HTTPS sites show "not secure" instead of the block page.
Do it. It takes 30 seconds.

```bash
waffle --generate-ca     # creates your local CA cert
waffle --install-ca      # installs it into Chrome/Firefox NSS + system store
waffle --check-ca        # make sure it actually worked

# Close your browser fully, then reopen it
waffle --activate
```

---

## How it works

WAFFLE runs a proxy on `127.0.0.1:8080`.

- **HTTP sites** — intercepted, checked against blocklist, either blocked (403 + block page) or forwarded
- **HTTPS sites** — CONNECT tunnel intercepted, SSL bumped using a locally-trusted CA cert, block page served over real TLS if blocked, otherwise passed through transparently

Blocking is prefix-based. Block `example.com` and every path under it is blocked too.
Both `http://` and `https://` are always checked regardless of what you typed when adding.



## Config

Blocklist lives at `~/.config/waffle/waffle.conf`. One URL per line.

```
https://example.com
https://time-wasting-site.com
# comments work too
```


## Building from source

```bash
pip install pyinstaller cryptography
python3 -m PyInstaller --onefile --name waffle --strip waffle.py
# binary at dist/waffle
```

Or push a tag and let GitHub Actions build it:
```bash
git tag v1.4.0
git push origin v1.4.0
# Actions tab → Build WAFFLE Binaries → Run workflow
```



## License

Free for everyone. If you're making money off it, credit **AstroJr0**.
No warranty. See [LICENSE](LICENSE).



## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first.
TL;DR: real fixes only, branch workflow, don't lie to the codebase.



*made with intention. alhamdulillah.*
