# Under Construction ⚒️ 

Probable comparison table:
| Checks | v1 | v2 |
| --- | --- | ---|
| Codebase | Python | Rust |
| problems | doesn't work on chrome | it will be fixed |
| speed | fast | very FAST |
| simplicity | everything in one simple file | might be divided for better understanding |
| UI Support | CLI Only | QML Based UI through `qt_bridge` crate |

# 🧇 Waffle

> A minimal, self-sovereign proxy filter built out of practical necessity.

[![Host](https://img.shields.io/badge/Hosted_on-Codeberg-blue?logo=codeberg)](https://codeberg.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)


## Philosophy

Waffle wasn't built to follow dev trends. It was built because I needed a lightweight,, direct way to break my bad digital habits, block distractions, and regain focus over my own environment. 

It started as a raw Python based proxy server engineered to solve a personal friction point. It worked so well in my daily workflow that it became a core tool worth maintaining, evolving, and protecting. 


##  Features

- **Direct Site & Domain Filtering:** Intercepts unwanted connections cleanly before they hit your browser.
- **Zero Telemetry:** Designed strictly for localized control with no tracking or external reporting. It stays inside your own machine, its detached from outside world.
- **Lightweight Footprint:** Low resource overhead, running silently in the background as a simple service.
- **Custom Rule Control:** Easy configuration setup to block, allow, or redirect host targets.

## Why is it different and how it works

Every other site blocker uses same old tactic. so i took a different approch. The system *(aka waffle)* starts a proxy server inside your system. Then, it installs appropriate certificates inside your daily drive browsers so they can trust **waffle**. 

When you add your own local address *(mostly 127.0.0.1)* waffle starts listening to sites. When it founds a blocked site, it blocks them *obviously*. I tried to reduce the latency, and became pseudo-realtime.
