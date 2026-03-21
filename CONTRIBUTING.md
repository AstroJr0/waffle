# Contributing to WAFFLE

First of all — respect for wanting to contribute to a parental control tool
built by a teenager trying to be better. That's genuinely cool.

---

## The Rules (non-negotiable)

### 1. Don't lie to the codebase
No fake benchmarks. No "this is faster" without proof.
No "I fixed a bug" when you actually introduced three.
The code has to actually do what you say it does.

### 2. Commits must be beneficial
Ask yourself: *does this make WAFFLE better?*
Not just "different". Not just "my style". **Better.**
Fixing bugs ✅ — Adding features ✅ — Renaming variables for no reason ❌

### 3. Branch workflow — always
```
main        ← stable, protected, nobody touches this directly
dev         ← general development base
feature/your-feature-name   ← your branch
fix/what-youre-fixing        ← your branch
```

Open a Pull Request into `dev`. If it's good, it gets merged into `main`.
Direct pushes to `main` will be rejected and judged silently.

### 4. Pull Request checklist
Before opening a PR, make sure:
- [ ] `python3 -m py_compile waffle.py` passes with zero errors
- [ ] You tested it — actually ran it, not just "it looks right"
- [ ] Your commit messages are descriptive (`fix ssl bump on arch` not `fix stuff`)
- [ ] You didn't accidentally commit your `ca.key` or any personal files

### 5. What will NOT be accepted
- Breaking changes without a very good reason
- Windows-only or Linux-only code with no cross-platform fallback
- Anything that weakens the blocking (the whole point is to block things)
- Unnecessary dependencies (we like zero-dep where possible)
- AI-generated slop that wasn't reviewed by a human brain

---

## What would actually be great to have
- macOS proxy support improvements
- KDE / XFCE proxy setting support
- A proper test suite
- Browser extension companion
- Better block page designs
- More graceful handling of edge-case URLs

---

## How to set up for development

```bash
git clone https://github.com/AstroJr0/waffle.git
cd waffle
git checkout -b feature/your-feature-name

# make your changes
python3 -m py_compile waffle.py   # syntax check
python3 waffle.py --help          # smoke test

# commit and push
git add .
git commit -m "your descriptive message"
git push origin feature/your-feature-name
# then open a PR on GitHub
```

---

*WAFFLE was built with a specific intention. Keep that spirit intact.*