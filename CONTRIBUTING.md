# Contributing to WAFFLE

First of all,, respect for wanting to contribute to a parental control tool
built by a teenager trying to be better. That's genuinely cool! thanks you!

## The Rules (non-negotiable)

### 1. Don't lie to the codebase
- No fake benchmarks.
- No "this is faster" without proof.
- No "I fixed a bug" when you actually introduced three.

The code has to actually do what you say it does.

### 2. Commits must be beneficial
Ask yourself: *does this make WAFFLE better?*
Not just "different". Not just "my style".
- Fixing bugs ✅
- Adding features ✅
- Renaming variables for no reason ❌

### 3. Branch workflow — always
DO NOT TOUCH the main branch. it is a sacred piece. create a different branch then push your commits there. Name should show what it's doing. i.e.
- `fix-my-fix` <- push your fix
- `add-my-feature` <- push your awesome feature
- `optimize-some-thing` <- found a better optimization than mine? push it!


### 4. Pull Request checklist
- [ ] running `cargo test --all-target` returns success
- [ ] building the binary and testing is optional but encouraged.

### 5. What will NOT be accepted
- Breaking changes without a very good reason
- Anything that weakens the blocking (the whole point is to block haram sites)
- Unnecessary dependencies (we like zero-dep where possible)
- AI-generated slop that wasn't reviewed by a human brain. *(Using AI for generating code is not encouraged. speeding up your workflow or using AI to optimize your **own code** is allowed. and AI generated code **MUST** be reviewed with proper checks even if it hallucinates "it will 100% work, trust me".)*

## What would actually be great to have
- macOS proxy support improvements
- KDE / XFCE proxy setting support
- Browser extension companion 
- More graceful handling of edge-case URLs

> *WAFFLE was built with a specific intention. Keep that spirit intact.*
