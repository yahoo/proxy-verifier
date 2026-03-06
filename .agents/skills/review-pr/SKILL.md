---
name: review-pr
description: Review the current GitHub PR with gh and report findings without modifying the PR.
---

# Review a PR

Using `gh`, review the current PR and report findings.

Focus areas:

- Expensive pass-by-copy where reference or pointer is preferable.
- Opportunities to use modern C++ features appropriately.
- Opportunities to use `lib/swoc` APIs (for example `TextView`).
- Resource leaks or lifetime bugs.
- Duplicated code and maintainability concerns.
- Any domain-specific correctness or behavior regressions.

Do not modify the PR or post comments unless explicitly asked.
