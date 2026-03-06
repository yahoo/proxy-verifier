---
name: create-pr
description: Create a GitHub pull request from the current branch using the latest commit message for title/body, assign to the current user, and return the PR link.
---

# Create PR

This assumes that the ../commit/SKILL.md commit skill has been used and a
commit is created. When asked to create a PR for the current branch:

1. Use the latest commit message subject as the PR title.
2. Use the latest commit message body as the PR description.
3. Assign the PR to yourself (`--assignee @me`).
6. Return a clickable PR link.

## Commands

```bash
subj=$(git log -1 --pretty=%s)
body=$(git log -1 --pretty=%b)
gh pr create \
  --base master \
  --head "$(git config user.name | tr '[:upper:]' '[:lower:]')":"$(git branch --show-current)" \
  --title "$subj" \
  --body "$body" \
  --assignee @me \
  --milestone "11.0.0"
```
