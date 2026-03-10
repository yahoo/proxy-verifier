---
name: create-pr
description: Create a GitHub pull request from the current branch using the latest commit message for title/body, assign to the current user, and return the PR link.
---

# Create PR

This assumes that the ../commit/SKILL.md commit skill has been used and a
commit is created. When asked to create a PR for the current branch:

1. Never create a PR from `master`.
2. If `master` is currently checked out, create a development branch first.
3. Prefer branching from `origin/master` before doing work. If the change is
   already committed on local `master`, create the new branch at the current
   `HEAD` so the commit stays attached to the development branch.
4. Choose a short descriptive branch name based on the change, such as
   `fix-create-pr-skill` or `add-on-connect-feature`. Do not use a slash in
   the branch name.
5. Use the latest commit message subject as the PR title.
6. Use the latest commit message body as the PR description.
7. Push the current branch to `origin` first if it is not already pushed.
8. Derive the `--head` owner from the `origin` remote, not
   `git config user.name`.
9. Assign the PR to yourself (`--assignee @me`).
10. Return a clickable PR link.

## Commands

```bash
branch=$(git branch --show-current)
if [ "$branch" = "master" ]; then
  git fetch origin master
  branch="fix-create-pr-skill"
  git switch -c "$branch"
fi

subj=$(git log -1 --pretty=%s)
body=$(git log -1 --pretty=%b)
origin_url=$(git remote get-url origin)
head_owner=$(printf '%s\n' "$origin_url" | sed -E \
  's#(git@github.com:|https://github.com/)##; s#\\.git$##; s#/.*##')

git push -u origin "$branch"

gh pr create \
  --base master \
  --head "${head_owner}:${branch}" \
  --title "$subj" \
  --body "$body" \
  --assignee @me
```
