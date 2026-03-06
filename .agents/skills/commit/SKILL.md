---
name: commit
description: Write a git commit message and verify formatting before committing.
---

# Generate a Git Commit

When creating a commit for a patch:

- Run `bash tools/format.sh` if formatting has not been run since the last edits.
- Most files should have a copyright, save files like gold files and .json files which don't take comments.
- Run `bash tools/copyright_update.sh` after the final edits to update copyrights. With no argument it updates currently changed files; with a commit argument it updates the files touched by that commit.
- Verify every changed or new file that carries a copyright header uses the current year before committing.
- Write a short one-line summary (target: under ~60 characters).
- Add a concise body (1-3 short paragraphs) focused on why the change is needed and how it resolves the issue.
- Wrap all commit message lines at 72 characters or less.
- Use real newlines in the commit body; never embed literal `\n` sequences.
- Prefer writing the message to a temporary file or heredoc and passing it via `git commit -F <file>` to preserve wrapping.
- Keep implementation detail high-level; the patch contains exact code changes.
- If applicable, end with: `Fixes: #<issue_number>`.

Do not push unless explicitly asked.
