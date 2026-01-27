---
name: windows-powershell-safety
description: Guidelines for running commands safely on Windows PowerShell, specifically prohibiting '&&' chaining.
---

# Windows PowerShell Safety

You are running in a Windows PowerShell environment where the `&&` operator is NOT supported or unreliable.

## Critical Rules

1.  **NEVER use `&&` to chain commands.**
    *   ❌ **BAD:** `git add . && git commit -m "msg"`
    *   ✅ **GOOD:** Run them as **separate** `run_command` calls.
    *   *Reason:* The user's shell throws `The token '&&' is not a valid statement separator`.

2.  **Separate Git Workflows**
    *   Do not combine git steps.
    *   **Call 1:** `git add .`
    *   **Call 2:** `git commit -m "message"`
    *   **Call 3:** `git push`

3.  **Error Handling**
    *   Running commands separately allows you to catch errors at each step.
    *   If `git commit` fails (e.g. "nothing to commit"), `git push` will not run, preventing confusion.

## When to use
This rule applies **ALWAYS** when the Operating System is **Windows**.
