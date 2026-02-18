# VHS tape for sks5 interactive wizard — https://github.com/charmbracelet/vhs
#
# Usage:
#   vhs contrib/wizard-interactive.tape
#
# Prerequisites:
#   - sks5 binary in PATH or target/release/sks5
#
# Demonstrates the full interactive TUI wizard:
#   1. Configure Server (listen addresses)
#   2. Add a user (alice) with password auth
#   3. Save & Exit
#   4. Validate the generated config
#
Output contrib/wizard-interactive.gif

Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1100
Set Height 700
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 50ms
Set WaitTimeout 10s

# ── Title ─────────────────────────────────────────────────────────
Type "# sks5 interactive wizard — step-by-step configuration"
Enter
Sleep 1s

# ── Launch the interactive wizard ─────────────────────────────────
Type "sks5 wizard --output /tmp/wizard-interactive.toml"
Enter
Wait+Screen@10s /Select a section to configure/
Sleep 1s

# ── 1. Configure Server ──────────────────────────────────────────
# Server is already selected (default index 0)
Enter
Wait+Screen@5s /Server.*configure/
Sleep 500ms

# Select "Listen addresses" (index 0, already default)
Enter
Wait@5s /SSH listen address/
Sleep 500ms

# Accept default SSH listen (0.0.0.0:2222)
Enter
Wait@5s /SOCKS5/
Sleep 500ms

# Accept SOCKS5 enabled (default yes)
Enter
Wait@5s /SOCKS5 listen/
Sleep 500ms

# Accept default SOCKS5 listen (0.0.0.0:1080)
Enter
Wait@5s /SSH banner/
Sleep 500ms

# Accept default banner
Enter
Wait+Screen@5s /Server.*configure/
Sleep 500ms

# Back to main menu (index 5 in Server submenu)
# From index 0, press Down 5 times to reach "Back to main menu"
Down
Down
Down
Down
Down
Enter
Wait+Screen@5s /Select a section to configure/
Sleep 1s

# ── 2. Configure Users ───────────────────────────────────────────
# Navigate to Users (index 1)
Down
Enter
Wait+Screen@5s /Users.*select to edit or add/
Sleep 500ms

# "+ Add new user" is default (index 0 when no users exist)
Enter
Wait@5s /Username/
Sleep 300ms

# Enter username
Type "alice"
Enter
Wait+Screen@5s /Authentication method/
Sleep 300ms

# Select Password (index 0, already default)
Enter
Wait@5s /Password/
Sleep 300ms

# Enter password
Type "s3cret!Pass"
Enter
Wait@5s /Confirm/
Sleep 300ms

# Confirm password
Type "s3cret!Pass"
Enter
Wait@5s /Allow shell/
Sleep 300ms

# Accept "Allow shell access?" (default yes)
Enter
Wait@5s /Configure advanced/
Sleep 300ms

# Decline advanced options (default no)
Enter
Wait+Screen@5s /Users.*select to edit or add/
Sleep 1s

# Back to main menu: alice is at index 0, "+ Add new user" at 1 (default), "Back" at 2
# From default position (1), press Down once to reach "Back"
Down
Enter
Wait+Screen@5s /Select a section to configure/
Sleep 1s

# ── 3. Save & Exit ───────────────────────────────────────────────
# Navigate down to "Save & Exit" (last item, index 14)
# Currently at index 0, press Down 14 times
Down
Down
Down
Down
Down
Down
Down
Down
Down
Down
Down
Down
Down
Down
Enter
Wait@10s />/
Sleep 1s

# ── 4. Validate the generated config ─────────────────────────────
Type "# Validate the generated configuration"
Enter
Sleep 500ms
Type "sks5 -c /tmp/wizard-interactive.toml check-config"
Enter
Wait@5s />/
Sleep 1s

# ── 5. Show the config ───────────────────────────────────────────
Type "# Inspect the generated config"
Enter
Sleep 500ms
Type "head -50 /tmp/wizard-interactive.toml"
Enter
Wait@5s />/
Sleep 2s

# ── Cleanup ──────────────────────────────────────────────────────
Type "rm -f /tmp/wizard-interactive.toml"
Enter
Sleep 500ms
