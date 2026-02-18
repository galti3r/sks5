# VHS tape for sks5 wizard (non-interactive) — https://github.com/charmbracelet/vhs
#
# Usage:
#   vhs contrib/wizard.tape
#
# Prerequisites:
#   - sks5 binary in PATH or target/release/sks5
#
# See also: wizard-interactive.tape for the full interactive wizard demo
#
Output contrib/wizard.gif

Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 50ms
Set WaitTimeout 10s

# ── Title ─────────────────────────────────────────────────────────
Type "# sks5 wizard — configuration generator"
Enter
Sleep 1s

# ── Non-interactive mode (generates config with defaults) ────────
Type "# Generate a config with sensible defaults"
Enter
Sleep 500ms
Type "sks5 wizard --non-interactive --output /tmp/wizard-demo.toml"
Enter
Wait+Screen@15s /Configuration written/
Sleep 1s

# ── Show the generated config ────────────────────────────────────
Type "# Inspect the generated configuration"
Enter
Sleep 500ms
Type "head -40 /tmp/wizard-demo.toml"
Enter
Wait@5s />/
Sleep 2s

# ── Validate the config ──────────────────────────────────────────
Type "# Validate the configuration"
Enter
Sleep 500ms
Type "sks5 -c /tmp/wizard-demo.toml check-config"
Enter
Wait@5s />/
Sleep 1.5s

# ── Cleanup ──────────────────────────────────────────────────────
Type "rm -f /tmp/wizard-demo.toml"
Enter
Sleep 500ms
