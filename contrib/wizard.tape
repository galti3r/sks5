# VHS tape for sks5 wizard — https://github.com/charmbracelet/vhs
#
# Usage:
#   vhs contrib/wizard.tape
#
# Prerequisites:
#   - sks5 binary in PATH or target/release/sks5
#
Output contrib/wizard.gif

Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 50ms

# ── Title ─────────────────────────────────────────────────────────
Type "# sks5 wizard — interactive configuration generator"
Enter
Sleep 1s

# ── Non-interactive mode (generates config with defaults) ────────
Type "# Generate a config with sensible defaults"
Enter
Sleep 500ms
Type "sks5 wizard --non-interactive --output /tmp/wizard-demo.toml"
Enter
Sleep 3s

# ── Show the generated config ────────────────────────────────────
Type "# Inspect the generated configuration"
Enter
Sleep 500ms
Type "head -40 /tmp/wizard-demo.toml"
Enter
Sleep 3s

# ── Validate the config ──────────────────────────────────────────
Type "# Validate the configuration"
Enter
Sleep 500ms
Type "sks5 check-config --config /tmp/wizard-demo.toml"
Enter
Sleep 2s

# ── Interactive wizard (show menu) ───────────────────────────────
Type "# Launch the interactive wizard (14 sections)"
Enter
Sleep 500ms
Type "sks5 wizard"
Enter
Sleep 2s

# Navigate the menu: select Server section
Enter
Sleep 1.5s

# Accept all defaults in Server section (press Enter for each prompt)
Enter
Sleep 500ms
Enter
Sleep 500ms
Enter
Sleep 500ms
Enter
Sleep 500ms

# Navigate to Users section
Down
Enter
Sleep 1.5s

# Add a user — answer prompts
Type "alice"
Enter
Sleep 500ms
Type "secret123"
Enter
Sleep 500ms
Type "secret123"
Enter
Sleep 500ms

# Accept defaults for remaining user prompts
Enter
Sleep 500ms
Enter
Sleep 500ms
Enter
Sleep 500ms

# Back to main menu — go to Save & Exit
Sleep 500ms

# Navigate down to "Save & Exit" (it's the last item, index 14)
# Use multiple Down presses to reach it
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
Sleep 2s

# ── Cleanup ──────────────────────────────────────────────────────
Type "rm -f /tmp/wizard-demo.toml"
Enter
Sleep 500ms
