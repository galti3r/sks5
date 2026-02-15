# VHS demo tape for sks5 — https://github.com/charmbracelet/vhs
#
# Usage:
#   vhs contrib/demo.tape
#
# Prerequisites:
#   - sks5 binary in PATH or target/release/sks5
#
Output contrib/demo.gif

Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1100
Set Height 550
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 50ms

# ── Start sks5 demo (pre-populated with users, ACLs, quotas) ──────
Type "# Start sks5 with pre-populated demo data"
Enter
Sleep 500ms
Type "sks5 demo --password demo &"
Enter
Sleep 3s

# ── SSH Shell ───────────────────────────────────────────────────
Type "# Connect via SSH"
Enter
Sleep 500ms
Type "ssh -o StrictHostKeyChecking=no -p 2222 alice@localhost"
Enter
Sleep 2s
Type "demo"
Enter
Sleep 1s

Type "show status"
Enter
Sleep 1.5s

Type "show acl"
Enter
Sleep 1.5s

# ── Quota display with pre-populated usage ──────────────────────
Type "show quota"
Enter
Sleep 2s

# ── ACL enforcement ────────────────────────────────────────────
Type "# Test ACL rules"
Enter
Sleep 500ms
Type "test example.com:443"
Enter
Sleep 1s

Type "test blocked.internal:22"
Enter
Sleep 1s

# ── Bookmarks ──────────────────────────────────────────────────
Type "bookmark add web example.com:443"
Enter
Sleep 1s

Type "bookmark list"
Enter
Sleep 1s

Type "show connections"
Enter
Sleep 1s

Type "exit"
Enter
Sleep 1s

# ── SOCKS5 Proxy ──────────────────────────────────────────────
Type "# Use as a SOCKS5 proxy"
Enter
Sleep 500ms
Type "curl -x socks5h://alice:demo@localhost:1080 http://example.com -sS -o /dev/null -w '%{http_code}\n'"
Enter
Sleep 3s

# ── REST API ─────────────────────────────────────────────────
Type "# Query the REST API"
Enter
Sleep 500ms
Type "curl -sS http://localhost:9091/api/status -H 'Authorization: Bearer demo' | jq ."
Enter
Sleep 2s

# ── Health Check ──────────────────────────────────────────────
Type "# Built-in health check"
Enter
Sleep 500ms
Type "sks5 health-check --addr 127.0.0.1:2222 --timeout 5"
Enter
Sleep 2s

# ── Cleanup ───────────────────────────────────────────────────
Type "kill %1 2>/dev/null"
Enter
Sleep 500ms
