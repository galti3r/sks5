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
Set WaitTimeout 10s

# ── Start sks5 demo (pre-populated with users, ACLs, quotas) ──────
Type "# Start sks5 with pre-populated demo data"
Enter
Sleep 500ms
Type "sks5 demo --password demo >/tmp/sks5.log 2>&1 &"
Enter
Sleep 3s

# ── SSH Shell ───────────────────────────────────────────────────
Type "# Connect via SSH"
Enter
Sleep 500ms
Type "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 alice@localhost"
Enter
Wait@15s /password/
Type "demo"
Enter
Wait@10s /alice@sks5/
Sleep 500ms

Type "show status"
Enter
Wait@5s /alice@sks5/
Sleep 1s

Type "show acl"
Enter
Wait@5s /alice@sks5/
Sleep 1s

# ── Quota display with pre-populated usage ──────────────────────
Type "show quota"
Enter
Wait@5s /alice@sks5/
Sleep 1.5s

# ── ACL enforcement ────────────────────────────────────────────
Type "# Test ACL rules"
Enter
Sleep 500ms
Type "test example.com:443"
Enter
Wait@5s /alice@sks5/
Sleep 500ms

Type "test blocked.internal:22"
Enter
Wait@5s /alice@sks5/
Sleep 500ms

# ── Bookmarks ──────────────────────────────────────────────────
Type "bookmark add web example.com:443"
Enter
Wait@5s /alice@sks5/
Sleep 500ms

Type "bookmark list"
Enter
Wait@5s /alice@sks5/
Sleep 500ms

Type "show connections"
Enter
Wait@5s /alice@sks5/
Sleep 500ms

Type "exit"
Enter
Wait@5s />/
Sleep 500ms

# ── SOCKS5 Proxy ──────────────────────────────────────────────
Type "# Use as a SOCKS5 proxy"
Enter
Sleep 500ms
Type "curl -x socks5h://alice:demo@localhost:1080 http://example.com -sS -o /dev/null -w '%{http_code}\n'"
Enter
Wait@10s />/
Sleep 1s

# ── REST API ─────────────────────────────────────────────────
Type "# Query the REST API"
Enter
Sleep 500ms
Type "curl -sS http://localhost:9091/api/status -H 'Authorization: Bearer demo' | jq ."
Enter
Wait@10s />/
Sleep 1s

# ── Health Check ──────────────────────────────────────────────
Type "# Built-in health check"
Enter
Sleep 500ms
Type "sks5 health-check --addr 127.0.0.1:2222 --timeout 5"
Enter
Wait@10s />/
Sleep 1s

# ── Cleanup ───────────────────────────────────────────────────
Type "kill %1 2>/dev/null"
Enter
Sleep 500ms
