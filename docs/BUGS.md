# sks5 - Bug Tracker

## Process

1. **Report**: Add a new entry below using the template
2. **Triage**: Assign severity and priority
3. **Fix**: Link the fix commit and regression test
4. **Verify**: Confirm the fix in CI; move status to Fixed

## Severity Guide

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | System down, data loss, security breach | Immediate |
| High | Major feature broken, no workaround | Same day |
| Medium | Feature impaired, workaround exists | This sprint |
| Low | Minor issue, cosmetic | Backlog |

## Status Flow

```
Open --> In Progress --> Fixed --> Verified --> Closed
                    \-> Won't Fix
                    \-> Cannot Reproduce
```

---

## Template

Copy this template when adding a new bug:

```markdown
## [BUG-XXX] Short description

### Metadata
- **Status**: Open | In Progress | Fixed | Won't Fix | Cannot Reproduce
- **Severity**: Critical | High | Medium | Low
- **Priority**: P0 | P1 | P2 | P3
- **Discovered**: YYYY-MM-DD
- **Fixed**: YYYY-MM-DD (if applicable)
- **Discovered by**: (agent/user)
- **Fixed by**: (agent/user)

### Environment
- OS:
- Rust version:
- sks5 version/commit:

### Description
Detailed description of the bug.

### Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

### Expected Behavior
What should happen.

### Actual Behavior
What actually happens.

### Root Cause
(When identified) Explanation of why this bug occurs.

### Fix
(When resolved) Description of the fix applied.

### Related
- **Tests added**: `path/to/test_file.rs`
- **Commits**: `abc1234`
- **Related bugs**: BUG-YYY

### Regression Prevention
How we ensure this does not happen again.
```

---

## Known Bugs

No known bugs.
