#!/usr/bin/env bash
# e2e smoke test for rosec using secret-tool (libsecret CLI).
#
# Exercises:
#   - Provider discovery (verifies write target matches daemon config)
#   - store -> lookup -> search -> update (replace) -> clear -> verify gone
#   - rosec:provider attribute: items stamped with their provider ID
#   - Provider-scoped search via rosec:provider filter
#
# Requires:
#   - secret-tool (libsecret CLI)
#   - rosec CLI (in PATH, or at ./target/debug/rosec, or set ROSEC=)
#   - A running rosecd with an unlocked write-capable local provider
#
# Usage:
#   ./tests/e2e-secret-tool.sh
#   ROSEC=/path/to/rosec ./tests/e2e-secret-tool.sh

set -euo pipefail

# ── Locate rosec CLI ─────────────────────────────────────────────────
ROSEC="${ROSEC:-}"
if [[ -z "$ROSEC" ]]; then
    if command -v rosec &>/dev/null; then
        ROSEC=rosec
    elif [[ -x ./target/debug/rosec ]]; then
        ROSEC=./target/debug/rosec
    elif [[ -x ./target/release/rosec ]]; then
        ROSEC=./target/release/rosec
    else
        printf "ERROR: cannot find rosec binary. Set ROSEC= or build first.\n" >&2
        exit 1
    fi
fi

# ── Test namespace ───────────────────────────────────────────────────
NS="rosec-test"
ATTR_KEY="rosec_test_id"
ATTR_VAL="e2e-$$"  # PID-scoped to avoid collisions across parallel runs

pass=0
fail=0

pass() { ((pass++)); printf "  \033[32mPASS\033[0m %s\n" "$1"; }
fail() { ((fail++)); printf "  \033[31mFAIL\033[0m %s\n" "$1"; }

cleanup() {
    # Best-effort removal of test items.
    secret-tool clear "$ATTR_KEY" "$ATTR_VAL" 2>/dev/null || true
}
trap cleanup EXIT

printf "=== rosec e2e: secret-tool ===\n"
printf "rosec binary: %s\n" "$ROSEC"
printf "attribute: %s=%s\n\n" "$ATTR_KEY" "$ATTR_VAL"

# ── 0. Provider discovery ───────────────────────────────────────────
# Determine which provider will receive writes. The daemon resolves
# write_provider from config (service.write_provider explicit setting,
# or first provider with Capability::Write). Only kind=local providers
# have Capability::Write, so we identify the expected write target from
# `rosec status` and later verify items land there via rosec:provider.

printf "[discovery] identifying write-capable provider...\n"

status_out=$("$ROSEC" status 2>&1) || {
    printf "ERROR: rosec status failed:\n%s\n" "$status_out" >&2
    exit 1
}

# Parse provider lines from status output.
# Format: "  Name (id)  [kind, state]"
# We need the first local (write-capable) provider's ID.
# Regex stored in variable — bash [[ =~ ]] quoting is fragile otherwise.
provider_re='[(]([^)]+)[)][[:space:]]+\[([^,]+), ([^]]+)\]'

expected_provider=""
while IFS= read -r line; do
    if [[ "$line" =~ $provider_re ]]; then
        p_id="${BASH_REMATCH[1]}"
        p_kind="${BASH_REMATCH[2]}"
        p_state="${BASH_REMATCH[3]}"
        if [[ "$p_kind" == "local" && -z "$expected_provider" ]]; then
            expected_provider="$p_id"
            printf "  write provider: %s (kind=%s, state=%s)\n" "$p_id" "$p_kind" "$p_state"
        fi
    fi
done <<< "$status_out"

if [[ -z "$expected_provider" ]]; then
    printf "ERROR: no local (write-capable) provider found in rosec status:\n%s\n" "$status_out" >&2
    exit 1
fi

# Check provider lock state. If locked, secret-tool will trigger the
# Secret Service Prompt() flow which spawns rosec's GUI prompt dialog —
# the same path any real application would take. No manual unlock needed.
state_re="[(]${expected_provider}[)][[:space:]]+\[[^,]+, ([^]]+)\]"
while IFS= read -r line; do
    if [[ "$line" =~ $state_re ]]; then
        if [[ "${BASH_REMATCH[1]}" == "locked" ]]; then
            printf "  provider '%s' is locked; secret-tool will trigger GUI prompt\n" "$expected_provider"
        else
            printf "  provider '%s' is already unlocked\n" "$expected_provider"
        fi
    fi
done <<< "$status_out"

pass "discovered write provider: $expected_provider"

# ── 1. Store ─────────────────────────────────────────────────────────
printf "\n[store] creating test item...\n"
printf "hunter2" | secret-tool store \
    --label="$NS test item" \
    "$ATTR_KEY" "$ATTR_VAL" \
    type login \
    username "testuser@example.com"

got=$(secret-tool lookup "$ATTR_KEY" "$ATTR_VAL" 2>/dev/null || true)
if [[ "$got" == "hunter2" ]]; then
    pass "store + lookup"
else
    fail "store + lookup: expected 'hunter2', got '$got'"
fi

# ── 2. Verify provider routing ──────────────────────────────────────
# The stored item should have rosec:provider=$expected_provider.
# secret-tool search reads D-Bus Attributes — rosec:provider is public.
# rosec search --format=kv also shows it.

printf "\n[provider-routing] verifying item landed in '%s'...\n" "$expected_provider"

# 2a. Via secret-tool search — rosec:provider is in public Attributes.
search_out=$(secret-tool search --all "$ATTR_KEY" "$ATTR_VAL" 2>&1 || true)
if printf "%s" "$search_out" | grep -q "rosec:provider = ${expected_provider}"; then
    pass "secret-tool sees rosec:provider=$expected_provider"
else
    # Some libsecret versions may format differently; not a hard failure.
    printf "  (secret-tool did not show rosec:provider; checking via rosec)\n"
fi

# 2b. Via rosec search — definitive check.
rosec_kv=$("$ROSEC" search --format=kv "$ATTR_KEY"="$ATTR_VAL" 2>&1 || true)
if printf "%s" "$rosec_kv" | grep -q "rosec:provider=${expected_provider}"; then
    pass "rosec search confirms rosec:provider=$expected_provider"
else
    fail "provider routing: expected rosec:provider=$expected_provider in:\n$rosec_kv"
fi

# ── 3. Provider-scoped search ───────────────────────────────────────
# Search using rosec:provider as a filter — should find our test item.
printf "\n[provider-search] filtering by rosec:provider...\n"

provider_search=$("$ROSEC" search --format=kv "rosec:provider=${expected_provider}" "$ATTR_KEY"="$ATTR_VAL" 2>&1 || true)
if printf "%s" "$provider_search" | grep -q "$ATTR_KEY=$ATTR_VAL"; then
    pass "provider-scoped search finds item"
else
    fail "provider-scoped search: expected item in:\n$provider_search"
fi

# Negative test: non-existent provider should return nothing.
bogus_search=$("$ROSEC" search --format=kv "rosec:provider=nonexistent" "$ATTR_KEY"="$ATTR_VAL" 2>&1 || true)
if printf "%s" "$bogus_search" | grep -q "$ATTR_KEY=$ATTR_VAL"; then
    fail "bogus provider search should NOT find item"
else
    pass "bogus provider search correctly returns nothing"
fi

# ── 4. Attribute search ─────────────────────────────────────────────
printf "\n[search] standard attribute search...\n"
search_out=$(secret-tool search --all "$ATTR_KEY" "$ATTR_VAL" 2>&1 || true)
if printf "%s" "$search_out" | grep -q "label = $NS test item"; then
    pass "search finds item by label"
else
    fail "search: expected label in output, got: $search_out"
fi

if printf "%s" "$search_out" | grep -q "username = testuser@example.com"; then
    pass "search shows username attribute"
else
    fail "search: expected username attribute, got: $search_out"
fi

# ── 5. Update (store with same attrs replaces) ──────────────────────
printf "\n[update] replacing secret value...\n"
printf "correcthorsebatterystaple" | secret-tool store \
    --label="$NS test item (updated)" \
    "$ATTR_KEY" "$ATTR_VAL" \
    type login \
    username "testuser@example.com"

got=$(secret-tool lookup "$ATTR_KEY" "$ATTR_VAL" 2>/dev/null || true)
if [[ "$got" == "correcthorsebatterystaple" ]]; then
    pass "update replaces secret"
else
    fail "update: expected 'correcthorsebatterystaple', got '$got'"
fi

# Verify label was updated too.
search_out=$(secret-tool search --all "$ATTR_KEY" "$ATTR_VAL" 2>&1 || true)
if printf "%s" "$search_out" | grep -q "updated"; then
    pass "update changes label"
else
    fail "update: expected updated label, got: $search_out"
fi

# Verify updated item still routes to the same provider.
rosec_kv=$("$ROSEC" search --format=kv "$ATTR_KEY"="$ATTR_VAL" 2>&1 || true)
if printf "%s" "$rosec_kv" | grep -q "rosec:provider=${expected_provider}"; then
    pass "updated item still in provider $expected_provider"
else
    fail "updated item: expected rosec:provider=$expected_provider in:\n$rosec_kv"
fi

# ── 6. Clear (delete) ───────────────────────────────────────────────
printf "\n[clear] deleting test item...\n"
secret-tool clear "$ATTR_KEY" "$ATTR_VAL"

got=$(secret-tool lookup "$ATTR_KEY" "$ATTR_VAL" 2>/dev/null || true)
if [[ -z "$got" ]]; then
    pass "clear removes item"
else
    fail "clear: expected empty lookup, got '$got'"
fi

# Verify item is gone from rosec search too.
rosec_kv=$("$ROSEC" search --format=kv "$ATTR_KEY"="$ATTR_VAL" 2>&1 || true)
if [[ -z "$rosec_kv" ]]; then
    pass "item gone from rosec search"
else
    fail "clear: item still visible in rosec search:\n$rosec_kv"
fi

# ── Summary ──────────────────────────────────────────────────────────
printf "\n=== %d passed, %d failed ===\n" "$pass" "$fail"
[[ "$fail" -eq 0 ]]
