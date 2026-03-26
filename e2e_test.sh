#!/bin/bash
# End-to-end test for gitbox CLI
# This test creates a git repo, generates keys, and runs through the full workflow.
set -euo pipefail

GITBOX="$(cd "$(dirname "$0")" && pwd)/gitbox"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== GitBox End-to-End Test ==="
echo "Working directory: $WORKDIR"
echo ""

# Set up a fake git repo
cd "$WORKDIR"
git init -q
git config user.email "test@test.com"
git config user.name "Test"

# Generate test SSH keys (Ed25519 and RSA)
mkdir -p "$WORKDIR/.ssh"
ssh-keygen -t ed25519 -f "$WORKDIR/.ssh/id_ed25519" -N "" -q
ssh-keygen -t rsa -b 2048 -f "$WORKDIR/.ssh/id_rsa" -N "" -q

echo "--- Step 1: Init ---"
$GITBOX init
test -d .gitbox
test -f .gitbox/config.yaml
echo "PASS: init"

echo ""
echo "--- Step 2: Add users (using add-key) ---"
# Alice is first (bootstrap -- self-signs with her own key)
$GITBOX add-key alice "$WORKDIR/.ssh/id_ed25519.pub" -k "$WORKDIR/.ssh/id_ed25519"
# Bob is signed by alice
$GITBOX add-key bob "$WORKDIR/.ssh/id_rsa.pub" -k "$WORKDIR/.ssh/id_ed25519"
echo "PASS: created test identities"

echo ""
echo "--- Step 3: List users ---"
$GITBOX list-users
echo "PASS: list-users"

echo ""
echo "--- Step 4: Encrypt a secret ---"
echo "DATABASE_URL=postgres://prod:supersecret@db.example.com:5432/app" > secrets.env
echo "API_KEY=sk-live-abc123def456" >> secrets.env
$GITBOX encrypt secrets.env -n prod-secrets -r alice
test -f .gitbox/secrets/prod-secrets.yaml
echo "PASS: encrypt"

echo ""
echo "--- Step 5: List secrets ---"
$GITBOX list
echo "PASS: list"

echo ""
echo "--- Step 6: Decrypt with Ed25519 key ---"
DECRYPTED=$($GITBOX decrypt prod-secrets -k "$WORKDIR/.ssh/id_ed25519" --stdout)
ORIGINAL=$(cat secrets.env)
if [ "$DECRYPTED" = "$ORIGINAL" ]; then
    echo "PASS: decrypt with ed25519 - content matches"
else
    echo "FAIL: decrypt content mismatch"
    echo "Expected: $ORIGINAL"
    echo "Got: $DECRYPTED"
    exit 1
fi

echo ""
echo "--- Step 7: Decrypt to file ---"
$GITBOX decrypt prod-secrets -k "$WORKDIR/.ssh/id_ed25519" -o "$WORKDIR/decrypted.env"
diff secrets.env "$WORKDIR/decrypted.env" > /dev/null
echo "PASS: decrypt to file"

echo ""
echo "--- Step 8: Grant access to bob ---"
$GITBOX grant prod-secrets bob -k "$WORKDIR/.ssh/id_ed25519"
echo "PASS: grant"

echo ""
echo "--- Step 9: Bob can now decrypt with RSA key ---"
BOB_DECRYPTED=$($GITBOX decrypt prod-secrets -k "$WORKDIR/.ssh/id_rsa" --stdout)
if [ "$BOB_DECRYPTED" = "$ORIGINAL" ]; then
    echo "PASS: bob decrypt with rsa - content matches"
else
    echo "FAIL: bob decrypt content mismatch"
    exit 1
fi

echo ""
echo "--- Step 10: Revoke bob's access ---"
$GITBOX revoke prod-secrets bob -k "$WORKDIR/.ssh/id_ed25519"
echo "PASS: revoke"

echo ""
echo "--- Step 11: Bob can no longer decrypt ---"
if $GITBOX decrypt prod-secrets -k "$WORKDIR/.ssh/id_rsa" --stdout 2>/dev/null; then
    echo "FAIL: bob should not be able to decrypt after revoke"
    exit 1
else
    echo "PASS: bob correctly denied after revoke"
fi

echo ""
echo "--- Step 12: Alice can still decrypt after revoke ---"
ALICE_AFTER=$($GITBOX decrypt prod-secrets -k "$WORKDIR/.ssh/id_ed25519" --stdout)
if [ "$ALICE_AFTER" = "$ORIGINAL" ]; then
    echo "PASS: alice can still decrypt after revoking bob"
else
    echo "FAIL: alice lost access after revoking bob"
    exit 1
fi

echo ""
echo "--- Step 13: Paper key ---"
# Generate paper key (signed by alice's key)
$GITBOX paper-key generate -k "$WORKDIR/.ssh/id_ed25519"
test -d .gitbox/paperkeys && test "$(ls .gitbox/paperkeys/*.yaml 2>/dev/null | wc -l)" -gt 0
echo "PASS: paper key generated"

echo ""
echo "--- Step 14: Encrypt new secret with paper key auto-included ---"
echo "STRIPE_KEY=sk_live_xyz" > payment.env
$GITBOX encrypt payment.env -n payment-secrets -r alice
# Verify the paper key recipient is in the manifest
if grep -q "__paper_key__:" .gitbox/secrets/payment-secrets.yaml; then
    echo "PASS: paper key auto-included as recipient"
else
    echo "FAIL: paper key not auto-included"
    exit 1
fi

echo ""
echo "--- Step 15: Install hook ---"
$GITBOX install-hook
test -f .git/hooks/pre-commit
test -x .git/hooks/pre-commit
echo "PASS: hook installed"

echo ""
echo "--- Step 16: Verify encrypted files are safe to commit ---"
git add .gitbox/
git commit -q -m "add encrypted secrets"
echo "PASS: encrypted files committed successfully"

echo ""
echo "--- Step 17: Multiple secrets ---"
echo "REDIS_URL=redis://cache:6379" > cache.env
$GITBOX encrypt cache.env -n cache-config -r alice,bob
CACHE_DECRYPTED=$($GITBOX decrypt cache-config -k "$WORKDIR/.ssh/id_ed25519" --stdout)
if [ "$CACHE_DECRYPTED" = "$(cat cache.env)" ]; then
    echo "PASS: multi-recipient encrypt/decrypt"
else
    echo "FAIL: multi-recipient mismatch"
    exit 1
fi

echo ""
echo "--- Step 18: Version ---"
$GITBOX version
echo "PASS: version"

echo ""
echo "=== ALL TESTS PASSED ==="
