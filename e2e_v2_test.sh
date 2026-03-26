#!/bin/bash
# End-to-end test for gitbox v2 features: manual keys, groups, refresh, apply/export
set -euo pipefail

GITBOX="$(cd "$(dirname "$0")" && pwd)/gitbox"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== GitBox V2 Features E2E Test ==="
echo "Working directory: $WORKDIR"
echo ""

cd "$WORKDIR"
git init -q
git config user.email "test@test.com"
git config user.name "Test"

# Generate test keys
ssh-keygen -t ed25519 -f "$WORKDIR/alice_key" -N "" -q
ssh-keygen -t rsa -b 2048 -f "$WORKDIR/bob_key" -N "" -q
ssh-keygen -t ed25519 -f "$WORKDIR/charlie_key" -N "" -q
ssh-keygen -t ed25519 -f "$WORKDIR/diana_key" -N "" -q

$GITBOX init > /dev/null

# ================================================================
echo "--- Test 1: Manual key add (bootstrap - self-signed) ---"
$GITBOX add-key alice "$WORKDIR/alice_key.pub" -k "$WORKDIR/alice_key"
echo "PASS: add-key from file (bootstrap)"

echo ""
echo "--- Test 2: Manual key add (signed by alice) ---"
$GITBOX add-key bob "$(cat "$WORKDIR/bob_key.pub")" -k "$WORKDIR/alice_key"
echo "PASS: add-key inline (signed)"

echo ""
echo "--- Test 3: Add second key to existing user ---"
ssh-keygen -t rsa -b 2048 -f "$WORKDIR/alice_key2" -N "" -q
$GITBOX add-key alice "$WORKDIR/alice_key2.pub" -k "$WORKDIR/alice_key"
echo "PASS: add additional key to existing user"

echo ""
echo "--- Test 4: Add users charlie and diana (signed by alice) ---"
$GITBOX add-key charlie "$WORKDIR/charlie_key.pub" -k "$WORKDIR/alice_key"
$GITBOX add-key diana "$WORKDIR/diana_key.pub" -k "$WORKDIR/alice_key"
echo "PASS: added charlie and diana"

echo ""
echo "--- Test 5: List users shows all ---"
OUTPUT=$($GITBOX list-users)
echo "$OUTPUT"
for user in alice bob charlie diana; do
    if echo "$OUTPUT" | grep -q "$user"; then
        true
    else
        echo "FAIL: missing user $user"
        exit 1
    fi
done
echo "PASS: all users listed"

# ================================================================
echo ""
echo "--- Test 6: Create groups (signed by alice) ---"
$GITBOX group create backend alice,bob -k "$WORKDIR/alice_key"
$GITBOX group create frontend charlie,diana -k "$WORKDIR/alice_key"
echo "PASS: created groups"

echo ""
echo "--- Test 7: List groups ---"
$GITBOX group list
echo "PASS: list groups"

echo ""
echo "--- Test 8: Add user to group ---"
$GITBOX group add backend charlie -k "$WORKDIR/alice_key"
OUTPUT=$($GITBOX group list)
if echo "$OUTPUT" | grep -q "backend" && echo "$OUTPUT" | grep -q "charlie"; then
    echo "PASS: added user to group"
else
    echo "FAIL: charlie not in backend group"
    exit 1
fi

echo ""
echo "--- Test 9: Remove user from group ---"
$GITBOX group remove backend charlie -k "$WORKDIR/alice_key"
echo "PASS: removed user from group"

# ================================================================
echo ""
echo "--- Test 10: Encrypt with @group recipients ---"
echo "DB_PASSWORD=hunter2" > secrets.env
$GITBOX encrypt secrets.env -n db-secret -r @backend
OUTPUT=$($GITBOX list)
echo "$OUTPUT"
if echo "$OUTPUT" | grep -q "alice" && echo "$OUTPUT" | grep -q "bob"; then
    echo "PASS: @group resolved to alice,bob"
else
    echo "FAIL: group resolution"
    exit 1
fi

echo ""
echo "--- Test 11: Decrypt with alice's key ---"
DECRYPTED=$($GITBOX decrypt db-secret -k "$WORKDIR/alice_key")
if [ "$DECRYPTED" = "DB_PASSWORD=hunter2" ]; then
    echo "PASS: alice can decrypt group secret"
else
    echo "FAIL: alice decrypt mismatch: $DECRYPTED"
    exit 1
fi

echo ""
echo "--- Test 12: Decrypt with bob's key ---"
DECRYPTED=$($GITBOX decrypt db-secret -k "$WORKDIR/bob_key")
if [ "$DECRYPTED" = "DB_PASSWORD=hunter2" ]; then
    echo "PASS: bob can decrypt group secret"
else
    echo "FAIL: bob decrypt mismatch"
    exit 1
fi

echo ""
echo "--- Test 13: Mix groups and users in recipients ---"
echo "STRIPE_KEY=sk_live_abc" > stripe.env
$GITBOX encrypt stripe.env -n stripe-secret -r @frontend,alice
OUTPUT=$($GITBOX list)
echo "$OUTPUT"
# Should have alice, charlie, diana
RECIPIENTS=$($GITBOX list | grep stripe-secret)
for user in alice charlie diana; do
    if echo "$RECIPIENTS" | grep -q "$user"; then
        true
    else
        echo "FAIL: missing $user in stripe-secret recipients"
        exit 1
    fi
done
echo "PASS: mixed group + user recipients"

# ================================================================
echo ""
echo "--- Test 14: Export config ---"
$GITBOX export
$GITBOX export > "$WORKDIR/exported.yaml"
if grep -q "db-secret" "$WORKDIR/exported.yaml" && grep -q "stripe-secret" "$WORKDIR/exported.yaml"; then
    echo "PASS: export contains secrets"
else
    echo "FAIL: export missing secrets"
    exit 1
fi
if grep -q "backend" "$WORKDIR/exported.yaml"; then
    echo "PASS: export contains groups"
else
    echo "FAIL: export missing groups"
    exit 1
fi

echo ""
echo "--- Test 15: Apply config (converge state) ---"
# Create a new gitbox.yaml that adds diana to db-secret
cat > "$WORKDIR/apply-test.yaml" << 'YAML'
groups:
  backend:
    - alice
    - bob
  frontend:
    - charlie
    - diana

secrets:
  db-secret:
    recipients:
      - "@backend"
      - diana
  stripe-secret:
    recipients:
      - "@frontend"
      - alice
YAML

$GITBOX apply "$WORKDIR/apply-test.yaml" -k "$WORKDIR/alice_key"
echo ""

# Verify diana now has access to db-secret
DIANA_DECRYPTED=$($GITBOX decrypt db-secret -k "$WORKDIR/diana_key")
if [ "$DIANA_DECRYPTED" = "DB_PASSWORD=hunter2" ]; then
    echo "PASS: apply granted diana access to db-secret"
else
    echo "FAIL: diana can't decrypt after apply"
    exit 1
fi

echo ""
echo "--- Test 16: Apply config creates new secret from file ---"
echo "NEW_SECRET=xyz789" > "$WORKDIR/newsecret.txt"
cat > "$WORKDIR/apply-new.yaml" << YAML
secrets:
  db-secret:
    recipients:
      - alice
      - bob
      - diana
  stripe-secret:
    recipients:
      - charlie
      - diana
      - alice
  new-secret:
    file: "$WORKDIR/newsecret.txt"
    recipients:
      - alice
      - charlie
YAML

$GITBOX apply "$WORKDIR/apply-new.yaml" -k "$WORKDIR/alice_key"
echo ""

NEW_DECRYPTED=$($GITBOX decrypt new-secret -k "$WORKDIR/alice_key")
if [ "$NEW_DECRYPTED" = "NEW_SECRET=xyz789" ]; then
    echo "PASS: apply created new secret from file"
else
    echo "FAIL: new secret content mismatch: $NEW_DECRYPTED"
    exit 1
fi

echo ""
echo "--- Test 17: Group delete ---"
$GITBOX group delete frontend -k "$WORKDIR/alice_key"
OUTPUT=$($GITBOX group list)
if echo "$OUTPUT" | grep -q "frontend"; then
    echo "FAIL: frontend group should be deleted"
    exit 1
else
    echo "PASS: group deleted"
fi

echo ""
echo "--- Test 18: Nested groups ---"
$GITBOX group create frontend charlie,diana -k "$WORKDIR/alice_key"
$GITBOX group create all-devs "@backend,@frontend" -k "$WORKDIR/alice_key"
echo "Encrypt with @all-devs..."
echo "GLOBAL_SECRET=allhands" > global.env
$GITBOX encrypt global.env -n global-secret -r @all-devs
RECIPIENTS=$($GITBOX list | grep global-secret)
for user in alice bob charlie diana; do
    if echo "$RECIPIENTS" | grep -q "$user"; then
        true
    else
        echo "FAIL: missing $user in @all-devs"
        exit 1
    fi
done
echo "PASS: nested groups resolved correctly"

# Verify everyone can decrypt
for user in alice bob charlie diana; do
    RESULT=$($GITBOX decrypt global-secret -k "$WORKDIR/${user}_key")
    if [ "$RESULT" = "GLOBAL_SECRET=allhands" ]; then
        true
    else
        echo "FAIL: $user can't decrypt global-secret"
        exit 1
    fi
done
echo "PASS: all members of nested group can decrypt"

echo ""
echo "=== ALL V2 TESTS PASSED ==="
