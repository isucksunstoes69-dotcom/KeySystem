#!/usr/bin/env bash
# Admin helper for the license server. Set BASE and TOKEN, then run a command.
#
#   ./admin.sh create MyMod "Buyer Name" buyer@email.com 0      # 0 days = perpetual
#   ./admin.sh list
#   ./admin.sh revoke  ABCDE-FGHIJ-KLMNO-PQRST
#   ./admin.sh rebind  ABCDE-FGHIJ-KLMNO-PQRST                  # clear bound HWID (move to new PC)

BASE="${LICENSE_BASE:-http://127.0.0.1:8080}"
TOKEN="${LICENSE_ADMIN_TOKEN:?set LICENSE_ADMIN_TOKEN to your server admin token}"

cmd="$1"; shift
case "$cmd" in
  create)
    product="$1"; owner="$2"; email="$3"; days="${4:-0}"
    curl -s -X POST -H "X-Admin-Token: $TOKEN" \
      --data-urlencode "product=$product" \
      --data-urlencode "owner=$owner" \
      --data-urlencode "email=$email" \
      --data-urlencode "days=$days" \
      "$BASE/api/admin/create"
    ;;
  list)
    curl -s -H "X-Admin-Token: $TOKEN" "$BASE/api/admin/list"
    ;;
  revoke)
    curl -s -X POST -H "X-Admin-Token: $TOKEN" --data-urlencode "licenseKey=$1" "$BASE/api/admin/revoke"
    ;;
  rebind)
    curl -s -X POST -H "X-Admin-Token: $TOKEN" --data-urlencode "licenseKey=$1" "$BASE/api/admin/rebind"
    ;;
  reseller-create)
    curl -s -X POST -H "X-Admin-Token: $TOKEN" --data-urlencode "name=$1" "$BASE/api/admin/reseller/create"
    ;;
  reseller-list)
    curl -s -H "X-Admin-Token: $TOKEN" "$BASE/api/admin/reseller/list"
    ;;
  ban)
    # ban <user|hwid|ip> <value> [reason]
    curl -s -X POST -H "X-Admin-Token: $TOKEN" \
      --data-urlencode "type=$1" --data-urlencode "value=$2" --data-urlencode "reason=$3" "$BASE/api/admin/ban"
    ;;
  unban)
    curl -s -X POST -H "X-Admin-Token: $TOKEN" \
      --data-urlencode "type=$1" --data-urlencode "value=$2" "$BASE/api/admin/unban"
    ;;
  bans)
    curl -s -H "X-Admin-Token: $TOKEN" "$BASE/api/admin/bans"
    ;;
  *)
    echo "usage: $0 {create <product> <owner> <email> [days] | list | revoke <key> | rebind <key>"
    echo "          | reseller-create <name> | reseller-list"
    echo "          | ban <user|hwid|ip> <value> [reason] | unban <type> <value> | bans}"
    exit 1
    ;;
esac
echo
