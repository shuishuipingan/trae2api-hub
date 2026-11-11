#!/usr/bin/env bash
# ===========================================================
#  Allow Trae2API-Hub through the host firewall (LAN mode).
#  Linux / macOS counterpart of allow-firewall.bat.
#
#  Run this ONCE with sudo if other devices cannot connect:
#      sudo ./allow-firewall.sh [port]      (default port: 8791)
#
#  It detects which firewall is in charge (ufw / firewalld /
#  nftables / iptables) and opens just the one TCP port.
# ===========================================================
set -u

PORT="${1:-8791}"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] root is required to change firewall rules."
    echo "        re-run as:  sudo $0 $PORT"
    exit 1
fi

# WSL2 note: the rule below only opens the Linux side. Windows Firewall
# still filters traffic from the LAN, and WSL's NAT needs a portproxy.
wsl=""
if [ -r /proc/version ] && grep -qi "microsoft" /proc/version 2>/dev/null; then
    wsl="yes"
fi

echo "Opening TCP port $PORT for Trae2API-Hub ..."
echo

done_any=""

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; then
    ufw allow "$PORT"/tcp
    done_any="ufw"
    echo
    echo "Added with ufw. To remove it later:"
    echo "  sudo ufw delete allow $PORT/tcp"

elif command -v firewall-cmd >/dev/null 2>&1 \
     && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$PORT"/tcp
    firewall-cmd --reload
    done_any="firewalld"
    echo
    echo "Added with firewalld. To remove it later:"
    echo "  sudo firewall-cmd --permanent --remove-port=$PORT/tcp && sudo firewall-cmd --reload"

# The chain must already exist: "nft list ruleset" succeeds on an empty
# ruleset (common on Ubuntu, where ufw is merely inactive), and adding a
# rule to a non-existent chain would fail with a cryptic error.
elif command -v nft >/dev/null 2>&1 \
     && nft list chain inet filter input >/dev/null 2>&1; then
    nft add rule inet filter input tcp dport "$PORT" accept
    done_any="nftables"
    echo
    echo "Added with nftables (not persistent across reboot). To remove it later:"
    echo "  sudo nft -a list chain inet filter input   # find the handle"
    echo "  sudo nft delete rule inet filter input handle <handle>"

elif command -v iptables >/dev/null 2>&1; then
    # -C keeps this idempotent: a second run must not stack duplicate rules.
    if iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; then
        echo "Rule already present - nothing to do."
    else
        iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
    fi
    done_any="iptables"
    echo
    echo "Added with iptables (not persistent across reboot). To remove it later:"
    echo "  sudo iptables -D INPUT -p tcp --dport $PORT -j ACCEPT"
else
    echo "[NOTE] No active firewall manager was detected (ufw / firewalld /"
    echo "       nftables / iptables). Your machine may already allow the port."
fi

echo

if [ -n "$wsl" ]; then
    cat <<EOF
Detected WSL. Two extra steps are needed on the Windows side:

  1) Windows Firewall - run in an ADMIN PowerShell:
       New-NetFirewallRule -DisplayName "Trae2API-Hub (TCP $PORT)" \`
         -Direction Inbound -Action Allow -Protocol TCP -LocalPort $PORT

  2) Forward the port from Windows to WSL - in an ADMIN cmd/PowerShell:
       netsh interface portproxy add v4tov4 listenport=$PORT \`
         listenaddress=0.0.0.0 connectport=$PORT connectaddress=<WSL-IP>
     (find <WSL-IP> by running this in WSL:  ip -4 addr show eth0)

     To undo:
       netsh interface portproxy delete v4tov4 listenport=$PORT listenaddress=0.0.0.0
       Remove-NetFirewallRule -DisplayName "Trae2API-Hub (TCP $PORT)"

EOF
fi

if [ -n "$done_any" ]; then
    echo "Done. Other devices on the network should now reach:"
    echo "  http://<this-machine-ip>:$PORT/"
    echo
    echo "(If the rule is still not enough, also check that the router/AP"
    echo " does not isolate clients from each other.)"
else
    echo "Nothing was changed."
fi
