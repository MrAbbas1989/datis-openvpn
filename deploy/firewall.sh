#!/usr/bin/env bash
set -Eeuo pipefail
source /etc/datisvpn/firewall.env
[[ "$WAN_IF" =~ ^[A-Za-z0-9_.:-]+$ && "$VPN_PORT" =~ ^[0-9]+$ && "$VPN_PROTO" =~ ^(tcp|udp)$ ]] || exit 1
add() { local table=$1; shift; iptables -w -t "$table" -C "$@" 2>/dev/null || iptables -w -t "$table" -I "$@"; }
del() { local table=$1; shift; if iptables -w -t "$table" -C "$@" 2>/dev/null; then iptables -w -t "$table" -D "$@"; fi; }
if [[ "${1:-}" == start ]]; then
  add filter INPUT -i "$WAN_IF" -p "$VPN_PROTO" --dport "$VPN_PORT" -m comment --comment datisvpn -j ACCEPT
  add filter FORWARD -i tun-datis -o "$WAN_IF" -s 10.87.0.0/24 -m comment --comment datisvpn -j ACCEPT
  add filter FORWARD -i "$WAN_IF" -o tun-datis -d 10.87.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment datisvpn -j ACCEPT
  add nat POSTROUTING -s 10.87.0.0/24 -o "$WAN_IF" -m comment --comment datisvpn -j MASQUERADE
  # VPN clients must not reach services on the VPN host or one another.
  add filter INPUT -i tun-datis -m comment --comment datisvpn -j DROP
  add filter FORWARD -i tun-datis -o tun-datis -m comment --comment datisvpn -j DROP
  # Block routed private/link-local targets including cloud metadata.
  for subnet in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 127.0.0.0/8; do
    add filter FORWARD -i tun-datis -d "$subnet" -m comment --comment datisvpn -j DROP
  done
  ip6tables -w -C FORWARD -i tun-datis -m comment --comment datisvpn -j DROP 2>/dev/null || ip6tables -w -I FORWARD -i tun-datis -m comment --comment datisvpn -j DROP
  ip6tables -w -C INPUT -i tun-datis -m comment --comment datisvpn -j DROP 2>/dev/null || ip6tables -w -I INPUT -i tun-datis -m comment --comment datisvpn -j DROP
elif [[ "${1:-}" == stop ]]; then
  del filter INPUT -i "$WAN_IF" -p "$VPN_PROTO" --dport "$VPN_PORT" -m comment --comment datisvpn -j ACCEPT
  del filter FORWARD -i tun-datis -o "$WAN_IF" -s 10.87.0.0/24 -m comment --comment datisvpn -j ACCEPT
  del filter FORWARD -i "$WAN_IF" -o tun-datis -d 10.87.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment datisvpn -j ACCEPT
  del nat POSTROUTING -s 10.87.0.0/24 -o "$WAN_IF" -m comment --comment datisvpn -j MASQUERADE
  del filter INPUT -i tun-datis -m comment --comment datisvpn -j DROP
  del filter FORWARD -i tun-datis -o tun-datis -m comment --comment datisvpn -j DROP
  for subnet in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 127.0.0.0/8; do
    del filter FORWARD -i tun-datis -d "$subnet" -m comment --comment datisvpn -j DROP
  done
  for chain in INPUT FORWARD; do
    if ip6tables -w -C "$chain" -i tun-datis -m comment --comment datisvpn -j DROP 2>/dev/null; then
      ip6tables -w -D "$chain" -i tun-datis -m comment --comment datisvpn -j DROP
    fi
  done
else
  echo 'Expected start or stop' >&2; exit 1
fi
