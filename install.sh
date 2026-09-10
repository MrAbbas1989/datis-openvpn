#!/usr/bin/env bash
# Fresh, single-server installation. Never sources or executes a third-party installer.
set -Eeuo pipefail
umask 077
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENDPOINT=''; PORT=1194; PROTOCOL=udp; DOMAIN=''; EMAIL=''
usage() { echo "Usage: sudo bash install.sh --endpoint IP_OR_HOST [--port 1194] [--protocol udp|tcp] [--domain panel.example.com --email admin@example.com]"; }
while (($#)); do
  case "$1" in
    --endpoint) ENDPOINT="${2:?Missing endpoint}"; shift 2;;
    --port) PORT="${2:?Missing port}"; shift 2;;
    --protocol) PROTOCOL="${2:?Missing protocol}"; shift 2;;
    --domain) DOMAIN="${2:?Missing domain}"; shift 2;;
    --email) EMAIL="${2:?Missing email}"; shift 2;;
    --help|-h) usage; exit 0;;
    *) usage; exit 1;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'Run as root using sudo.'; exit 1; }
[[ -t 0 ]] || { echo 'Use an interactive terminal (admin password prompt).'; exit 1; }
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 22.04 ]] || { echo 'This installer targets Ubuntu 22.04 only.'; exit 1; }
[[ -c /dev/net/tun ]] || { echo 'TUN device is required.'; exit 1; }
[[ "$ENDPOINT" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || { echo 'Provide a public IPv4 address or DNS hostname with --endpoint.'; exit 1; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && ((10#$PORT >= 1 && 10#$PORT <= 65535)) || { echo 'Invalid port'; exit 1; }
PORT=$((10#$PORT))
[[ "$PROTOCOL" == udp || "$PROTOCOL" == tcp ]] || { echo 'Protocol must be udp or tcp'; exit 1; }
if [[ -n "$DOMAIN" ]]; then
  [[ "$DOMAIN" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,251}\.[A-Za-z]{2,63}$ && "$EMAIL" =~ ^[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]] || { echo 'Valid domain and email required for HTTPS.'; exit 1; }
  [[ "$PROTOCOL" != tcp || ( "$PORT" != 80 && "$PORT" != 443 ) ]] || { echo 'HTTPS needs TCP ports 80 and 443.'; exit 1; }
  [[ ! -d /etc/nginx/sites-enabled ]] || { echo 'Existing Nginx detected. Install without --domain and configure your reverse proxy manually.'; exit 1; }
fi
[[ ! -e /opt/datisvpn && ! -e /etc/datisvpn && ! -e /var/lib/datisvpn ]] || { echo 'Existing/partial Datis installation detected. See docs/OPERATIONS.md; nothing overwritten.'; exit 1; }
if compgen -G '/etc/openvpn/*.conf' >/dev/null || compgen -G '/etc/openvpn/server/*.conf' >/dev/null; then
  echo 'Existing OpenVPN detected. Use a fresh VPS; automatic migration is not supported.'; exit 1
fi
if command -v ufw >/dev/null && ufw status | head -1 | grep -qx 'Status: active'; then
  echo 'Active UFW detected. This installer requires a fresh VPS; see firewall notes.'; exit 1
fi
if ss -H -lntu | awk '{print $5}' | grep -Eq ":(8080|${PORT})$"; then
  echo 'VPN port or local panel port 8080 is already in use.'; exit 1
fi
WAN_IF="$(ip -4 route show default | awk 'NR==1 {print $5}')"
[[ "$WAN_IF" =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo 'No valid default IPv4 interface'; exit 1; }
if ip -4 route show | grep -q '^10\.87\.0\.0/24'; then
  echo 'VPN subnet 10.87.0.0/24 is already routed.'; exit 1
fi
[[ -f "$ROOT_DIR/datis/web.py" && -f "$ROOT_DIR/requirements.txt" ]] || { echo 'Extract/clone the complete repository first.'; exit 1; }
trap 'echo "Installation stopped at line $LINENO. No pre-existing service was intentionally modified. Inspect /opt/datisvpn and /etc/datisvpn before retrying; see docs/OPERATIONS.md." >&2' ERR
apt-get update
apt-get install -y openvpn easy-rsa python3-venv python3-pip iptables ca-certificates openssl
id datisvpn >/dev/null 2>&1 || useradd --system --home /var/lib/datisvpn --shell /usr/sbin/nologin datisvpn
install -d -m 0755 /opt/datisvpn
install -d -m 0750 -o root -g datisvpn /etc/datisvpn
install -d -m 0700 -o datisvpn -g datisvpn /var/lib/datisvpn
cp -R "$ROOT_DIR/datis" /opt/datisvpn/
cp "$ROOT_DIR/requirements.txt" /opt/datisvpn/
chown -R root:root /opt/datisvpn
chmod -R u=rwX,go=rX /opt/datisvpn
python3 -m venv /opt/datisvpn/venv
/opt/datisvpn/venv/bin/pip install --disable-pip-version-check -r /opt/datisvpn/requirements.txt
install -d -m 0700 /etc/datisvpn/easy-rsa
cp -R /usr/share/easy-rsa/. /etc/datisvpn/easy-rsa/
(
  cd /etc/datisvpn/easy-rsa
  export EASYRSA_BATCH=1 EASYRSA_REQ_CN=DatisVPN-CA EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1 EASYRSA_CERT_EXPIRE=825
  ./easyrsa init-pki
  ./easyrsa build-ca nopass
  ./easyrsa build-server-full datis-server nopass
)
openvpn --genkey secret /etc/datisvpn/tls-crypt.key
install -m 0644 /etc/datisvpn/easy-rsa/pki/ca.crt /etc/datisvpn/ca.crt
install -m 0644 /etc/datisvpn/easy-rsa/pki/issued/datis-server.crt /etc/datisvpn/server.crt
install -m 0600 /etc/datisvpn/easy-rsa/pki/private/datis-server.key /etc/datisvpn/server.key
SERVER_PROTO=udp; CLIENT_PROTO=udp
if [[ "$PROTOCOL" == tcp ]]; then SERVER_PROTO=tcp-server; CLIENT_PROTO=tcp-client; fi
cat > /etc/datisvpn/openvpn.conf <<CONF
port $PORT
proto $SERVER_PROTO
dev tun-datis
dev-type tun
topology subnet
server 10.87.0.0 255.255.255.0
server-ipv6 fd42:d47:15::/64
ca /etc/datisvpn/ca.crt
cert /etc/datisvpn/server.crt
key /etc/datisvpn/server.key
dh none
ecdh-curve prime256v1
tls-crypt /etc/datisvpn/tls-crypt.key
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
verify-client-cert none
username-as-common-name
duplicate-cn
management /run/datisvpn/management.sock unix
management-client-user datisvpn
management-client-group datisvpn
management-client-auth
management-hold
management-signal
management-forget-disconnect
push "redirect-gateway def1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
push "route-ipv6 2000::/3"
push "block-ipv6"
keepalive 10 60
reneg-sec 3600
persist-key
persist-tun
user nobody
group nogroup
verb 3
CONF
# OpenVPN 2.6 DCO is deliberately disabled until its accounting path is integration-tested.
if openvpn --help | grep -q -- '--disable-dco'; then echo 'disable-dco' >> /etc/datisvpn/openvpn.conf; fi
{
cat <<CONF
client
dev tun
proto $CLIENT_PROTO
remote $ENDPOINT $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name datis-server name
tls-version-min 1.2
auth-user-pass
auth-nocache
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verb 3
<ca>
CONF
cat /etc/datisvpn/ca.crt
echo '</ca>'
echo '<tls-crypt>'
cat /etc/datisvpn/tls-crypt.key
echo '</tls-crypt>'
} > /etc/datisvpn/client.ovpn
chown root:datisvpn /etc/datisvpn/client.ovpn
chmod 0640 /etc/datisvpn/client.ovpn
SECRET="$(openssl rand -hex 32)"
SECURE_COOKIE=0
[[ -z "$DOMAIN" ]] || SECURE_COOKIE=1
cat > /etc/datisvpn/panel.env <<CONF
DATIS_SECRET=$SECRET
DATIS_DB=/var/lib/datisvpn/panel.db
DATIS_MANAGEMENT=/run/datisvpn/management.sock
DATIS_PROFILE=/etc/datisvpn/client.ovpn
DATIS_SECURE_COOKIE=$SECURE_COOKIE
CONF
unset SECRET
chown root:datisvpn /etc/datisvpn/panel.env
chmod 0640 /etc/datisvpn/panel.env
cat > /etc/datisvpn/firewall.env <<CONF
WAN_IF=$WAN_IF
VPN_PORT=$PORT
VPN_PROTO=$PROTOCOL
CONF
install -m 0755 "$ROOT_DIR/deploy/firewall.sh" /opt/datisvpn/firewall.sh
install -m 0644 "$ROOT_DIR/deploy/"*.service /etc/systemd/system/
cat > /etc/tmpfiles.d/datisvpn.conf <<'CONF'
d /run/datisvpn 0750 datisvpn datisvpn -
CONF
systemd-tmpfiles --create /etc/tmpfiles.d/datisvpn.conf
cat > /etc/sysctl.d/90-datisvpn.conf <<'CONF'
net.ipv4.ip_forward = 1
CONF
sysctl -p /etc/sysctl.d/90-datisvpn.conf
cat > /usr/local/bin/datisvpn <<'CONF'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Use sudo datisvpn ...'; exit 1; }
cd /opt/datisvpn
exec runuser -u datisvpn -- /opt/datisvpn/venv/bin/python -m datis.cli "$@"
CONF
chmod 0755 /usr/local/bin/datisvpn
# Administrator secrets are entered via getpass, never command-line arguments or logs.
datisvpn admin admin
systemctl daemon-reload
systemctl enable --now datis-firewall.service datis-openvpn.service datis-agent.service datis-panel.service
if [[ -n "$DOMAIN" ]]; then
  apt-get install -y nginx certbot python3-certbot-nginx
  cat > /etc/nginx/sites-available/datisvpn <<CONF
server {
    listen 80;
    server_name $DOMAIN;
    client_max_body_size 16k;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }
}
CONF
  ln -s /etc/nginx/sites-available/datisvpn /etc/nginx/sites-enabled/datisvpn
  nginx -t
  systemctl reload nginx
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "$EMAIL" --redirect
  echo "Panel: https://$DOMAIN (administrator: admin)"
else
  echo 'Panel listens only on 127.0.0.1:8080.'
  echo "On your PC: ssh -N -L 8080:127.0.0.1:8080 root@$ENDPOINT"
  echo 'Then open http://127.0.0.1:8080 (administrator: admin). Keep the SSH session open.'
fi
systemctl is-active datis-openvpn datis-agent datis-panel
echo "Open the VPS provider firewall for $PORT/$PROTOCOL; HTTPS mode also needs 80/tcp and 443/tcp."
echo 'Installation complete. Test one client, quota exhaustion, expiry, and agent failure before selling service.'
