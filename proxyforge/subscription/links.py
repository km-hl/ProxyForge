"""Parse supported share links without network or storage access."""
import base64
import ipaddress
import json
import re
import urllib.parse


def parse_share_link(link: str) -> dict:
    link = link.strip()

    def b64_decode(value: str) -> str:
        value = value.strip()
        value += "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode(value).decode("utf-8")

    def first(qs: dict, *keys: str, default: str = "") -> str:
        for key in keys:
            if key in qs and qs[key]:
                return qs[key][0]
        return default

    def split_list(value: str) -> list:
        return [item for item in value.replace(",", "\n").splitlines() if item]

    def add_integer_field(node: dict, qs: dict, field: str, *keys: str):
        value = first(qs, *keys)
        if not value:
            return
        if not re.fullmatch(r"\d+", value):
            raise ValueError(f"{field} must be a non-negative integer")
        node[field] = int(value)

    def add_boolean_field(node: dict, qs: dict, field: str, *keys: str):
        value = first(qs, *keys)
        if not value:
            return
        normalized = value.lower()
        if normalized not in {"1", "true", "yes", "0", "false", "no"}:
            raise ValueError(f"{field} must be boolean")
        node[field] = normalized in {"1", "true", "yes"}

    def add_common_tls_fields(node: dict, qs: dict, sni_field: str):
        sni = first(qs, "sni", "peer")
        if sni:
            node[sni_field] = sni
        alpn = first(qs, "alpn")
        if alpn:
            node["alpn"] = split_list(alpn)
        fingerprint = first(qs, "fingerprint")
        if fingerprint:
            node["fingerprint"] = fingerprint
        client_fingerprint = first(qs, "fp", "client-fingerprint")
        if client_fingerprint:
            node["client-fingerprint"] = client_fingerprint
        add_boolean_field(
            node,
            qs,
            "skip-cert-verify",
            "skip-cert-verify",
            "allowInsecure",
            "allow_insecure",
            "insecure",
        )
        name_cert_verify = first(qs, "name-cert-verify", "name_cert_verify")
        if name_cert_verify:
            node["name-cert-verify"] = name_cert_verify

    def add_transport_opts(node: dict, qs: dict):
        network = node.get("network")
        path = first(qs, "path", default="/")
        host = first(qs, "host")
        if network == "ws":
            ws_opts = {"path": path}
            if host:
                ws_opts["headers"] = {"Host": host}
            node["ws-opts"] = ws_opts
        elif network == "grpc":
            service_name = first(qs, "serviceName", "service-name", "grpc-service-name")
            if service_name:
                node["grpc-opts"] = {"grpc-service-name": service_name}
        elif network == "h2":
            h2_opts = {"path": path}
            if host:
                h2_opts["host"] = split_list(host)
            node["h2-opts"] = h2_opts
        elif network == "xhttp":
            xhttp_opts = {"path": path}
            if host:
                xhttp_opts["host"] = host
            mode = first(qs, "mode")
            if mode:
                xhttp_opts["mode"] = mode
            node["xhttp-opts"] = xhttp_opts

    if link.lower().startswith("vmess://"):
        try:
            b64 = link[8:]
            data = json.loads(b64_decode(b64))
            node = {
                "name": data.get("ps", "vmess_node"),
                "type": "vmess",
                "server": data.get("add", ""),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id", ""),
                "alterId": int(data.get("aid", 0)),
                "cipher": data.get("scy", "auto"),
                "network": data.get("net", "tcp"),
                "tls": data.get("tls") == "tls",
                "udp": True
            }
            if data.get("net") == "ws":
                node["ws-opts"] = {"path": data.get("path", ""), "headers": {"Host": data.get("host", "")}}
            if data.get("sni"):
                node["servername"] = data.get("sni")
            return node
        except: return None
    elif link.lower().startswith("ss://"):
        try:
            parsed = urllib.parse.urlparse(link)
            userinfo = parsed.username or ""
            server = parsed.hostname
            port = parsed.port
            cipher = ""
            password = ""

            if parsed.password is not None:
                cipher = urllib.parse.unquote(parsed.username or "")
                password = urllib.parse.unquote(parsed.password)
            elif parsed.hostname and parsed.port and userinfo:
                decoded_userinfo = b64_decode(userinfo)
                cipher, password = decoded_userinfo.split(":", 1)
            else:
                raw = parsed.netloc or link[5:].split("#", 1)[0].split("?", 1)[0]
                decoded = b64_decode(raw)
                userinfo, address = decoded.rsplit("@", 1)
                cipher, password = userinfo.split(":", 1)
                server, port_text = address.rsplit(":", 1)
                port = int(port_text)

            return {
                "name": urllib.parse.unquote(parsed.fragment) if parsed.fragment else "ss_node",
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": cipher,
                "password": password,
                "udp": True
            }
        except: return None
    elif any(link.lower().startswith(prefix) for prefix in [
        "vless://",
        "trojan://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "anytls://",
        "wireguard://",
    ]):
        try:
            parsed = urllib.parse.urlparse(link)
            scheme = "hysteria2" if parsed.scheme == "hy2" else parsed.scheme

            # Hysteria 2 permits both userpass authentication ("user:pass") and
            # multi-port authorities such as host:443,2000-3000. urllib's
            # parsed.username/parsed.port either truncates or rejects those valid
            # forms, so preserve the raw authority for Hysteria 2.
            raw_authority = parsed.netloc.rsplit("@", 1)
            raw_auth = urllib.parse.unquote(raw_authority[0]) if len(raw_authority) == 2 else ""
            raw_host_port = raw_authority[-1]
            port_value = None
            ports_value = ""
            if scheme == "hysteria2":
                if raw_host_port.startswith("["):
                    closing_bracket = raw_host_port.find("]")
                    port_spec = raw_host_port[closing_bracket + 2:] if closing_bracket >= 0 and raw_host_port[closing_bracket + 1:closing_bracket + 2] == ":" else ""
                else:
                    host_parts = raw_host_port.rsplit(":", 1)
                    port_spec = host_parts[1] if len(host_parts) == 2 else ""

                port_spec = urllib.parse.unquote(port_spec)
                if port_spec and re.fullmatch(r"[0-9,-]+", port_spec):
                    if "," in port_spec or "-" in port_spec:
                        ports_value = port_spec
                        first_port = re.search(r"\d+", port_spec)
                        port_value = int(first_port.group(0)) if first_port else 443
                    else:
                        port_value = int(port_spec)
                else:
                    # The Hysteria URI specification defines 443 as the default.
                    port_value = 443
            elif scheme in {"anytls", "wireguard"}:
                port_value = parsed.port or 443
            else:
                port_value = parsed.port

            node = {
                "type": scheme,
                "server": parsed.hostname,
                "port": port_value,
                "name": urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"{scheme}_node",
                "udp": True
            }
            if scheme == "vless": node["uuid"] = urllib.parse.unquote(parsed.username or "")
            elif scheme == "trojan": node["password"] = urllib.parse.unquote(parsed.username or "")
            elif scheme == "hysteria2":
                node["password"] = raw_auth
                if ports_value:
                    node["ports"] = ports_value
            elif scheme == "tuic":
                raw_tuic_auth = raw_authority[0] if len(raw_authority) == 2 else ""
                if ":" in raw_tuic_auth:
                    raw_uuid, raw_password = raw_tuic_auth.split(":", 1)
                    node["uuid"] = urllib.parse.unquote(raw_uuid)
                    node["password"] = urllib.parse.unquote(raw_password)
                else:
                    node["token"] = urllib.parse.unquote(raw_tuic_auth)
            elif scheme == "anytls":
                node["password"] = raw_auth
            elif scheme == "wireguard":
                node["private-key"] = raw_auth

            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if "type" in qs: node["network"] = qs["type"][0]

            if scheme == "vless":
                add_common_tls_fields(node, qs, "servername")
                sec = first(qs, "security").lower()
                node["tls"] = sec != "none"
                encryption = first(qs, "encryption")
                if encryption:
                    node["encryption"] = encryption
                flow = first(qs, "flow")
                if flow:
                    node["flow"] = flow
                packet_encoding = first(qs, "packetEncoding", "packet-encoding")
                if packet_encoding:
                    node["packet-encoding"] = packet_encoding
                if sec == "reality":
                    node["tls"] = True
                    node["reality-opts"] = {"public-key": first(qs, "pbk")}
                    if "sid" in qs: node["reality-opts"]["short-id"] = qs["sid"][0]
                    if "spx" in qs: node["reality-opts"]["spider-x"] = qs["spx"][0]
                add_transport_opts(node, qs)
            elif scheme == "trojan":
                add_common_tls_fields(node, qs, "sni")
                add_transport_opts(node, qs)
            elif scheme == "hysteria2":
                add_common_tls_fields(node, qs, "sni")
                auth = first(qs, "auth")
                if auth and not node["password"]:
                    node["password"] = auth
                obfs = first(qs, "obfs")
                if obfs and obfs.lower() != "none":
                    node["obfs"] = obfs
                obfs_password = first(qs, "obfs-password", "obfsPassword")
                if obfs_password and node.get("obfs"):
                    node["obfs-password"] = obfs_password
                pin_sha256 = first(qs, "pinSHA256", "pin-sha256")
                if pin_sha256:
                    node["fingerprint"] = pin_sha256
                field_aliases = {
                    "ports": ("ports", "mport"),
                    "hop-interval": ("hop-interval", "hopInterval"),
                    "up": ("up", "upmbps"),
                    "down": ("down", "downmbps"),
                    "obfs-min-packet-size": ("obfs-min-packet-size",),
                    "obfs-max-packet-size": ("obfs-max-packet-size",),
                }
                for field, aliases in field_aliases.items():
                    value = first(qs, *aliases)
                    if value:
                        node[field] = value
            elif scheme == "tuic":
                add_common_tls_fields(node, qs, "sni")
                congestion_controller = first(
                    qs,
                    "congestion-controller",
                    "congestion-control",
                    "congestion_control",
                )
                if congestion_controller:
                    node["congestion-controller"] = congestion_controller
                udp_relay_mode = first(qs, "udp-relay-mode", "udp_relay_mode")
                if udp_relay_mode:
                    node["udp-relay-mode"] = udp_relay_mode
                bbr_profile = first(qs, "bbr-profile", "bbr_profile")
                if bbr_profile:
                    node["bbr-profile"] = bbr_profile
                add_boolean_field(
                    node,
                    qs,
                    "reduce-rtt",
                    "reduce-rtt",
                    "reduce_rtt",
                    "zero-rtt-handshake",
                    "zero_rtt_handshake",
                )
                add_boolean_field(node, qs, "disable-sni", "disable-sni", "disable_sni")
                add_boolean_field(node, qs, "fast-open", "fast-open", "fast_open")
                add_integer_field(
                    node,
                    qs,
                    "heartbeat-interval",
                    "heartbeat-interval",
                    "heartbeat_interval",
                )
                add_integer_field(
                    node,
                    qs,
                    "request-timeout",
                    "request-timeout",
                    "request_timeout",
                )
                add_integer_field(
                    node,
                    qs,
                    "max-udp-relay-packet-size",
                    "max-udp-relay-packet-size",
                    "max_udp_relay_packet_size",
                )
                add_integer_field(
                    node,
                    qs,
                    "max-open-streams",
                    "max-open-streams",
                    "max_open_streams",
                )
            elif scheme == "anytls":
                if first(qs, "security").lower() == "reality":
                    return None
                add_common_tls_fields(node, qs, "sni")
                add_boolean_field(node, qs, "udp", "udp")
                add_integer_field(
                    node,
                    qs,
                    "idle-session-check-interval",
                    "idle-session-check-interval",
                    "idle_session_check_interval",
                )
                add_integer_field(
                    node,
                    qs,
                    "idle-session-timeout",
                    "idle-session-timeout",
                    "idle_session_timeout",
                )
                add_integer_field(
                    node,
                    qs,
                    "min-idle-session",
                    "min-idle-session",
                    "min_idle_session",
                )
            elif scheme == "wireguard":
                def wireguard_key(*keys: str) -> str:
                    # Query-string decoders translate an unescaped '+' to a
                    # space, but '+' is valid in standard WireGuard Base64 keys.
                    return first(qs, *keys).replace(" ", "+")

                public_key = wireguard_key("publickey", "public-key", "public_key")
                if public_key:
                    node["public-key"] = public_key

                address_values = []
                address = first(qs, "address", "addresses")
                if address:
                    address_values.extend(split_list(address))
                explicit_ip = first(qs, "ip")
                if explicit_ip:
                    address_values.append(explicit_ip)
                explicit_ipv6 = first(qs, "ipv6")
                if explicit_ipv6:
                    address_values.append(explicit_ipv6)
                for address_value in address_values:
                    interface = ipaddress.ip_interface(address_value.strip())
                    field = "ip" if interface.version == 4 else "ipv6"
                    if field in node:
                        raise ValueError(f"only one WireGuard {field} address is supported")
                    node[field] = str(interface.ip)

                allowed_ips = first(qs, "allowedips", "allowed-ips", "allowed_ips")
                if allowed_ips:
                    node["allowed-ips"] = [
                        value.strip()
                        for value in split_list(allowed_ips)
                        if value.strip()
                    ]

                reserved = first(qs, "reserved")
                if reserved:
                    if "," in reserved:
                        reserved_bytes = [int(value.strip()) for value in reserved.split(",")]
                        if len(reserved_bytes) != 3 or any(value < 0 or value > 255 for value in reserved_bytes):
                            raise ValueError("reserved must contain exactly three bytes")
                        node["reserved"] = reserved_bytes
                    else:
                        node["reserved"] = reserved

                pre_shared_key = wireguard_key(
                    "presharedkey",
                    "preshared-key",
                    "pre-shared-key",
                    "pre_shared_key",
                )
                if pre_shared_key:
                    node["pre-shared-key"] = pre_shared_key

                dns = first(qs, "dns")
                if dns:
                    node["dns"] = [
                        value.strip()
                        for value in split_list(dns)
                        if value.strip()
                    ]
                node["remote-dns-resolve"] = True
                add_boolean_field(
                    node,
                    qs,
                    "remote-dns-resolve",
                    "remote-dns-resolve",
                    "remote_dns_resolve",
                )
                add_boolean_field(node, qs, "udp", "udp")
                add_integer_field(node, qs, "mtu", "mtu")
                add_integer_field(
                    node,
                    qs,
                    "persistent-keepalive",
                    "persistent-keepalive",
                    "persistent_keepalive",
                    "keepalive",
                )
                dialer_proxy = first(qs, "dialer-proxy", "dialer_proxy", "dp")
                if dialer_proxy:
                    node["dialer-proxy"] = dialer_proxy
            return node
        except: return None
    return None
