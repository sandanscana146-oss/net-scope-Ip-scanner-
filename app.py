import ipaddress
import json
import platform
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

# ==========================================
# NETSCOPE - NETWORK DISCOVERY AND SCANNER
# ==========================================

st.set_page_config(
    page_title="NetScope | IP Scanner",
    page_icon="🌐",
    layout="wide"
)

st.title("🌐 NetScope")
st.subheader("Network Discovery & Security Assessment")
st.caption("Blue Team Network Intelligence Dashboard")

st.divider()

REPORTS_DIR = Path("reports")

# ==========================================
# PORT DATABASE  (port: service, risk, advice)
# ==========================================

PORT_INFO = {
    21: ("FTP", "High", "Sends credentials in cleartext. Use SFTP or FTPS."),
    22: ("SSH", "Medium", "Use key authentication, disable root login, restrict by IP."),
    23: ("Telnet", "High", "Cleartext remote access. Disable and use SSH."),
    25: ("SMTP", "Medium", "Check it is not an open relay and requires TLS."),
    53: ("DNS", "Low", "Restrict zone transfers and recursion."),
    80: ("HTTP", "Low", "Unencrypted web traffic. Redirect to HTTPS."),
    110: ("POP3", "Medium", "Cleartext mail. Use POP3S."),
    135: ("MS-RPC", "Medium", "Block at the firewall outside the LAN."),
    139: ("NetBIOS", "High", "Legacy file sharing. Disable if unused."),
    143: ("IMAP", "Medium", "Cleartext mail. Use IMAPS."),
    389: ("LDAP", "Medium", "Prefer LDAPS and restrict access."),
    443: ("HTTPS", "Low", "Check the TLS version and certificate."),
    445: ("SMB", "High", "Common lateral-movement and ransomware target. Restrict access."),
    1433: ("MSSQL", "High", "Databases should not be reachable from untrusted networks."),
    3306: ("MySQL", "High", "Bind to 127.0.0.1 or restrict by firewall."),
    3389: ("RDP", "High", "Frequent attack target. Use a VPN, MFA and NLA."),
    5432: ("PostgreSQL", "High", "Databases should not be reachable from untrusted networks."),
    5900: ("VNC", "High", "Weak authentication is common. Tunnel it or disable."),
    6379: ("Redis", "High", "Often unauthenticated by default. Bind locally."),
    8080: ("HTTP Proxy", "Medium", "Often a proxy or admin panel. Confirm it should be exposed."),
    8443: ("HTTPS-Alt", "Low", "Check the TLS configuration."),
    27017: ("MongoDB", "High", "Frequently exposed with no authentication."),
}

DISCOVERY_PORTS = (80, 443, 445, 22, 3389, 135)
HTTP_PORTS = {80, 8000, 8080, 8443, 443}
TLS_PORTS = {443, 465, 636, 993, 995, 8443}
RISK_ORDER = ["High", "Medium", "Low", "Info"]
RISK_RANK = {name: i for i, name in enumerate(RISK_ORDER)}
RISK_COLOURS = {"High": "#B3261E", "Medium": "#B26A00", "Low": "#1F7A5C", "Info": "#5B6B7A"}
CHANGE_LABELS = (
    ("new_hosts", "New devices"),
    ("new_ports", "Newly opened ports"),
    ("gone_hosts", "Devices no longer seen"),
    ("closed_ports", "Ports now closed"),
)


# ==========================================
# NETWORK FUNCTIONS
# ==========================================

def ping_host(ip):
    """True only if a real echo reply came back (Windows can exit 0 on 'unreachable')."""
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", "700", ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]
    try:
        out = subprocess.run(command, capture_output=True, text=True, timeout=3)
        return out.returncode == 0 and "ttl=" in out.stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return False


def tcp_alive(ip, timeout):
    """Catches hosts that block ping: an accepted or refused connection means it is up."""
    for port in DISCOVERY_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


def discover(ip, timeout):
    if ping_host(ip):
        return "Ping"
    if tcp_alive(ip, timeout):
        return "TCP probe"
    return None


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return "Unknown"


def clean_banner(data):
    if not data:
        return ""
    lines = data.replace("\r", "").split("\n")
    for line in lines:
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()[:80]
    first = next((ln for ln in lines if ln.strip()), "")
    return "".join(ch for ch in first if ch.isprintable()).strip()[:80]


def grab_banner(sock, host, port, timeout):
    data = ""
    try:
        sock.settimeout(max(timeout, 1.0))
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: NetScope\r\n\r\n".encode())
        data = sock.recv(512).decode("latin-1", errors="replace")
    except OSError:
        data = ""
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return clean_banner(data)


def scan_port(ip, port, timeout, grab):
    """Returns (ip, port, banner). banner is None when the port is closed."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return ip, port, None
    if grab:
        return ip, port, grab_banner(sock, ip, port, timeout)
    sock.close()
    return ip, port, ""


def describe(port):
    if port in PORT_INFO:
        return PORT_INFO[port]
    try:
        name = socket.getservbyport(port, "tcp")
    except OSError:
        name = "Unknown"
    return name, "Info", "Identify the service and confirm it should be exposed."


def assess_security(rows):
    """Plain-language findings for one device, built from its High-risk ports."""
    findings = [f'{r["Service"]} ({r["Port"]}): {r["Recommendation"]}' for r in rows if r["Risk"] == "High"]
    return "; ".join(findings) if findings else "No high-risk ports"


# ==========================================
# SCANNING ENGINE
# ==========================================

def run_scan(hosts, ports, cfg, progress, status):
    start_time = time.time()
    workers, timeout = cfg["workers"], cfg["timeout"]
    how = {}

    if cfg["discover"]:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(discover, str(ip), timeout): str(ip) for ip in hosts}
            for i, future in enumerate(as_completed(futures), 1):
                if future.result():
                    how[futures[future]] = future.result()
                progress.progress(0.3 * i / len(futures))
                status.write(f"Discovering devices: {i}/{len(futures)}")
        targets = sorted(how, key=ipaddress.ip_address)
    else:
        targets = [str(ip) for ip in hosts]

    found = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_port, ip, p, timeout, cfg["grab"]) for ip in targets for p in ports]
        for i, future in enumerate(as_completed(futures), 1):
            ip, port, banner = future.result()
            if banner is not None:
                found.append((ip, port, banner))
            if i % 25 == 0 or i == len(futures):
                progress.progress(0.3 + 0.7 * i / len(futures))
                status.write(f"Scanning ports: {i}/{len(futures)}")

    live = sorted({ip for ip, _, _ in found} | set(how), key=ipaddress.ip_address)
    with ThreadPoolExecutor(max_workers=16) as pool:
        names = dict(zip(live, pool.map(get_hostname, live)))

    port_rows = []
    for ip, port, banner in found:
        service, risk, advice = describe(port)
        port_rows.append({"Host": ip, "Port": port, "Service": service, "Risk": risk,
                          "Banner": banner, "Recommendation": advice})
    ports_df = pd.DataFrame(port_rows, columns=["Host", "Port", "Service", "Risk", "Banner", "Recommendation"])
    if not ports_df.empty:
        ports_df["_ip"] = ports_df["Host"].map(lambda h: int(ipaddress.ip_address(h)))
        ports_df = ports_df.sort_values(["_ip", "Port"]).drop(columns="_ip").reset_index(drop=True)

    device_rows = []
    for ip in live:
        mine = [r for r in port_rows if r["Host"] == ip]
        worst = min((r["Risk"] for r in mine), key=RISK_RANK.get, default="None")
        device_rows.append({
            "IP Address": ip,
            "Hostname": names.get(ip, "Unknown"),
            "Found By": how.get(ip, "Port scan"),
            "Open Ports": len(mine),
            "Services": ", ".join(f'{r["Port"]}/{r["Service"]}' for r in sorted(mine, key=lambda r: r["Port"])),
            "Highest Risk": worst,
            "Security Findings": assess_security(mine),
        })
    devices_df = pd.DataFrame(device_rows, columns=[
        "IP Address", "Hostname", "Found By", "Open Ports", "Services", "Highest Risk", "Security Findings"])

    return devices_df, ports_df, round(time.time() - start_time, 2)


# ==========================================
# HISTORY AND CHANGE DETECTION
# ==========================================

def previous_scan(target):
    if not REPORTS_DIR.exists():
        return None
    for path in sorted(REPORTS_DIR.glob("scan_*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if data.get("target") == target:
            return data
    return None


def find_changes(prev, ports_df, devices_df):
    if not prev:
        return None
    before = {(r["Host"], r["Port"]): r["Service"] for r in prev["ports"]}
    now = {(r.Host, r.Port): r.Service for r in ports_df.itertuples()}
    return {
        "when": prev["started"],
        "new_ports": [f"{h}:{p} ({now[(h, p)]})" for h, p in sorted(now.keys() - before.keys())],
        "closed_ports": [f"{h}:{p} ({before[(h, p)]})" for h, p in sorted(before.keys() - now.keys())],
        "new_hosts": sorted(set(devices_df["IP Address"]) - set(prev.get("hosts", []))),
        "gone_hosts": sorted(set(prev.get("hosts", [])) - set(devices_df["IP Address"])),
    }


def save_scan(target, devices_df, ports_df, duration):
    REPORTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = REPORTS_DIR / f"scan_{stamp}.csv"
    ports_df.to_csv(csv_path, index=False)
    meta = {
        "target": target,
        "started": datetime.now().isoformat(timespec="seconds"),
        "duration": duration,
        "hosts": list(devices_df["IP Address"]),
        "ports": ports_df[["Host", "Port", "Service", "Risk"]].to_dict("records"),
    }
    (REPORTS_DIR / f"scan_{stamp}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return csv_path


# ==========================================
# REPORT HELPERS
# ==========================================

def style_risk(df, column):
    def colour(value):
        bg = RISK_COLOURS.get(value)
        return f"background-color: {bg}; color: white" if bg else ""

    styler = df.style
    apply = getattr(styler, "map", None) or styler.applymap
    return apply(colour, subset=[column])


def build_html_report(target, devices_df, ports_df, duration):
    def table(df):
        head = "".join(f"<th>{escape(c)}</th>" for c in df.columns)
        body = "".join("<tr>" + "".join(f"<td>{escape(str(v))}</td>" for v in row) + "</tr>"
                       for row in df.itertuples(index=False))
        return f"<table><tr>{head}</tr>{body}</table>"

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>NetScope report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#111}}
table{{border-collapse:collapse;width:100%;margin-bottom:2rem}}
th,td{{border:1px solid #ccc;padding:6px 10px;text-align:left;font-size:14px}}th{{background:#f0f0f0}}</style></head>
<body><h1>NetScope scan report</h1>
<p><b>Target:</b> {escape(target)}<br><b>Generated:</b> {datetime.now():%Y-%m-%d %H:%M}<br>
<b>Duration:</b> {duration} s<br><b>Devices:</b> {len(devices_df)} &nbsp; <b>Open ports:</b> {len(ports_df)}</p>
<h2>Devices</h2>{table(devices_df)}<h2>Open ports</h2>{table(ports_df)}</body></html>"""


def parse_extra_ports(text):
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            ports.update(range(min(a, b), max(a, b) + 1))
        else:
            ports.add(int(part))
    if ports and (min(ports) < 1 or max(ports) > 65535):
        raise ValueError("port out of range")
    return ports


# ==========================================
# SIDEBAR CONFIGURATION
# ==========================================

st.sidebar.title("⚙️ Scanner Settings")

network_input = st.sidebar.text_input(
    "Target Network (CIDR or single IP)",
    value="10.0.0.0/24"
)

selected_ports = st.sidebar.multiselect(
    "Select TCP Ports",
    options=list(PORT_INFO.keys()),
    default=[22, 80, 443, 445, 3389, 8080],
    format_func=lambda p: f"{p} - {PORT_INFO[p][0]}"
)

extra_ports = st.sidebar.text_input(
    "Extra ports (optional)",
    placeholder="e.g. 8000-8100, 9000"
)

workers = st.sidebar.slider("Concurrent Workers", min_value=10, max_value=200, value=100)

timeout = st.sidebar.slider("Timeout per port (seconds)", 0.2, 2.0, 0.5, 0.1)

discover_first = st.sidebar.toggle(
    "Discover devices first",
    value=True,
    help="Ping plus a TCP probe. Turn off to scan every address, even ones that don't answer."
)

grab_banners = st.sidebar.toggle("Grab service banners", value=True)

st.sidebar.warning("Only scan networks you own or have permission to assess.")

allowed = st.sidebar.checkbox("I have permission to scan this network")

start_scan = st.sidebar.button(
    "🚀 Start Network Scan",
    disabled=not allowed
)


# ==========================================
# START SCAN
# ==========================================

if start_scan:

    try:
        network = ipaddress.ip_network(network_input.strip(), strict=False)
    except ValueError:
        st.error("Invalid network address. Use a CIDR block like 10.0.0.0/24 or a single IP.")
        st.stop()

    if network.version != 4:
        st.error("Only IPv4 networks are supported.")
        st.stop()

    if not network.is_private:
        st.error("Please enter a private network.")
        st.stop()

    if network.num_addresses > 256:
        st.error("Maximum supported network size is /24.")
        st.stop()

    try:
        ports = sorted(set(selected_ports) | parse_extra_ports(extra_ports))
    except ValueError:
        st.error("Extra ports must look like 22, 8000-8100 and stay between 1 and 65535.")
        st.stop()

    if not ports:
        st.error("Select at least one TCP port.")
        st.stop()

    hosts = list(network.hosts()) or [network.network_address]

    st.subheader("🔍 Network Scan")
    st.write(f"Target network: **{network}**")
    st.write(f"Addresses to check: **{len(hosts)}**  |  Ports per device: **{len(ports)}**")

    progress = st.progress(0)
    status = st.empty()

    cfg = {"workers": workers, "timeout": timeout, "discover": discover_first, "grab": grab_banners}
    devices_df, ports_df, duration = run_scan(hosts, ports, cfg, progress, status)
    status.empty()

    target = str(network)
    changes = find_changes(previous_scan(target), ports_df, devices_df)
    saved = save_scan(target, devices_df, ports_df, duration)

    st.session_state["scan"] = {
        "target": target, "devices": devices_df, "ports": ports_df,
        "duration": duration, "changes": changes, "saved": str(saved),
    }

    st.success("Network scan completed!")


# ==========================================
# RESULTS DASHBOARD
# ==========================================

if "scan" in st.session_state:

    scan = st.session_state["scan"]
    devices_df, ports_df = scan["devices"], scan["ports"]

    flagged = int((devices_df["Highest Risk"] == "High").sum()) if not devices_df.empty else 0

    st.divider()
    st.subheader("📊 Network Overview")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Active Devices", len(devices_df))
    col2.metric("Open Ports", len(ports_df))
    col3.metric("Flagged Devices", flagged)
    col4.metric("Scan Duration", f'{scan["duration"]} sec')

    st.divider()

    if devices_df.empty:
        st.info(
            "No responsive devices found. Check the network range, or turn off "
            "'Discover devices first' if your devices block ping and probes."
        )
    else:
        tab_devices, tab_ports, tab_changes = st.tabs(["💻 Devices", "🔌 Open Ports", "🔄 Changes"])

        with tab_devices:
            st.dataframe(style_risk(devices_df, "Highest Risk"), hide_index=True)
            if flagged:
                st.warning(f"{flagged} devices have high-risk ports and require further investigation.")
            else:
                st.success("No high-risk ports detected.")

        with tab_ports:
            if ports_df.empty:
                st.info("Devices responded, but none had an open port in the selected list.")
            else:
                levels = st.multiselect("Show risk levels", RISK_ORDER, default=RISK_ORDER)
                st.dataframe(style_risk(ports_df[ports_df["Risk"].isin(levels)], "Risk"), hide_index=True)

        with tab_changes:
            changes = scan["changes"]
            if not changes:
                st.info("This is the first saved scan of this network. Scan it again later to see what changed.")
            else:
                st.caption(f"Compared with the scan from {changes['when']}.")
                if not any(changes[key] for key, _ in CHANGE_LABELS):
                    st.success("Nothing changed since the last scan.")
                for key, label in CHANGE_LABELS:
                    if changes[key]:
                        st.write(f"**{label}**")
                        st.write(", ".join(changes[key]))

        st.divider()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        d1, d2, d3 = st.columns(3)
        d1.download_button("📥 Devices CSV", devices_df.to_csv(index=False).encode("utf-8"),
                           f"netscope_devices_{stamp}.csv", "text/csv")
        d2.download_button("📥 Open ports CSV", ports_df.to_csv(index=False).encode("utf-8"),
                           f"netscope_ports_{stamp}.csv", "text/csv")
        d3.download_button("📥 HTML report",
                           build_html_report(scan["target"], devices_df, ports_df, scan["duration"]),
                           f"netscope_report_{stamp}.html", "text/html")
        st.caption(f'Scan saved to {scan["saved"]}')


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "NetScope | Network Discovery & Security Assessment | Educational Project"
)