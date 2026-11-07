"""Run on a native Linux host on the LAN, optionally connected over Wi-Fi."""
import ipaddress
import logging
import os
import re
import statistics
import subprocess
import time
import uuid
from pathlib import Path

import dns.resolver
import httpx
import yaml
from scapy.all import ARP, Ether, conf, get_if_addr, srp

from .models import Sample, Scan, Traffic

log = logging.getLogger("lanmark-agent")


def ping(target: str) -> dict:
    # Addresses are operator config, but validate anyway; never invoke a shell.
    address = str(ipaddress.IPv4Address(target))
    result = subprocess.run(["ping", "-n", "-c", "5", "-i", "0.2", "-W", "1", address], capture_output=True, text=True, timeout=12, env=os.environ | {"LC_ALL": "C"})
    if result.returncode not in (0, 1):
        raise RuntimeError("ping failed to execute; verify raw socket capability")
    loss_match = re.search(r"([\d.]+)% packet loss", result.stdout)
    if not loss_match:
        raise RuntimeError("ping did not report packet loss")
    rtts = [float(v) / 1000 for v in re.findall(r"time[=<]([\d.]+)\s*ms", result.stdout)]
    return {"success": bool(rtts), "latency_seconds": statistics.mean(rtts) if rtts else None,
            "loss_ratio": float(loss_match.group(1)) / 100,
            "jitter_seconds": statistics.mean(abs(b - a) for a, b in zip(rtts, rtts[1:])) if len(rtts) > 1 else None}


def dns_probe(server: str, query: str) -> dict:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [str(ipaddress.IPv4Address(server))]
    started = time.monotonic()
    try:
        resolver.resolve(query, "A", lifetime=3)
        return {"success": True, "latency_seconds": time.monotonic() - started}
    except dns.exception.DNSException:
        return {"success": False}


def discover(interface: str, cidr: str) -> list[dict]:
    # ARP only scans the configured IPv4 broadcast domain, bounded to /22 or smaller.
    network = ipaddress.IPv4Network(cidr, strict=False)
    if network.prefixlen < 22 or not network.is_private:
        raise ValueError("Choose a private LAN IPv4 subnet of /22 or smaller")
    if interface not in conf.ifaces:
        raise ValueError("Configured interface is absent")
    local_ip = ipaddress.IPv4Address(get_if_addr(interface))
    if local_ip not in network:
        raise ValueError("Interface address is outside the configured LAN subnet")
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)), iface=interface, timeout=3, retry=1, verbose=False)
    devices = {}
    for _, packet in answered:
        if ARP in packet and ipaddress.IPv4Address(packet[ARP].psrc) in network:
            devices[packet[ARP].hwsrc.lower()] = {"mac": packet[ARP].hwsrc.lower(), "ip": packet[ARP].psrc}
    return list(devices.values())


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = yaml.safe_load(Path(os.getenv("AGENT_CONFIG_FILE", "/etc/lanmark/agent.yaml")).read_text())
    token = os.environ["LANMARK_AGENT_TOKEN"]
    url = os.environ["LANMARK_API_URL"].rstrip("/")
    interval = max(15, int(config.get("interval_seconds", 30)))
    if len(token) < 32:
        raise ValueError("LANMARK_AGENT_TOKEN must contain at least 32 characters")
    if len(config.get("targets", [])) > 32:
        raise ValueError("At most 32 agent targets are allowed")
    previous_counters = None
    with httpx.Client(timeout=10, headers={"Authorization": f"Bearer {token}"}) as client:
        while True:
            started = time.monotonic()
            try:
                devices = discover(config["interface"], config["cidr"])
                scan_ok = True
            except Exception as error:
                log.error("Discovery failed (%s); inventory presence will be preserved", type(error).__name__)
                devices, scan_ok = [], False
            samples = []
            for target in config.get("targets", []):
                try:
                    kind = target["kind"]
                    if kind == "dns":
                        values = dns_probe(target["address"], config.get("dns_query", "example.com"))
                    elif kind in ("gateway", "isp"):
                        values = ping(target["address"])
                    else:
                        raise ValueError("Agent targets support gateway, isp and dns kinds")
                    samples.append(Sample(target=target["name"], kind=kind, **values))
                except Exception as error:
                    log.error("Probe %s could not run (%s); no measurement submitted", target.get("name"), type(error).__name__)
            traffic = None
            try:
                interface = config["interface"]
                if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,32}", interface):
                    raise ValueError("Invalid interface name")
                stats = Path("/sys/class/net") / interface / "statistics"
                counters = (time.monotonic(), int((stats / "rx_bytes").read_text()), int((stats / "tx_bytes").read_text()))
                if previous_counters and counters[0] > previous_counters[0] and counters[1] >= previous_counters[1] and counters[2] >= previous_counters[2]:
                    duration = counters[0] - previous_counters[0]
                    traffic = Traffic(interface=interface, rx_bytes_per_second=(counters[1] - previous_counters[1]) / duration, tx_bytes_per_second=(counters[2] - previous_counters[2]) / duration)
                previous_counters = counters
            except (OSError, ValueError):
                log.warning("Host interface throughput is unavailable this cycle")
            scan = Scan(source=config["source"], scan_id=uuid.uuid4().hex, scan_ok=scan_ok, devices=devices, samples=samples, traffic=traffic)
            # Retry the identical batch ID so a lost response cannot duplicate events.
            for attempt in range(3):
                try:
                    response = client.post(url + "/v1/scans", json=scan.model_dump())
                    response.raise_for_status()
                    log.info("Submitted %s devices and %s measurements (discovery=%s)", len(devices), len(samples), scan_ok)
                    break
                except httpx.HTTPError as error:
                    log.error("Submission failed (%s), attempt %s/3", type(error).__name__, attempt + 1)
                    time.sleep(2 ** attempt)
            time.sleep(max(1, interval - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
