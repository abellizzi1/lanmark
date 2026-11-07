from statistics import median


def latency_anomaly(values: list[float], current: float) -> dict | None:
    """One-sided robust baseline with a 20ms floor; never train on current sample."""
    if len(values) < 30:
        return None
    center = median(values)
    mad = median(abs(v - center) for v in values)
    threshold = center + max(6 * 1.4826 * mad, 0.020, center * 2)
    if current <= threshold:
        return None
    return {"median_seconds": center, "mad_seconds": mad, "threshold_seconds": threshold,
            "observed_seconds": current, "baseline_samples": len(values)}


def explain(samples: list[dict]) -> str:
    """Only correlate measurements from the same source and collection cycle."""
    by_kind: dict[str, list[bool]] = {}
    for s in samples:
        by_kind.setdefault(s["kind"], []).append(s["success"])
    gateway = by_kind.get("gateway", [])
    isp = by_kind.get("isp", [])
    dns = by_kind.get("dns", [])
    http = by_kind.get("http", [])
    if gateway and not all(gateway):
        return "Gateway probe failed: the local link, access point, router, or ICMP filtering may be involved. Compare a wired agent before attributing this to Wi-Fi."
    if gateway and all(gateway) and len(isp) >= 2 and not any(isp):
        return "Gateway responds but multiple public IP probes fail: an upstream/ISP path problem is likely; public ICMP filtering remains possible."
    if isp and all(isp) and dns and not all(dns):
        return "Public IP probes work while DNS queries fail: the configured resolver or its path is a likely cause."
    if isp and all(isp) and dns and all(dns) and http and not all(http):
        return "IP and DNS probes work while HTTP fails: check the destination service, TLS, proxy, or HTTP path."
    return "The available probes do not isolate a cause. Compare gateway, multiple public IPs, DNS, HTTP, and a second measurement location."
