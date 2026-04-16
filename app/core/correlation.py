def correlate_alerts(alerts):
    correlation = {}

    for alert in alerts:
        ip = alert.get("src_ip")
        if not ip:
            continue

        if ip not in correlation:
            correlation[ip] = []

        correlation[ip].append(alert)

    return correlation