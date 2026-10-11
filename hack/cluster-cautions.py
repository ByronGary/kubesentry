#!/usr/bin/env python3
"""Snapshot the cautions and critical alerts a cluster is raising.

Read-only. Uses kubectl (current or --context) and, through the API server's
service proxy, the in-cluster Prometheus. Each snapshot is written as JSON;
--summarize folds a directory of snapshots into a markdown table of what fired,
how often, and at what peak, split into real cautions and known artifacts of the
kind/KWOK stress environment.

  hack/cluster-cautions.py --out DIR [--label L2] [--every 300] [--count N]
  hack/cluster-cautions.py --summarize DIR > DIR/cautions.md

Stdlib only, so it runs anywhere kubectl does.
"""
import argparse
import collections
import datetime as dt
import glob
import json
import os
import subprocess
import sys
import time
import urllib.parse

# Alerts that fire because of the local stress environment, not because the
# cluster is unhealthy. Each entry: alertname -> (predicate on labels, reason).
ARTIFACTS = {
    "Watchdog": (lambda l: True, "always-firing heartbeat that proves the alert pipeline works"),
    "InfoInhibitor": (lambda l: True, "helper alert used for inhibition"),
    "KubeProxyInstanceUnreachable": (
        lambda l: True,
        "kube-proxy binds its metrics to 127.0.0.1 (kind's default, and EKS's unless the kube-proxy "
        "config is patched); on KWOK fake nodes nothing runs at all"),
    "etcdInsufficientMembers": (lambda l: True, "kind binds etcd metrics to localhost, so Prometheus cannot scrape them"),
    "etcdMembersDown": (lambda l: True, "kind binds etcd metrics to localhost"),
    "KubeControllerManagerInstanceUnreachable": (lambda l: True, "kind binds kube-controller-manager metrics to localhost"),
    "KubeSchedulerInstanceUnreachable": (lambda l: True, "kind binds kube-scheduler metrics to localhost"),
    "KubeControllerManagerDown": (lambda l: True, "kind binds kube-controller-manager metrics to localhost"),
    "KubeSchedulerDown": (lambda l: True, "kind binds kube-scheduler metrics to localhost"),
    "KubeProxyDown": (lambda l: True, "kube-proxy targets on KWOK nodes are not scrapeable"),
    "PrometheusNotConnectedToAlertmanagers": (lambda l: True, "Alertmanager is disabled in the stress profile (no alert routing)"),
    "TargetDown": (
        lambda l: l.get("job") in ("kube-proxy", "kube-etcd", "kube-scheduler", "kube-controller-manager"),
        "targets that kind binds to localhost or that run on KWOK nodes"),
}

PROM_QUERIES = {
    # API server health
    "apiserver_429_per_s": 'sum(rate(apiserver_request_total{code="429"}[5m]))',
    "apiserver_5xx_per_s": 'sum(rate(apiserver_request_total{code=~"5.."}[5m]))',
    "apiserver_apf_rejected_per_s": "sum(rate(apiserver_flowcontrol_rejected_requests_total[5m]))",
    "apiserver_apf_inqueue": "sum(apiserver_flowcontrol_current_inqueue_requests)",
    "apiserver_inflight": "sum(apiserver_current_inflight_requests)",
    "apiserver_read_p99_s": 'histogram_quantile(0.99, sum by (le) (rate(apiserver_request_duration_seconds_bucket{verb=~"GET|LIST"}[5m])))',
    "apiserver_write_p99_s": 'histogram_quantile(0.99, sum by (le) (rate(apiserver_request_duration_seconds_bucket{verb=~"POST|PUT|PATCH|DELETE"}[5m])))',
    "etcd_request_p99_s": "histogram_quantile(0.99, sum by (le) (rate(etcd_request_duration_seconds_bucket[5m])))",
    "etcd_db_bytes": "max(apiserver_storage_db_total_size_in_bytes)",
    "etcd_objects_top": "topk(5, apiserver_storage_objects)",
    # Prometheus self-health
    "prom_rule_iterations_missed_per_s": "sum(rate(prometheus_rule_group_iterations_missed_total[5m]))",
    "prom_rule_eval_failures_per_s": "sum(rate(prometheus_rule_evaluation_failures_total[5m]))",
    "prom_head_series": "max(prometheus_tsdb_head_series)",
    "prom_rss_bytes": 'max(process_resident_memory_bytes{job=~".*prometheus.*",container!="config-reloader"})',
    "prom_slowest_rule_group_s": "max(prometheus_rule_group_last_duration_seconds)",
    "prom_scrape_samples_rejected_per_s": "sum(rate(prometheus_target_scrapes_sample_out_of_order_total[5m]) + rate(prometheus_target_scrapes_exceeded_sample_limit_total[5m]))",
    # Real nodes (node-exporter runs only on non-KWOK nodes)
    "node_mem_available_min_ratio": "min(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)",
    "node_fs_available_min_ratio": 'min(node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"})',
    "node_load1_max_per_cpu": 'max(node_load1 / on(instance) count by (instance) (node_cpu_seconds_total{mode="idle"}))',
    # Containers on real nodes
    # Containers on real nodes: job="kubelet" is cAdvisor; the stress harness's
    # metrics-sim job fakes memory for KWOK pods and must not count here.
    "container_cpu_throttled_top": 'topk(5, sum by (namespace, pod) (rate(container_cpu_cfs_throttled_periods_total{job="kubelet"}[5m])) / sum by (namespace, pod) (rate(container_cpu_cfs_periods_total{job="kubelet"}[5m])) > 0.25)',
    "container_mem_near_limit_top": 'topk(5, max by (namespace, pod, container) (container_memory_working_set_bytes{job="kubelet",container!=""}) / on(namespace, pod, container) group_left max by (namespace, pod, container) (kube_pod_container_resource_limits{resource="memory"}) > 0.85)',
}


def run(args, ctx):
    cmd = ["kubectl"] + (["--context", ctx] if ctx else []) + args
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or f"kubectl {' '.join(args)} failed")
    return out.stdout


def prom(ctx, base, query):
    path = f"{base}/api/v1/query?query={urllib.parse.quote(query)}"
    return json.loads(run(["get", "--raw", path], ctx))["data"]["result"]


def find_prometheus(ctx, pin):
    if pin:
        ns, rest = pin.split("/", 1)
        return f"/api/v1/namespaces/{ns}/services/{rest}/proxy"
    svcs = json.loads(run(["get", "svc", "-A", "-l", "app=kube-prometheus-stack-prometheus", "-o", "json"], ctx))["items"]
    for s in svcs:
        port = next((p["port"] for p in s["spec"]["ports"] if p.get("name") in ("http-web", "web")), 9090)
        return f"/api/v1/namespaces/{s['metadata']['namespace']}/services/{s['metadata']['name']}:{port}/proxy"
    return None


USE_ARTIFACTS = True


def classify(name, labels):
    art = ARTIFACTS.get(name) if USE_ARTIFACTS else None
    if art and art[0](labels):
        return "artifact", art[1]
    return "real", ""


def snapshot(ctx, prom_base):
    now = dt.datetime.now(dt.timezone.utc)
    snap = {"time": now.isoformat(timespec="seconds"), "errors": []}

    def guard(key, fn):
        try:
            snap[key] = fn()
        except Exception as e:  # keep the rest of the snapshot
            snap["errors"].append(f"{key}: {e}")

    # Alerts
    def alerts():
        out = []
        for state in ("firing", "pending"):
            for r in prom(ctx, prom_base, f'ALERTS{{alertstate="{state}"}}'):
                m = r["metric"]
                kind, why = classify(m.get("alertname", ""), m)
                out.append({"state": state, "alertname": m.get("alertname"), "severity": m.get("severity", ""),
                            "kind": kind, "why": why,
                            "where": {k: m[k] for k in ("namespace", "pod", "container", "job", "instance", "node",
                                                         "persistentvolumeclaim", "deployment", "statefulset",
                                                         "daemonset", "job_name", "service") if k in m}})
        return out
    if prom_base:
        guard("alerts", alerts)
        metrics = {}
        for k, q in PROM_QUERIES.items():
            try:
                res = prom(ctx, prom_base, q)
                if k.endswith("_top"):
                    metrics[k] = [{**r["metric"], "value": float(r["value"][1])} for r in res]
                else:
                    metrics[k] = float(res[0]["value"][1]) if res else None
            except Exception as e:
                snap["errors"].append(f"{k}: {e}")
        snap["metrics"] = metrics
    else:
        snap["errors"].append("prometheus: not found")

    # Nodes
    def nodes():
        items = json.loads(run(["get", "nodes", "-o", "json"], ctx))["items"]
        c = collections.Counter()
        bad = []
        for n in items:
            fake = n["metadata"].get("annotations", {}).get("kwok.x-k8s.io/node") == "fake" or \
                n["metadata"].get("labels", {}).get("type") == "kwok"
            c["fake" if fake else "real"] += 1
            for x in n["status"].get("conditions", []):
                if (x["type"] == "Ready" and x["status"] != "True") or (x["type"] != "Ready" and x["status"] == "True"):
                    bad.append({"node": n["metadata"]["name"], "condition": x["type"], "status": x["status"],
                                "reason": x.get("reason", ""), "fake": fake})
            if n["spec"].get("unschedulable"):
                bad.append({"node": n["metadata"]["name"], "condition": "Cordoned", "status": "True", "fake": fake})
        return {"counts": dict(c), "problems": bad}
    guard("nodes", nodes)

    # Pods in trouble
    def pods():
        items = json.loads(run(["get", "pods", "-A", "-o", "json"], ctx))["items"]
        reasons = collections.Counter()
        examples = collections.defaultdict(list)
        restarts = []
        phases = collections.Counter()
        for p in items:
            ns, name = p["metadata"]["namespace"], p["metadata"]["name"]
            st = p.get("status", {})
            phases[st.get("phase", "Unknown")] += 1
            why = set()
            if st.get("reason") in ("Evicted", "NodeLost", "UnexpectedAdmissionError", "OutOfmemory", "OutOfcpu"):
                why.add(st["reason"])
            if p["metadata"].get("deletionTimestamp"):
                age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(p["metadata"]["deletionTimestamp"].replace("Z", "+00:00"))).total_seconds()
                if age > 300:
                    why.add("StuckTerminating")
            if st.get("phase") == "Pending":
                created = dt.datetime.fromisoformat(p["metadata"]["creationTimestamp"].replace("Z", "+00:00"))
                if (dt.datetime.now(dt.timezone.utc) - created).total_seconds() > 300:
                    sched = next((c for c in st.get("conditions", []) if c["type"] == "PodScheduled"), None)
                    why.add("Unschedulable" if sched and sched.get("status") == "False" else "PendingOver5m")
            total = 0
            for cs in st.get("initContainerStatuses", []) + st.get("containerStatuses", []):
                total += cs.get("restartCount", 0)
                w = cs.get("state", {}).get("waiting", {}).get("reason")
                if w in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError",
                         "CreateContainerError", "InvalidImageName", "RunContainerError"):
                    why.add(w)
                lt = cs.get("lastState", {}).get("terminated", {})
                if lt.get("reason") == "OOMKilled":
                    why.add("OOMKilled(last)")
            if total >= 3:
                restarts.append({"namespace": ns, "pod": name, "restarts": total})
            for w in why:
                reasons[w] += 1
                if len(examples[w]) < 3:
                    examples[w].append(f"{ns}/{name}")
        restarts.sort(key=lambda r: -r["restarts"])
        return {"total": len(items), "phases": dict(phases), "reasons": dict(reasons),
                "examples": dict(examples), "top_restarts": restarts[:10]}
    guard("pods", pods)

    # Warning events
    def events():
        items = json.loads(run(["get", "events", "-A", "--field-selector", "type=Warning", "-o", "json"], ctx))["items"]
        c = collections.Counter()
        ex = {}
        for e in items:
            k = f'{e.get("reason", "")} ({e["involvedObject"].get("kind", "")})'
            c[k] += e.get("count") or 1
            ex.setdefault(k, f'{e["involvedObject"].get("namespace", "")}/{e["involvedObject"].get("name", "")}: {(e.get("message") or "")[:160]}')
        return {"total": sum(c.values()), "by_reason": dict(c.most_common(25)), "examples": ex}
    guard("events", events)

    # cert-manager
    def certs():
        try:
            items = json.loads(run(["get", "certificates.cert-manager.io", "-A", "-o", "json"], ctx))["items"]
        except RuntimeError:
            return None
        notready, soon = [], []
        for c in items:
            cond = next((x for x in c.get("status", {}).get("conditions", []) if x["type"] == "Ready"), {})
            ref = f'{c["metadata"]["namespace"]}/{c["metadata"]["name"]}'
            if cond.get("status") != "True":
                notready.append(f'{ref}: {cond.get("reason", "no status")}')
            na = c.get("status", {}).get("notAfter")
            if na:
                left = (dt.datetime.fromisoformat(na.replace("Z", "+00:00")) - dt.datetime.now(dt.timezone.utc)).days
                if left < 14:
                    soon.append(f"{ref}: {left}d left")
        return {"total": len(items), "not_ready": notready[:20], "not_ready_count": len(notready),
                "expiring_14d": soon[:20], "expiring_14d_count": len(soon)}
    guard("certificates", certs)

    # PVCs not bound
    def pvcs():
        items = json.loads(run(["get", "pvc", "-A", "-o", "json"], ctx))["items"]
        c = collections.Counter(i.get("status", {}).get("phase", "Unknown") for i in items)
        return {"total": len(items), "phases": dict(c)}
    guard("pvcs", pvcs)

    # Host memory (this machine), when it is the Docker host
    try:
        with open("/proc/meminfo") as f:
            mi = {l.split(":")[0]: int(l.split()[1]) for l in f}
        snap["host_mem_available_mib"] = mi.get("MemAvailable", 0) // 1024
    except OSError:
        pass
    return snap


def fmt(v, kind=""):
    if v is None:
        return "-"
    if kind == "bytes":
        for unit in ("B", "KiB", "MiB", "GiB"):
            if abs(v) < 1024:
                return f"{v:.0f} {unit}"
            v /= 1024
        return f"{v:.1f} TiB"
    if kind == "ratio":
        return f"{v * 100:.0f}%"
    if kind == "s":
        return f"{v * 1000:.0f} ms" if v < 1 else f"{v:.1f} s"
    return f"{v:.3g}"


METRIC_FMT = {
    "apiserver_429_per_s": ("API server 429s /s", "", "high"), "apiserver_5xx_per_s": ("API server 5xx /s", "", "high"),
    "apiserver_apf_rejected_per_s": ("APF rejected /s", "", "high"), "apiserver_apf_inqueue": ("APF queued requests", "", "high"),
    "apiserver_inflight": ("API server inflight", "", "high"), "apiserver_read_p99_s": ("API read p99", "s", "high"),
    "apiserver_write_p99_s": ("API write p99", "s", "high"), "etcd_request_p99_s": ("etcd request p99", "s", "high"),
    "etcd_db_bytes": ("etcd DB size", "bytes", "high"),
    "prom_rule_iterations_missed_per_s": ("Prometheus missed rule evals /s", "", "high"),
    "prom_rule_eval_failures_per_s": ("Prometheus rule eval failures /s", "", "high"),
    "prom_head_series": ("Prometheus head series", "", "high"), "prom_rss_bytes": ("Prometheus RSS", "bytes", "high"),
    "prom_slowest_rule_group_s": ("Slowest rule group", "s", "high"),
    "node_mem_available_min_ratio": ("Real node min mem available", "ratio", "low"),
    "node_fs_available_min_ratio": ("Real node min disk available", "ratio", "low"),
    "node_load1_max_per_cpu": ("Real node max load/CPU", "", "high"),
}


def summarize(d):
    snaps = []
    for p in sorted(glob.glob(os.path.join(d, "cautions-*.json"))):
        with open(p) as f:
            snaps.append(json.load(f))
    if not snaps:
        return f"No snapshots in {d}\n"
    out = [f"# Cluster cautions: {os.path.basename(os.path.normpath(d))}", "",
           f"{len(snaps)} snapshots from {snaps[0]['time']} to {snaps[-1]['time']}.", ""]

    # Alerts
    agg = {}
    for i, s in enumerate(snaps):
        per = collections.Counter()
        for a in s.get("alerts", []):
            per[(a["alertname"], a["severity"], a["state"], a["kind"], a["why"])] += 1
        for k, n in per.items():
            e = agg.setdefault(k, {"peak": 0, "seen": 0, "first": s["time"], "last": s["time"], "where": None})
            e["peak"] = max(e["peak"], n)
            e["seen"] += 1
            e["last"] = s["time"]
        for a in s.get("alerts", []):
            k = (a["alertname"], a["severity"], a["state"], a["kind"], a["why"])
            if agg[k]["where"] is None and a["where"]:
                agg[k]["where"] = ", ".join(f"{x}={y}" for x, y in a["where"].items())
    sev_rank = {"critical": 0, "warning": 1, "info": 2, "none": 3, "": 3}
    for kind, title in (("real", "Alerts that point at real problems"), ("artifact", "Alerts caused by the stress environment")):
        rows = [(k, v) for k, v in agg.items() if k[3] == kind]
        rows.sort(key=lambda kv: (kv[0][2] != "firing", sev_rank.get(kv[0][1], 3), -kv[1]["peak"]))
        out += [f"## {title}", ""]
        if not rows:
            out += ["None.", ""]
            continue
        if kind == "real":
            out += ["| Alert | Severity | State | Peak count | Seen in | First / last | Example |", "|---|---|---|---:|---:|---|---|"]
            for (name, sev, state, _, _), v in rows:
                out.append(f"| {name} | {sev} | {state} | {v['peak']} | {v['seen']}/{len(snaps)} | {v['first'][11:19]} / {v['last'][11:19]} | {v['where'] or ''} |")
        else:
            out += ["| Alert | Severity | Peak count | Why it is an artifact |", "|---|---|---:|---|"]
            for (name, sev, state, _, why), v in rows:
                out.append(f"| {name} | {sev} | {v['peak']} | {why} |")
        out.append("")

    # Health metrics: worst value seen
    out += ["## Control plane and monitoring health (worst value seen)", "", "| Signal | Worst | Last |", "|---|---:|---:|"]
    for k, (label, kind, worst) in METRIC_FMT.items():
        vals = [s.get("metrics", {}).get(k) for s in snaps]
        vals = [v for v in vals if isinstance(v, (int, float))]
        if not vals:
            continue
        w = max(vals) if worst == "high" else min(vals)
        out.append(f"| {label} | {fmt(w, kind)} | {fmt(vals[-1], kind)} |")
    top = snaps[-1].get("metrics", {})
    if top.get("etcd_objects_top"):
        out.append("")
        out.append("Largest object counts in etcd (last snapshot): " + ", ".join(
            f"{r.get('resource', r.get('group', '?'))} {r['value']:.0f}" for r in top["etcd_objects_top"]))
    for k, label in (("container_cpu_throttled_top", "CPU-throttled pods (>25% of periods)"),
                     ("container_mem_near_limit_top", "Containers above 85% of their memory limit")):
        seen = {}
        for s in snaps:
            for r in s.get("metrics", {}).get(k) or []:
                key = f"{r.get('namespace')}/{r.get('pod')}" + (f"/{r['container']}" if r.get("container") else "")
                seen[key] = max(seen.get(key, 0), r["value"])
        if seen:
            out += ["", f"{label}: " + ", ".join(f"{p} ({v * 100:.0f}%)" for p, v in sorted(seen.items(), key=lambda x: -x[1])[:8])]
    out.append("")

    # Workload problems: peak per reason
    out += ["## Pods, nodes and objects in trouble (peak across snapshots)", "", "| Signal | Peak | Example |", "|---|---:|---|"]
    peak, ex = collections.Counter(), {}
    for s in snaps:
        for r, n in (s.get("pods") or {}).get("reasons", {}).items():
            if n > peak[r]:
                peak[r] = n
                ex[r] = ", ".join((s["pods"].get("examples") or {}).get(r, []))
    for r, n in peak.most_common():
        out.append(f"| Pods: {r} | {n} | {ex.get(r, '')} |")
    nodes_bad = collections.Counter()
    for s in snaps:
        c = collections.Counter(f"{p['condition']}={p['status']}" + (" (fake)" if p.get("fake") else "") for p in (s.get("nodes") or {}).get("problems", []))
        for k, n in c.items():
            nodes_bad[k] = max(nodes_bad[k], n)
    for k, n in nodes_bad.most_common():
        out.append(f"| Nodes: {k} | {n} | |")
    for s in snaps[-1:]:
        c = s.get("certificates") or {}
        if c:
            out.append(f"| Certificates not ready | {c.get('not_ready_count', 0)} | {'; '.join(c.get('not_ready', [])[:3])} |")
            out.append(f"| Certificates expiring < 14d | {c.get('expiring_14d_count', 0)} | {'; '.join(c.get('expiring_14d', [])[:3])} |")
        pv = (s.get("pvcs") or {}).get("phases", {})
        notbound = {k: v for k, v in pv.items() if k != "Bound"}
        if notbound:
            out.append(f"| PVCs not Bound | {sum(notbound.values())} | {notbound} |")
    top_r = (snaps[-1].get("pods") or {}).get("top_restarts", [])
    if top_r:
        out += ["", "Most restarted pods (last snapshot): " + ", ".join(f"{r['namespace']}/{r['pod']} ×{r['restarts']}" for r in top_r[:8])]
    out.append("")

    # Events
    ev = collections.Counter()
    exs = {}
    for s in snaps:
        for k, n in (s.get("events") or {}).get("by_reason", {}).items():
            ev[k] = max(ev[k], n)
            exs.setdefault(k, (s.get("events") or {}).get("examples", {}).get(k, ""))
    if ev:
        out += ["## Warning events (peak count per reason)", "", "| Reason (object) | Peak | Example |", "|---|---:|---|"]
        for k, n in ev.most_common(20):
            out.append(f"| {k} | {n} | {exs.get(k, '').replace('|', '/')} |")
        out.append("")

    host = [s["host_mem_available_mib"] for s in snaps if "host_mem_available_mib" in s]
    if host:
        out += [f"Host memory available: min {min(host)} MiB, last {host[-1]} MiB.", ""]
    errs = collections.Counter(e.split(":")[0] for s in snaps for e in s.get("errors", []))
    if errs:
        out += ["Collector errors: " + ", ".join(f"{k} ×{n}" for k, n in errs.items()), ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--context", default="")
    ap.add_argument("--prometheus", default="", help="namespace/service:port to pin (default: find kube-prometheus-stack)")
    ap.add_argument("--out", help="directory for cautions-<time>.json snapshots")
    ap.add_argument("--label", default="", help="free-form label stored in each snapshot (e.g. the load level)")
    ap.add_argument("--every", type=int, default=0, help="seconds between snapshots (0: one snapshot)")
    ap.add_argument("--count", type=int, default=0, help="stop after N snapshots (0: until killed)")
    ap.add_argument("--summarize", metavar="DIR", help="print a markdown summary of the snapshots in DIR")
    ap.add_argument("--no-artifacts", action="store_true",
                    help="treat every alert as real (for clusters other than the kind/KWOK stress setup)")
    a = ap.parse_args()
    global USE_ARTIFACTS
    USE_ARTIFACTS = not a.no_artifacts
    if a.summarize:
        sys.stdout.write(summarize(a.summarize))
        return
    if not a.out:
        ap.error("--out or --summarize is required")
    os.makedirs(a.out, exist_ok=True)
    prom_base = None
    n = 0
    while True:
        if prom_base is None:
            try:
                prom_base = find_prometheus(a.context, a.prometheus)
            except Exception as e:
                print(f"prometheus lookup: {e}", file=sys.stderr)
        s = snapshot(a.context, prom_base)
        s["label"] = a.label
        path = os.path.join(a.out, f"cautions-{s['time'].replace(':', '')}.json")
        with open(path, "w") as f:
            json.dump(s, f, indent=1)
        real = sum(1 for x in s.get("alerts", []) if x["kind"] == "real" and x["state"] == "firing")
        print(f"{s['time']} {a.label}: {real} real firing alerts, {len(s.get('alerts', []))} total, errors {len(s['errors'])} -> {path}", flush=True)
        n += 1
        if not a.every or (a.count and n >= a.count):
            return
        time.sleep(a.every)


if __name__ == "__main__":
    main()
