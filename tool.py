#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Networking Internship Mini-Tool
- Parse router configs from Conf/<Router>/config.dump
- Build topology, validate configs, do simple capacity/demand check
- Recommend load balancing / backup paths
- Minimal Day-1 simulation (threads+queues) for ARP/OSPF discovery events
Outputs:
  - topology.png
  - analysis.json
"""

import os, re, json, threading, queue, time, itertools, random
from collections import defaultdict, Counter
import networkx as nx
import matplotlib.pyplot as plt
import json

CONF_DIR = "Conf"         # root folder for configs
OUTPUT_TOPO = "topology.png"
OUTPUT_JSON = "analysis.json"

IP_RE = r"(?:\d{1,3}\.){3}\d{1,3}"

def load_all_configs(root=CONF_DIR):
    """
    Reads Conf/<NODE>/config.dump files and returns dict[node] = raw_text
    """
    configs = {}
    if not os.path.isdir(root):
        raise SystemExit(f"[ERR] Config root not found: {root}")
    for node in os.listdir(root):
        node_dir = os.path.join(root, node)
        fpath = os.path.join(node_dir, "config.dump")
        if os.path.isdir(node_dir) and os.path.isfile(fpath):
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                configs[node] = f.read()
        else:
            # Missing component flag (e.g., missing switch config)
            pass
    return configs

def parse_config(node, text):
    """
    Very lightweight Cisco-ish parser.
    Returns dict with hostname, interfaces, vlans, routes, protocol, gateway, mtu, bandwidth.
    """
    out = {
        "hostname": None,
        "device_type": "router",  # assume router; switch if we see 'switch' marker
        "interfaces": [],         # list of dicts (name, ip, mask, vlan, mtu, bw, connects_to)
        "vlans": {},              # vlan_id -> name/label
        "routes": [],             # static routes
        "protocols": set(),       # {'OSPF', 'BGP', ...}
        "default_gateway": None,
        "asn": None,              # for BGP
    }

    # Hostname
    m = re.search(r"^hostname\s+(\S+)", text, flags=re.M)
    out["hostname"] = (m.group(1) if m else node)

    # Device type hint
    if re.search(r"spanning-tree|switchport|vlan\s+\d+", text, flags=re.I):
        out["device_type"] = "switch"

    # VLANs
    for vid, vname in re.findall(r"vlan\s+(\d+)\s+name\s+(\S+)", text, flags=re.I):
        out["vlans"][vid] = vname

    # Default gateway (often for L3 switch/host configs; not always present)
    mgw = re.search(r"ip\s+default-gateway\s+("+IP_RE+")", text)
    if mgw:
        out["default_gateway"] = mgw.group(1)

    # BGP ASN
    masn = re.search(r"router\s+bgp\s+(\d+)", text, flags=re.I)
    if masn:
        out["protocols"].add("BGP")
        out["asn"] = int(masn.group(1))

    # OSPF presence
    if re.search(r"router\s+ospf\s+\d+", text, flags=re.I):
        out["protocols"].add("OSPF")

    # Interfaces: extremely simplified
    for block in re.findall(r"(?:^|\n)interface\s+(\S+)(.*?)(?=\n\S|\Z)", text, flags=re.S|re.I):
        name, body = block
        # ipm = re.search(r"ip address\s+("+IP_RE+")\s+("+IP_RE+")", body)
        ipm = re.search(r"ip address\s+(" + IP_RE + r")\s+(" + IP_RE + r")", body)
        vlanm = re.search(r"switchport access vlan\s+(\d+)", body, flags=re.I)
        mtum = re.search(r"mtu\s+(\d+)", body, flags=re.I)
        bwm  = re.search(r"bandwidth\s+(\d+)", body, flags=re.I)
        desc = re.search(r"description\s+(.+)", body, flags=re.I)
        # Optional hint to connect neighbor: "description to R3:Fa0/1"
        connects_to = None
        if desc:
            m2 = re.search(r"to\s+([A-Za-z0-9_-]+):([A-Za-z0-9/.-]+)", desc.group(1))
            if m2:
                connects_to = (m2.group(1), m2.group(2))
        out["interfaces"].append({
            "name": name,
            "ip": ipm.group(1) if ipm else None,
            "mask": ipm.group(2) if ipm else None,
            "vlan": vlanm.group(1) if vlanm else None,
            "mtu": int(mtum.group(1)) if mtum else 1500,
            "bw": int(bwm.group(1)) if bwm else 100000,  # in Kbps (Cisco style)
            "connects_to": connects_to
        })

    # Static routes (optional)
    for dst, mask, nh in re.findall(fr"ip route\s+({IP_RE})\s+({IP_RE})\s+({IP_RE})", text):
        out["routes"].append({"dst": dst, "mask": mask, "nh": nh})

    return out

def build_topology(parsed):
    """
    Build an undirected topology graph using interface 'connects_to' hints and IP pairing.
    """
    G = nx.Graph()
    # add nodes
    for n, data in parsed.items():
        G.add_node(n, **{"device_type": data["device_type"], "protocols": list(data["protocols"]), "asn": data.get("asn")})

    # edges via explicit "description to ..." hints
    for a, data in parsed.items():
        for intf in data["interfaces"]:
            ct = intf.get("connects_to")
            if ct:
                b, b_if = ct
                if b in parsed:
                    # store bandwidth as min of both sides later
                    G.add_edge(a, b, links=set())
                    G.edges[a, b]["links"].add((a, intf["name"], b, b_if))

    # try to infer connections by shared subnets (very rough, demo-only)
    # if two interface IPs share first 3 octets -> assume L2/L3 adjacency
    iface_list = []
    for n, data in parsed.items():
        for intf in data["interfaces"]:
            if intf["ip"]:
                iface_list.append((n, intf["name"], intf["ip"], intf["mtu"], intf["bw"]))
    for (n1, i1, ip1, mtu1, bw1), (n2, i2, ip2, mtu2, bw2) in itertools.combinations(iface_list, 2):
        p1 = ".".join(ip1.split(".")[:3])
        p2 = ".".join(ip2.split(".")[:3])
        if p1 == p2 and n1 != n2:
            if not G.has_edge(n1, n2):
                G.add_edge(n1, n2, links=set())
            G.edges[n1, n2]["links"].add((n1, i1, n2, i2))

    # annotate capacity (Kbps) as sum of parallel links min-bw
    for u, v, data in G.edges(data=True):
        cap = 0
        for (a, ai, b, bi) in data["links"]:
            bw_a = bw_b = 100000
            for intf in parsed[a]["interfaces"]:
                if intf["name"] == ai:
                    bw_a = intf["bw"]
            for intf in parsed[b]["interfaces"]:
                if intf["name"] == bi:
                    bw_b = intf["bw"]
            cap += min(bw_a, bw_b)
        data["capacity_kbps"] = cap if cap else 100000
        # store MTUs (for mismatch check)
        data["mtus"] = []
        for (a, ai, b, bi) in data["links"]:
            ma = next((x["mtu"] for x in parsed[a]["interfaces"] if x["name"] == ai), 1500)
            mb = next((x["mtu"] for x in parsed[b]["interfaces"] if x["name"] == bi), 1500)
            data["mtus"].append((ma, mb))
    return G

def detect_issues(parsed, G):
    issues = []
    # duplicate IPs per VLAN scope (simplified: duplicate on node)
    all_ips = []
    for n, data in parsed.items():
        for intf in data["interfaces"]:
            if intf["ip"]:
                all_ips.append((n, intf.get("vlan") or "no-vlan", intf["ip"]))
    c = Counter([x[2] for x in all_ips])
    for ip, cnt in c.items():
        if cnt > 1:
            issues.append({"type": "duplicate_ip", "ip": ip, "where": [x[0] for x in all_ips if x[2]==ip]})

    # wrong vlan labels (demo: vlan id mentioned on access intf but not defined globally on switch)
    for n, data in parsed.items():
        if data["device_type"] == "switch":
            for intf in data["interfaces"]:
                v = intf.get("vlan")
                if v and v not in data["vlans"]:
                    issues.append({"type": "wrong_vlan_label", "node": n, "interface": intf["name"], "vlan": v})

    # gateway sanity (demo: if device has default_gw but no interface in same /24)
    for n, data in parsed.items():
        gw = data.get("default_gateway")
        if gw:
            same24 = False
            gprefix = ".".join(gw.split(".")[:3])
            for intf in data["interfaces"]:
                if intf["ip"] and ".".join(intf["ip"].split(".")[:3]) == gprefix:
                    same24 = True
            if not same24:
                issues.append({"type": "gateway_mismatch", "node": n, "gateway": gw})

    # mtu mismatch on links
    for u, v, ed in G.edges(data=True):
        for ma, mb in ed.get("mtus", []):
            if ma != mb:
                issues.append({"type": "mtu_mismatch", "link": f"{u}-{v}", "mtu_a": ma, "mtu_b": mb})

    # loops (if cycles > 0)
    cycles = list(nx.cycle_basis(G))
    if cycles:
        issues.append({"type": "network_loops", "cycles": cycles})

    # BGP vs OSPF recommendation (if multiple ASNs present -> prefer BGP)
    asns = [d.get("asn") for n, d in parsed.items() if d.get("asn")]
    if len(set(asns)) > 1:
        issues.append({"type": "bgp_recommended", "reason": "Multiple autonomous systems detected"})

    return issues

def estimate_endpoint_demands(parsed, G):
    """
    Toy demand model: each 'PC'/'Server' node (if present) contributes demand to nearest router.
    For this assignment, we simulate demands randomly or by interface labels.
    Return per-edge traffic in Kbps and recommendations if overload.
    """
    # create some pseudo endpoints
    # In a real run, parse endpoints from configs; here we just simulate
    edge_load = { (u, v): 0 for u, v in G.edges() }
    for _ in range(6):
        # pick a random router pair to simulate flow (PC to Server)
        src, dst = random.sample(list(G.nodes()), 2)
        try:
            path = nx.shortest_path(G, src, dst)
        except nx.NetworkXNoPath:
            continue
        demand = random.choice([1000, 5000, 10000, 20000, 40000])  # Kbps
        for a, b in zip(path, path[1:]):
            e = tuple(sorted((a, b)))
            edge_load[e] = edge_load.get(e, 0) + demand
    return edge_load

def recommend_load_balancing(G, edge_load):
    recos = []
    for (a, b), load in edge_load.items():
        cap = G.edges[a, b].get("capacity_kbps", 0)
        if load > cap:
            recos.append({
                "type": "load_balance",
                "link": f"{a}-{b}",
                "load_kbps": load,
                "capacity_kbps": cap,
                "suggestion": "Activate secondary path / move lower-priority traffic to backup (e.g., via alternate router)."
            })
    return recos

# ---- Day-1 mini-simulation (threads & IPC queues) ----

class NodeThread(threading.Thread):
    def __init__(self, name, neighbors):
        super().__init__(daemon=True)
        self.name = name
        self.neighbors = neighbors    # list of neighbor names
        self.inbox = queue.Queue()
        self.log = []

    def send(self, neighbor, msg):
        neighbor.inbox.put((self.name, msg))

    def run(self):
        # bootstrap discovery
        for nb in self.neighbors:
            self.send(nb, {"type": "NEIGHBOR_HELLO"})
        t0 = time.time()
        while time.time() - t0 < 2.0:  # 2s toy sim
            try:
                frm, msg = self.inbox.get(timeout=0.1)
                self.log.append((frm, msg["type"]))
                # respond to OSPF-ish hello
                if msg["type"] == "NEIGHBOR_HELLO":
                    self.send(nodes[frm], {"type": "NEIGHBOR_ACK"})
            except queue.Empty:
                pass

def run_day1_sim(G):
    # Build node objects for routers only
    router_nodes = [n for n, d in G.nodes(data=True) if d.get("device_type") == "router"]
    neighborhood = {n: [m for m in G.neighbors(n) if m in router_nodes] for n in router_nodes}
    global nodes
    nodes = {n: NodeThread(n, []) for n in router_nodes}
    # link neighbors
    for n in router_nodes:
        nodes[n].neighbors = [nodes[m] for m in neighborhood[n]]
    # start
    for n in router_nodes:
        nodes[n].start()
    time.sleep(2.2)
    simlog = {n: nodes[n].log for n in router_nodes}
    return simlog

def draw_topology(G):
    # Create a figure and axes object
    fig, ax = plt.subplots()

    pos = nx.spring_layout(G, seed=7)
    colors = ["#7db4ff" if G.nodes[n]["device_type"]=="router" else "#bafcc2" for n in G.nodes()]
    
    # Pass the axes object to nx.draw
    nx.draw(G, pos, ax=ax, with_labels=True, node_color=colors, node_size=1400, font_size=9)
    
    # annotate capacity
    edge_labels = { (u,v): f'{int(G.edges[u,v]["capacity_kbps"]/1000)} Mbps' for u,v in G.edges() }
    
    # Pass the axes object to nx.draw_networkx_edge_labels
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8, ax=ax)
    
    # The warning should now be resolved with a standard axes object
    plt.tight_layout(pad=2.0)
    plt.savefig(OUTPUT_TOPO, dpi=160)
    plt.close()

def main():
    raw = load_all_configs()
    parsed = {node: parse_config(node, text) for node, text in raw.items()}
    G = build_topology(parsed)

    issues = detect_issues(parsed, G)
    edge_load = estimate_endpoint_demands(parsed, G)
    recos = recommend_load_balancing(G, edge_load)  # This remains only load-balancing recos
    simlog = run_day1_sim(G)

    draw_topology(G)

    # Serialize summary
    summary = {
        "nodes": list(G.nodes(data=True)),
        "edges": [(u, v, d) for u, v, d in G.edges(data=True)],
        "issues": issues,
        "edge_load_kbps": {f"{min(a,b)}-{max(a,b)}": l for (a,b), l in edge_load.items()},
        "recommendations": [],  # Empty, we will fill both LB + MTU here for JSON
        "day1_sim_log": simlog,
        "notes": "This is a simplified educational demo as per internship assignment."
    }

    # Add load balancing recos to summary JSON
    for r in recos:
        summary["recommendations"].append(
            f"On link {r['link']}, load={r['load_kbps']} kbps > cap={r['capacity_kbps']} kbps"
        )

    # Add automatic MTU fix suggestions
    for issue in summary["issues"]:
        if issue["type"] == "mtu_mismatch":
            fix_value = min(issue["mtu_a"], issue["mtu_b"])
            summary["recommendations"].append(
                f"On link {issue['link']}, set both sides MTU to {fix_value} to resolve mismatch."
            )

    with open(OUTPUT_JSON, "w") as f:
        json.dump(summary, f, indent=2, default=list)

    # Console pretty print
    print("\n=== Topology Summary ===")
    print(f"Nodes: {G.number_of_nodes()}, Links: {G.number_of_edges()}")
    print(f"Saved diagram -> {OUTPUT_TOPO}")
    print(f"Issues found: {len(issues)}")
    for i in issues:
        print(" -", i)

    if recos:
        print("\nLoad-Balancing Suggestions:")
        for r in recos:
            print(" -", r["link"], f'load={r["load_kbps"]} kbps > cap={r["capacity_kbps"]} kbps')
    else:
        print("\nNo load issues detected in sample demand.")

    print(f"\nDetailed JSON -> {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
