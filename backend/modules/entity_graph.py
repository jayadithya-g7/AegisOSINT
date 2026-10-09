"""
AegisOSINT - Entity Correlation & Link Analysis Engine
Constructs heterogeneous intelligence graphs, computes topological graph metrics
(Degree centrality, Betweenness, PageRank, Connected Components),
and unmasks shared cybercrime syndicate infrastructure.
"""

from typing import Dict, Any, List, Optional, Tuple, Set
import networkx as nx


# Visual styling rules for Cytoscape.js representation
NODE_STYLE_CONFIG = {
    "Brand": {"color": "#10B981", "shape": "star", "size": 65, "icon": "shield"},
    "Domain": {"color": "#EF4444", "shape": "ellipse", "size": 48, "icon": "globe"},
    "IP_Address": {"color": "#F59E0B", "shape": "diamond", "size": 44, "icon": "server"},
    "ASN": {"color": "#8B5CF6", "shape": "round-rectangle", "size": 40, "icon": "network"},
    "Registrar": {"color": "#3B82F6", "shape": "rectangle", "size": 42, "icon": "building"},
    "Nameserver": {"color": "#06B6D4", "shape": "hexagon", "size": 38, "icon": "dns"},
    "SSL_Cert": {"color": "#EC4899", "shape": "octagon", "size": 36, "icon": "lock"},
    "Social_Account": {"color": "#F97316", "shape": "tag", "size": 42, "icon": "user"},
    "Crypto_Wallet": {"color": "#EAB308", "shape": "vee", "size": 38, "icon": "coins"},
    "Threat_Actor": {"color": "#DC2626", "shape": "triangle", "size": 55, "icon": "skull"}
}


class EntityCorrelationGraph:
    """Manages the OSINT threat network graph, performs correlation and link analytics."""

    def __init__(self):
        self.graph = nx.Graph()

    def add_entity(
        self,
        node_id: str,
        entity_type: str,
        label: str,
        properties: Optional[Dict[str, Any]] = None
    ):
        """Adds an entity node to the threat network graph."""
        props = properties or {}
        style = NODE_STYLE_CONFIG.get(entity_type, {"color": "#6B7280", "shape": "ellipse", "size": 35})
        self.graph.add_node(
            node_id,
            entity_type=entity_type,
            label=label,
            color=style["color"],
            shape=style["shape"],
            size=style["size"],
            **props
        )

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Adds a directional / semantic relationship edge between two entities."""
        meta = metadata or {}
        self.graph.add_edge(
            source_id,
            target_id,
            relationship=relationship,
            weight=weight,
            **meta
        )

    def ingest_domain_intelligence(
        self,
        domain: str,
        target_brand: str,
        ip_addresses: List[str],
        registrar: Optional[str] = None,
        nameservers: Optional[List[str]] = None,
        ssl_issuer: Optional[str] = None,
        associated_social: Optional[str] = None,
        crypto_wallet: Optional[str] = None,
        asn: Optional[str] = None
    ):
        """Automated OSINT ingestion: builds correlated subgraphs from domain scan artifacts."""
        brand_id = f"brand:{target_brand.lower()}"
        domain_id = f"domain:{domain.lower()}"

        # Ensure Brand node
        self.add_entity(brand_id, "Brand", target_brand.title(), {"brand": target_brand})

        # Add Domain node
        self.add_entity(domain_id, "Domain", domain, {"domain": domain})
        self.add_relation(domain_id, brand_id, "IMPERSONATES", weight=2.0)

        # Correlate IP Addresses
        for ip in ip_addresses:
            ip_id = f"ip:{ip}"
            self.add_entity(ip_id, "IP_Address", ip, {"ip": ip})
            self.add_relation(domain_id, ip_id, "RESOLVES_TO", weight=1.5)

            # Correlate ASN if provided
            if asn:
                asn_id = f"asn:{asn}"
                self.add_entity(asn_id, "ASN", asn, {"asn": asn})
                self.add_relation(ip_id, asn_id, "ANNOUNCED_BY", weight=1.0)

        # Correlate Registrar
        if registrar:
            reg_id = f"reg:{registrar.lower().replace(' ', '_')}"
            self.add_entity(reg_id, "Registrar", registrar, {"registrar": registrar})
            self.add_relation(domain_id, reg_id, "REGISTERED_VIA", weight=1.0)

        # Correlate Nameservers
        if nameservers:
            for ns in nameservers:
                ns_id = f"ns:{ns.lower()}"
                self.add_entity(ns_id, "Nameserver", ns, {"nameserver": ns})
                self.add_relation(domain_id, ns_id, "DELEGATED_TO", weight=1.0)

        # Correlate SSL Certificate Issuer
        if ssl_issuer:
            ssl_id = f"ssl:{ssl_issuer.lower().replace(' ', '_')}"
            self.add_entity(ssl_id, "SSL_Cert", ssl_issuer, {"issuer": ssl_issuer})
            self.add_relation(domain_id, ssl_id, "SECURED_BY", weight=1.0)

        # Correlate Social Account if present
        if associated_social:
            soc_id = f"soc:{associated_social.lower().lstrip('@')}"
            self.add_entity(soc_id, "Social_Account", associated_social, {"handle": associated_social})
            self.add_relation(soc_id, domain_id, "PROMOTES_LINK", weight=1.8)
            self.add_relation(soc_id, brand_id, "IMPERSONATES", weight=1.8)

        # Correlate Cryptocurrency Drainer Wallet
        if crypto_wallet:
            wallet_id = f"wallet:{crypto_wallet.lower()}"
            self.add_entity(wallet_id, "Crypto_Wallet", f"{crypto_wallet[:6]}...{crypto_wallet[-4:]}", {"address": crypto_wallet})
            self.add_relation(domain_id, wallet_id, "DRAINS_TO_WALLET", weight=2.5)

    def calculate_graph_metrics(self) -> Dict[str, Any]:
        """
        Computes formal network centrality metrics to uncover campaign nexus nodes:
        - Degree Centrality (most connected infrastructure hubs)
        - Betweenness Centrality (critical bridges between fraud rings)
        - PageRank (highest influence score)
        - Connected Components (discrete fraud syndicates)
        """
        if len(self.graph.nodes) == 0:
            return {"degree_centrality": {}, "betweenness_centrality": {}, "pagerank": {}, "syndicates": []}

        deg_centrality = nx.degree_centrality(self.graph)
        between_centrality = nx.betweenness_centrality(self.graph)
        try:
            pagerank = nx.pagerank(self.graph, weight="weight")
        except Exception:
            pagerank = {n: 1.0 / len(self.graph.nodes) for n in self.graph.nodes}

        # Connected components (syndicate clusters)
        components = list(nx.connected_components(self.graph))
        syndicates = []
        for i, comp in enumerate(components):
            comp_nodes = list(comp)
            node_types = {}
            for n in comp_nodes:
                etype = self.graph.nodes[n].get("entity_type", "Unknown")
                node_types[etype] = node_types.get(etype, 0) + 1

            syndicates.append({
                "syndicate_id": f"Syndicate-Cluster-{i+1}",
                "node_count": len(comp_nodes),
                "entities": comp_nodes,
                "composition": node_types
            })

        # Sort syndicates by size
        syndicates.sort(key=lambda s: s["node_count"], reverse=True)

        # Identify top infrastructure pivots
        pivots = []
        for node_id, deg in sorted(deg_centrality.items(), key=lambda x: x[1], reverse=True)[:10]:
            pivots.append({
                "node_id": node_id,
                "label": self.graph.nodes[node_id].get("label", node_id),
                "entity_type": self.graph.nodes[node_id].get("entity_type", "Unknown"),
                "degree_centrality": round(deg, 4),
                "betweenness_centrality": round(between_centrality.get(node_id, 0), 4),
                "pagerank": round(pagerank.get(node_id, 0), 4),
                "connected_edges": self.graph.degree(node_id)
            })

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "syndicates_count": len(syndicates),
            "top_infrastructure_pivots": pivots,
            "syndicates": syndicates
        }

    def export_to_cytoscape_json(self) -> Dict[str, Any]:
        """Exports graph in standard Cytoscape.js JSON structure for web UI rendering."""
        elements = {"nodes": [], "edges": []}

        metrics = self.calculate_graph_metrics()
        deg_map = {p["node_id"]: p["connected_edges"] for p in metrics.get("top_infrastructure_pivots", [])}

        for n, attrs in self.graph.nodes(data=True):
            elements["nodes"].append({
                "data": {
                    "id": n,
                    "label": attrs.get("label", n),
                    "entity_type": attrs.get("entity_type", "Unknown"),
                    "color": attrs.get("color", "#6B7280"),
                    "shape": attrs.get("shape", "ellipse"),
                    "size": attrs.get("size", 40),
                    "degree": self.graph.degree(n),
                    **{k: v for k, v in attrs.items() if k not in ["label", "entity_type", "color", "shape", "size"]}
                }
            })

        edge_counter = 0
        for u, v, attrs in self.graph.edges(data=True):
            edge_counter += 1
            elements["edges"].append({
                "data": {
                    "id": f"e{edge_counter}",
                    "source": u,
                    "target": v,
                    "relationship": attrs.get("relationship", "ASSOCIATED_WITH"),
                    "weight": attrs.get("weight", 1.0)
                }
            })

        return {
            "elements": elements,
            "summary": {
                "nodes": self.graph.number_of_nodes(),
                "edges": self.graph.number_of_edges(),
                "syndicates": metrics.get("syndicates_count", 0)
            }
        }
