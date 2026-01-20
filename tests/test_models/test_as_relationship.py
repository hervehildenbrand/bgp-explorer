"""Tests for AS relationship data models."""

from bgp_explorer.models.as_relationship import (
    ASConnectivity,
    ASNeighbor,
    ASRelationship,
)


class TestASRelationship:
    """Tests for ASRelationship dataclass."""

    def test_create_basic_relationship(self):
        """Test creating an ASRelationship with required fields."""
        rel = ASRelationship(
            asn1=47957,
            asn2=45666,
            asn2_name=None,
            connected_pct=47.7,
            peer_pct=17.6,
            as1_upstream_pct=30.1,
            as2_upstream_pct=0.0,
        )
        assert rel.asn1 == 47957
        assert rel.asn2 == 45666
        assert rel.connected_pct == 47.7
        assert rel.peer_pct == 17.6

    def test_create_full_relationship(self):
        """Test creating an ASRelationship with all fields."""
        rel = ASRelationship(
            asn1=47957,
            asn2=45666,
            asn2_name="Worldline Services Australia Pty Ltd.",
            connected_pct=47.7,
            peer_pct=17.6,
            as1_upstream_pct=30.1,
            as2_upstream_pct=0.0,
        )
        assert rel.asn1 == 47957
        assert rel.asn2 == 45666
        assert rel.asn2_name == "Worldline Services Australia Pty Ltd."

    def test_relationship_type_downstream(self):
        """Test relationship type detection for downstream."""
        rel = ASRelationship(
            asn1=47957,
            asn2=45666,
            asn2_name=None,
            connected_pct=47.7,
            peer_pct=17.6,
            as1_upstream_pct=30.1,  # asn1 provides transit to asn2
            as2_upstream_pct=0.0,
        )
        assert rel.relationship_type == "downstream"

    def test_relationship_type_upstream(self):
        """Test relationship type detection for upstream."""
        rel = ASRelationship(
            asn1=47957,
            asn2=3356,
            asn2_name="Level3",
            connected_pct=12.3,
            peer_pct=0.0,
            as1_upstream_pct=0.0,
            as2_upstream_pct=12.3,  # asn2 provides transit to asn1
        )
        assert rel.relationship_type == "upstream"

    def test_relationship_type_peer(self):
        """Test relationship type detection for peer."""
        rel = ASRelationship(
            asn1=47957,
            asn2=8677,
            asn2_name="Worldline SA",
            connected_pct=41.8,
            peer_pct=23.6,  # High peer percentage
            as1_upstream_pct=18.2,
            as2_upstream_pct=0.0,
        )
        assert rel.relationship_type == "peer"

    def test_relationship_type_peer_when_symmetric(self):
        """Test relationship type is peer when symmetric upstream."""
        rel = ASRelationship(
            asn1=100,
            asn2=200,
            asn2_name=None,
            connected_pct=50.0,
            peer_pct=10.0,
            as1_upstream_pct=20.0,
            as2_upstream_pct=20.0,  # Similar to as1_upstream
        )
        assert rel.relationship_type == "peer"

    def test_relationship_to_dict(self):
        """Test converting ASRelationship to dictionary."""
        rel = ASRelationship(
            asn1=47957,
            asn2=45666,
            asn2_name="Worldline Services Australia",
            connected_pct=47.7,
            peer_pct=17.6,
            as1_upstream_pct=30.1,
            as2_upstream_pct=0.0,
        )
        d = rel.to_dict()
        assert d["asn1"] == 47957
        assert d["asn2"] == 45666
        assert d["asn2_name"] == "Worldline Services Australia"
        assert d["connected_pct"] == 47.7
        assert d["relationship_type"] == "downstream"

    def test_relationship_from_dict_with_percentage_strings(self):
        """Test creating ASRelationship from Monocle JSON output."""
        data = {
            "asn1": 47957,
            "asn2": 45666,
            "asn2_name": "Worldline Services Australia",
            "connected": "47.7%",
            "peer": "17.6%",
            "as1_upstream": "30.1%",
            "as2_upstream": "0.0%",
        }
        rel = ASRelationship.from_dict(data)
        assert rel.asn1 == 47957
        assert rel.asn2 == 45666
        assert rel.connected_pct == 47.7
        assert rel.peer_pct == 17.6
        assert rel.as1_upstream_pct == 30.1
        assert rel.as2_upstream_pct == 0.0

    def test_relationship_from_dict_with_float_values(self):
        """Test creating ASRelationship from dict with float values."""
        data = {
            "asn1": 47957,
            "asn2": 45666,
            "asn2_name": None,
            "connected": 47.7,
            "peer": 17.6,
            "as1_upstream": 30.1,
            "as2_upstream": 0.0,
        }
        rel = ASRelationship.from_dict(data)
        assert rel.connected_pct == 47.7
        assert rel.peer_pct == 17.6

    def test_relationship_equality(self):
        """Test ASRelationship equality comparison."""
        rel1 = ASRelationship(
            asn1=47957,
            asn2=45666,
            asn2_name=None,
            connected_pct=47.7,
            peer_pct=17.6,
            as1_upstream_pct=30.1,
            as2_upstream_pct=0.0,
        )
        rel2 = ASRelationship(
            asn1=47957,
            asn2=45666,
            asn2_name=None,
            connected_pct=47.7,
            peer_pct=17.6,
            as1_upstream_pct=30.1,
            as2_upstream_pct=0.0,
        )
        assert rel1 == rel2


class TestASNeighbor:
    """Tests for ASNeighbor dataclass."""

    def test_create_basic_neighbor(self):
        """Test creating an ASNeighbor with required fields."""
        neighbor = ASNeighbor(
            asn=4826,
            name=None,
            peers_count=378,
            peers_percent=21.45,
        )
        assert neighbor.asn == 4826
        assert neighbor.name is None
        assert neighbor.peers_count == 378
        assert neighbor.peers_percent == 21.45

    def test_create_full_neighbor(self):
        """Test creating an ASNeighbor with all fields."""
        neighbor = ASNeighbor(
            asn=4826,
            name="VOCUS-BACKBONE-AS Vocus Connect",
            peers_count=378,
            peers_percent=21.45,
        )
        assert neighbor.asn == 4826
        assert neighbor.name == "VOCUS-BACKBONE-AS Vocus Connect"

    def test_neighbor_to_dict(self):
        """Test converting ASNeighbor to dictionary."""
        neighbor = ASNeighbor(
            asn=4826,
            name="VOCUS-BACKBONE-AS",
            peers_count=378,
            peers_percent=21.45,
        )
        d = neighbor.to_dict()
        assert d["asn"] == 4826
        assert d["name"] == "VOCUS-BACKBONE-AS"
        assert d["peers_count"] == 378
        assert d["peers_percent"] == 21.45

    def test_neighbor_from_dict(self):
        """Test creating ASNeighbor from dictionary."""
        data = {
            "asn": 4826,
            "name": "VOCUS-BACKBONE-AS",
            "peers_count": 378,
            "peers_percent": 21.45,
        }
        neighbor = ASNeighbor.from_dict(data)
        assert neighbor.asn == 4826
        assert neighbor.name == "VOCUS-BACKBONE-AS"
        assert neighbor.peers_count == 378

    def test_neighbor_from_dict_defaults(self):
        """Test creating ASNeighbor from dict with missing optional fields."""
        data = {"asn": 4826}
        neighbor = ASNeighbor.from_dict(data)
        assert neighbor.asn == 4826
        assert neighbor.name is None
        assert neighbor.peers_count == 0
        assert neighbor.peers_percent == 0.0

    def test_neighbor_equality(self):
        """Test ASNeighbor equality comparison."""
        n1 = ASNeighbor(asn=4826, name=None, peers_count=378, peers_percent=21.45)
        n2 = ASNeighbor(asn=4826, name=None, peers_count=378, peers_percent=21.45)
        assert n1 == n2


class TestASConnectivity:
    """Tests for ASConnectivity dataclass."""

    def test_create_empty_connectivity(self):
        """Test creating an ASConnectivity with no neighbors."""
        connectivity = ASConnectivity(
            asn=47957,
            total_neighbors=0,
            max_visibility=1762,
        )
        assert connectivity.asn == 47957
        assert connectivity.total_neighbors == 0
        assert connectivity.max_visibility == 1762
        assert connectivity.upstreams == []
        assert connectivity.peers == []
        assert connectivity.downstreams == []

    def test_create_full_connectivity(self):
        """Test creating an ASConnectivity with neighbors."""
        upstream1 = ASNeighbor(asn=4826, name="Vocus", peers_count=378, peers_percent=21.45)
        upstream2 = ASNeighbor(asn=3356, name="Level3", peers_count=217, peers_percent=12.32)
        peer1 = ASNeighbor(asn=45666, name="Worldline", peers_count=841, peers_percent=47.73)

        connectivity = ASConnectivity(
            asn=47957,
            total_neighbors=1790,
            max_visibility=1762,
            upstreams=[upstream1, upstream2],
            peers=[peer1],
            downstreams=[],
        )
        assert connectivity.asn == 47957
        assert connectivity.total_neighbors == 1790
        assert len(connectivity.upstreams) == 2
        assert len(connectivity.peers) == 1
        assert len(connectivity.downstreams) == 0

    def test_connectivity_counts(self):
        """Test connectivity count properties."""
        upstream1 = ASNeighbor(asn=4826, name="Vocus", peers_count=378, peers_percent=21.45)
        peer1 = ASNeighbor(asn=45666, name="Worldline", peers_count=841, peers_percent=47.73)
        downstream1 = ASNeighbor(asn=12345, name="Customer", peers_count=100, peers_percent=5.67)

        connectivity = ASConnectivity(
            asn=47957,
            total_neighbors=3,
            max_visibility=1762,
            upstreams=[upstream1],
            peers=[peer1],
            downstreams=[downstream1],
        )
        assert connectivity.upstream_count == 1
        assert connectivity.peer_count == 1
        assert connectivity.downstream_count == 1

    def test_connectivity_to_dict(self):
        """Test converting ASConnectivity to dictionary."""
        upstream = ASNeighbor(asn=4826, name="Vocus", peers_count=378, peers_percent=21.45)

        connectivity = ASConnectivity(
            asn=47957,
            total_neighbors=1,
            max_visibility=1762,
            upstreams=[upstream],
        )
        d = connectivity.to_dict()
        assert d["asn"] == 47957
        assert d["total_neighbors"] == 1
        assert d["max_visibility"] == 1762
        assert len(d["upstreams"]) == 1
        assert d["upstreams"][0]["asn"] == 4826

    def test_connectivity_from_dict(self):
        """Test creating ASConnectivity from Monocle inspect output."""
        data = {
            "asn": 47957,
            "upstreams": {
                "count": 7,
                "percent": 0.39,
                "top": [
                    {
                        "asn": 4826,
                        "name": "VOCUS-BACKBONE-AS",
                        "peers_count": 378,
                        "peers_percent": 21.45,
                    },
                    {
                        "asn": 3356,
                        "name": "LEVEL3",
                        "peers_count": 217,
                        "peers_percent": 12.32,
                    },
                ],
            },
            "peers": {
                "count": 1774,
                "percent": 99.11,
                "top": [
                    {
                        "asn": 45666,
                        "name": "WSAPL-AS-AP Worldline Services",
                        "peers_count": 841,
                        "peers_percent": 47.73,
                    },
                ],
            },
            "downstreams": {
                "count": 9,
                "percent": 0.50,
                "top": [],
            },
        }
        connectivity = ASConnectivity.from_dict(data, asn=47957, max_peers=1762)
        assert connectivity.asn == 47957
        assert connectivity.total_neighbors == 7 + 1774 + 9
        assert connectivity.max_visibility == 1762
        assert len(connectivity.upstreams) == 2
        assert len(connectivity.peers) == 1
        assert len(connectivity.downstreams) == 0

    def test_connectivity_from_dict_empty_top(self):
        """Test creating ASConnectivity when top lists are empty."""
        data = {
            "asn": 64496,
            "upstreams": {"count": 0, "percent": 0.0, "top": []},
            "peers": {"count": 0, "percent": 0.0, "top": []},
            "downstreams": {"count": 0, "percent": 0.0, "top": []},
        }
        connectivity = ASConnectivity.from_dict(data, asn=64496, max_peers=1000)
        assert connectivity.asn == 64496
        assert connectivity.total_neighbors == 0
        assert len(connectivity.upstreams) == 0
        assert len(connectivity.peers) == 0
        assert len(connectivity.downstreams) == 0

    def test_connectivity_equality(self):
        """Test ASConnectivity equality comparison."""
        c1 = ASConnectivity(asn=47957, total_neighbors=10, max_visibility=1762)
        c2 = ASConnectivity(asn=47957, total_neighbors=10, max_visibility=1762)
        assert c1 == c2
