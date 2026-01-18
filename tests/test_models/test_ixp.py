"""Tests for IXP data models."""

import pytest

from bgp_explorer.models.ixp import IXP, Network, IXPPresence


class TestIXP:
    """Tests for IXP dataclass."""

    def test_create_basic_ixp(self):
        """Test creating an IXP with required fields."""
        ixp = IXP(
            id=1,
            name="DE-CIX Frankfurt",
            city="Frankfurt",
            country="DE",
        )
        assert ixp.id == 1
        assert ixp.name == "DE-CIX Frankfurt"
        assert ixp.city == "Frankfurt"
        assert ixp.country == "DE"

    def test_create_full_ixp(self):
        """Test creating an IXP with all fields."""
        ixp = IXP(
            id=31,
            name="AMS-IX",
            city="Amsterdam",
            country="NL",
            website="https://www.ams-ix.net/",
            participant_count=900,
        )
        assert ixp.id == 31
        assert ixp.name == "AMS-IX"
        assert ixp.city == "Amsterdam"
        assert ixp.country == "NL"
        assert ixp.website == "https://www.ams-ix.net/"
        assert ixp.participant_count == 900

    def test_ixp_defaults(self):
        """Test that optional fields have correct defaults."""
        ixp = IXP(
            id=1,
            name="Test IXP",
            city="Test City",
            country="US",
        )
        assert ixp.website is None
        assert ixp.participant_count is None

    def test_ixp_to_dict(self):
        """Test converting IXP to dictionary."""
        ixp = IXP(
            id=31,
            name="AMS-IX",
            city="Amsterdam",
            country="NL",
            website="https://www.ams-ix.net/",
            participant_count=900,
        )
        d = ixp.to_dict()
        assert d["id"] == 31
        assert d["name"] == "AMS-IX"
        assert d["city"] == "Amsterdam"
        assert d["country"] == "NL"
        assert d["website"] == "https://www.ams-ix.net/"
        assert d["participant_count"] == 900

    def test_ixp_from_dict(self):
        """Test creating IXP from dictionary."""
        data = {
            "id": 31,
            "name": "AMS-IX",
            "city": "Amsterdam",
            "country": "NL",
            "website": "https://www.ams-ix.net/",
            "participant_count": 900,
        }
        ixp = IXP.from_dict(data)
        assert ixp.id == 31
        assert ixp.name == "AMS-IX"
        assert ixp.participant_count == 900

    def test_ixp_from_dict_minimal(self):
        """Test creating IXP from dictionary with minimal fields."""
        data = {
            "id": 1,
            "name": "Test IXP",
            "city": "Test City",
            "country": "US",
        }
        ixp = IXP.from_dict(data)
        assert ixp.id == 1
        assert ixp.website is None
        assert ixp.participant_count is None

    def test_ixp_equality(self):
        """Test IXP equality comparison."""
        ixp1 = IXP(id=1, name="Test IXP", city="Test City", country="US")
        ixp2 = IXP(id=1, name="Test IXP", city="Test City", country="US")
        assert ixp1 == ixp2


class TestNetwork:
    """Tests for Network dataclass."""

    def test_create_basic_network(self):
        """Test creating a Network with required fields."""
        network = Network(
            asn=15169,
            name="Google LLC",
        )
        assert network.asn == 15169
        assert network.name == "Google LLC"

    def test_create_full_network(self):
        """Test creating a Network with all fields."""
        network = Network(
            asn=13335,
            name="Cloudflare, Inc.",
            info_type="NSP",
            website="https://www.cloudflare.com",
        )
        assert network.asn == 13335
        assert network.name == "Cloudflare, Inc."
        assert network.info_type == "NSP"
        assert network.website == "https://www.cloudflare.com"

    def test_network_defaults(self):
        """Test that optional fields have correct defaults."""
        network = Network(asn=64496, name="Test Network")
        assert network.info_type is None
        assert network.website is None

    def test_network_to_dict(self):
        """Test converting Network to dictionary."""
        network = Network(
            asn=13335,
            name="Cloudflare, Inc.",
            info_type="NSP",
            website="https://www.cloudflare.com",
        )
        d = network.to_dict()
        assert d["asn"] == 13335
        assert d["name"] == "Cloudflare, Inc."
        assert d["info_type"] == "NSP"
        assert d["website"] == "https://www.cloudflare.com"

    def test_network_from_dict(self):
        """Test creating Network from dictionary."""
        data = {
            "asn": 13335,
            "name": "Cloudflare, Inc.",
            "info_type": "NSP",
            "website": "https://www.cloudflare.com",
        }
        network = Network.from_dict(data)
        assert network.asn == 13335
        assert network.name == "Cloudflare, Inc."

    def test_network_from_dict_minimal(self):
        """Test creating Network from dictionary with minimal fields."""
        data = {"asn": 64496, "name": "Test Network"}
        network = Network.from_dict(data)
        assert network.asn == 64496
        assert network.info_type is None

    def test_network_equality(self):
        """Test Network equality comparison."""
        net1 = Network(asn=15169, name="Google LLC")
        net2 = Network(asn=15169, name="Google LLC")
        assert net1 == net2


class TestIXPPresence:
    """Tests for IXPPresence dataclass."""

    def test_create_basic_presence(self):
        """Test creating an IXPPresence with required fields."""
        presence = IXPPresence(
            asn=15169,
            ixp_id=31,
            ixp_name="AMS-IX",
        )
        assert presence.asn == 15169
        assert presence.ixp_id == 31
        assert presence.ixp_name == "AMS-IX"

    def test_create_full_presence(self):
        """Test creating an IXPPresence with all fields."""
        presence = IXPPresence(
            asn=15169,
            ixp_id=31,
            ixp_name="AMS-IX",
            ipaddr4="80.249.208.1",
            ipaddr6="2001:7f8:1::a501:5169:1",
            speed=100000,
        )
        assert presence.asn == 15169
        assert presence.ixp_id == 31
        assert presence.ixp_name == "AMS-IX"
        assert presence.ipaddr4 == "80.249.208.1"
        assert presence.ipaddr6 == "2001:7f8:1::a501:5169:1"
        assert presence.speed == 100000

    def test_presence_defaults(self):
        """Test that optional fields have correct defaults."""
        presence = IXPPresence(asn=64496, ixp_id=1, ixp_name="Test IXP")
        assert presence.ipaddr4 is None
        assert presence.ipaddr6 is None
        assert presence.speed is None

    def test_presence_to_dict(self):
        """Test converting IXPPresence to dictionary."""
        presence = IXPPresence(
            asn=15169,
            ixp_id=31,
            ixp_name="AMS-IX",
            ipaddr4="80.249.208.1",
            ipaddr6="2001:7f8:1::a501:5169:1",
            speed=100000,
        )
        d = presence.to_dict()
        assert d["asn"] == 15169
        assert d["ixp_id"] == 31
        assert d["ixp_name"] == "AMS-IX"
        assert d["ipaddr4"] == "80.249.208.1"
        assert d["ipaddr6"] == "2001:7f8:1::a501:5169:1"
        assert d["speed"] == 100000

    def test_presence_from_dict(self):
        """Test creating IXPPresence from dictionary."""
        data = {
            "asn": 15169,
            "ixp_id": 31,
            "ixp_name": "AMS-IX",
            "ipaddr4": "80.249.208.1",
            "ipaddr6": "2001:7f8:1::a501:5169:1",
            "speed": 100000,
        }
        presence = IXPPresence.from_dict(data)
        assert presence.asn == 15169
        assert presence.ixp_id == 31
        assert presence.speed == 100000

    def test_presence_from_dict_minimal(self):
        """Test creating IXPPresence from dictionary with minimal fields."""
        data = {"asn": 64496, "ixp_id": 1, "ixp_name": "Test IXP"}
        presence = IXPPresence.from_dict(data)
        assert presence.asn == 64496
        assert presence.ipaddr4 is None

    def test_presence_equality(self):
        """Test IXPPresence equality comparison."""
        p1 = IXPPresence(asn=15169, ixp_id=31, ixp_name="AMS-IX")
        p2 = IXPPresence(asn=15169, ixp_id=31, ixp_name="AMS-IX")
        assert p1 == p2

    def test_presence_speed_in_mbps(self):
        """Test that speed is in Mbps."""
        presence = IXPPresence(
            asn=15169,
            ixp_id=31,
            ixp_name="AMS-IX",
            speed=100000,  # 100 Gbps
        )
        assert presence.speed == 100000
