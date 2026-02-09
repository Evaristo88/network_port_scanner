import unittest

from port_scanner import build_ip_list, build_port_list, get_top_ports, parse_ports


class TestParsePorts(unittest.TestCase):
    def test_single_port(self) -> None:
        self.assertEqual(parse_ports("80"), [80])

    def test_multiple_ports(self) -> None:
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_port_ranges(self) -> None:
        self.assertEqual(parse_ports("8000-8002"), [8000, 8001, 8002])

    def test_mixed_ports(self) -> None:
        self.assertEqual(parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_reversed_range(self) -> None:
        self.assertEqual(parse_ports("5-3"), [3, 4, 5])

    def test_invalid_port_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("0")


class TestBuildIpList(unittest.TestCase):
    def test_start_end(self) -> None:
        self.assertEqual(
            build_ip_list("192.168.0.1", "192.168.0.3", None),
            ["192.168.0.1", "192.168.0.2", "192.168.0.3"],
        )

    def test_reversed_start_end(self) -> None:
        self.assertEqual(
            build_ip_list("192.168.0.3", "192.168.0.1", None),
            ["192.168.0.1", "192.168.0.2", "192.168.0.3"],
        )

    def test_cidr(self) -> None:
        self.assertEqual(
            build_ip_list(None, None, "192.168.1.0/30"),
            ["192.168.1.1", "192.168.1.2"],
        )


class TestTopPorts(unittest.TestCase):
    def test_top_ports_positive_count(self) -> None:
        top_ports = get_top_ports(5)
        self.assertEqual(len(top_ports), 5)

    def test_build_port_list_with_top_ports(self) -> None:
        ports = build_port_list(None, 3)
        self.assertEqual(len(ports), 3)

    def test_build_port_list_combines_sources(self) -> None:
        ports = build_port_list("80,443", 3)
        self.assertIn(80, ports)
        self.assertIn(443, ports)


if __name__ == "__main__":
    unittest.main()
