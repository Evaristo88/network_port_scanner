import unittest

from port_scanner import build_ip_list, parse_ports


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


if __name__ == "__main__":
    unittest.main()
