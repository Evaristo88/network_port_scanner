import unittest

from agent_inventory import _parse_arp_line


class TestAgentInventory(unittest.TestCase):
    def test_parse_arp_line_valid(self) -> None:
        line = "192.168.1.10 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0"
        self.assertEqual(_parse_arp_line(line), ("192.168.1.10", "aa:bb:cc:dd:ee:ff"))

    def test_parse_arp_line_ignores_empty_mac(self) -> None:
        line = "192.168.1.10 0x1 0x2 00:00:00:00:00:00 * eth0"
        self.assertIsNone(_parse_arp_line(line))

    def test_parse_arp_line_invalid(self) -> None:
        self.assertIsNone(_parse_arp_line("bad"))


if __name__ == "__main__":
    unittest.main()
