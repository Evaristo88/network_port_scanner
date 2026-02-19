import unittest

from agent_discovery import cidr_from_ip_netmask


class TestCidrFromIpNetmask(unittest.TestCase):
    def test_cidr_from_ip_netmask(self) -> None:
        cidr = cidr_from_ip_netmask("192.168.10.5", "255.255.255.0")
        self.assertEqual(cidr, "192.168.10.0/24")


if __name__ == "__main__":
    unittest.main()
