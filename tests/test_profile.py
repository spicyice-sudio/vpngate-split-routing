import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).parents[1] / 'libexec/meta-vpngate-scan.py'
spec = importlib.util.spec_from_file_location('scanner', path)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ProfileTests(unittest.TestCase):
    source = (
        'client\r\nproto udp\r\nremote relay.example 1194\r\n'
        'redirect-gateway def1\r\nup /example.sh\r\n'
        '<ca>\r\nTEST CERTIFICATE\r\n</ca>\r\n'
    )

    def test_routes_and_scripts_are_removed(self):
        profile = scanner.sanitize(self.source, '8.8.8.8', 'vgmeta0')
        self.assertIn('remote 8.8.8.8 1194', profile.splitlines())
        self.assertIn('route-nopull', profile.splitlines())
        self.assertIn('route-noexec', profile.splitlines())
        self.assertIn('remote-cert-tls server', profile.splitlines())
        self.assertIn('<ca>\nTEST CERTIFICATE\n</ca>', profile)
        self.assertNotIn('redirect-gateway def1', profile)
        self.assertNotIn('/example.sh', profile)
        self.assertEqual(scanner.sanitize(profile, '8.8.8.8', 'vgmeta0'), profile)

    def test_malformed_inline_blocks_are_rejected(self):
        fixtures = [
            self.source.replace('</ca>', '<key>\n</ca>'),
            self.source.replace('</ca>', '</ca> up /example.sh'),
            self.source + '<ca>\nSECOND CERTIFICATE\n</ca>\n',
        ]
        for source in fixtures:
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    scanner.sanitize(source, '8.8.8.8', 'vgmeta0')

    def test_non_public_endpoints_are_rejected(self):
        for ip in ('127.0.0.1', '224.0.0.1', '192.168.1.1'):
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    scanner.sanitize(self.source, ip, 'vgmeta0')


if __name__ == '__main__':
    unittest.main()
