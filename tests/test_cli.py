import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from docker_vuln_patcher.cli import derive_patched_tag, parse_image_reference


class ImageReferenceParsingTests(unittest.TestCase):
    def test_parse_image_with_registry_port_and_tag(self):
        repo, tag = parse_image_reference("localhost:5000/team/app:1.2.3")
        self.assertEqual(repo, "localhost:5000/team/app")
        self.assertEqual(tag, "1.2.3")

    def test_parse_image_without_tag_defaults_latest(self):
        repo, tag = parse_image_reference("registry.internal:5000/ns/app")
        self.assertEqual(repo, "registry.internal:5000/ns/app")
        self.assertEqual(tag, "latest")

    def test_digest_reference_rejected(self):
        with self.assertRaises(ValueError):
            parse_image_reference("repo/app@sha256:abcdef")

    def test_derive_patched_tag_uses_existing_tag(self):
        value = derive_patched_tag("localhost:5000/team/app:1.2.3", "-patched")
        self.assertEqual(value, "localhost:5000/team/app:1.2.3-patched")


if __name__ == "__main__":
    unittest.main()
