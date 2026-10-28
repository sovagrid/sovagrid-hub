# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import unittest
from pathlib import Path


class CaddyHeadersTests(unittest.TestCase):
    def test_public_site_disallows_embedding(self):
        source = (Path(__file__).parents[1] / "deploy" / "Caddyfile.example").read_text()
        self.assertIn('Content-Security-Policy "frame-ancestors \'none\'"', source)
        self.assertIn('X-Frame-Options "DENY"', source)


if __name__ == "__main__":
    unittest.main()
