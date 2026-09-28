"""The public corpus must keep its documented policy outcomes reproducible."""

import unittest

from scripts.run_corpus import run_corpus


class CorpusTest(unittest.TestCase):
    def test_synthetic_attacks(self):
        self.assertEqual(run_corpus(), [])
