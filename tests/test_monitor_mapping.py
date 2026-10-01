import unittest

from scripts.validate_dataset import valid_monitor_mapping


class MonitorMappingTests(unittest.TestCase):
    def test_new_names_do_not_require_historical_corpus_membership(self):
        for host, domain in [
            ("new-candidate.ye", "new-candidate.ye"),
            ("www.new-candidate.ye", "new-candidate.ye"),
            ("mail.new-candidate.com.ye", "new-candidate.com.ye"),
        ]:
            self.assertTrue(valid_monitor_mapping(host, domain))

    def test_invalid_or_incorrect_mappings_are_rejected(self):
        for host, domain in [
            ("foreign.example", "foreign.example"),
            ("www.new.ye", "other.ye"),
            ("www.new.com.ye", "com.ye"),
            ("WWW.new.ye", "new.ye"),
            ("bad label.ye", "bad label.ye"),
            (None, "new.ye"),
        ]:
            self.assertFalse(valid_monitor_mapping(host, domain))


if __name__ == "__main__":
    unittest.main()
