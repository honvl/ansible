"""Unit tests for the migrated legacy Ansible filter."""

import importlib.util
from pathlib import Path
import unittest


PLUGIN_PATH = Path(__file__).parents[1] / "filter_plugins" / "myfilters.py"
SPEC = importlib.util.spec_from_file_location("myfilters", PLUGIN_PATH)
assert SPEC is not None and SPEC.loader is not None
PLUGIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLUGIN)


class CustomSortTests(unittest.TestCase):
    def test_sorts_gigabit_and_ten_gigabit_interfaces(self):
        values = ["Te2/1", "Te1/2", "Gi1/1"]

        self.assertEqual(
            PLUGIN.sort_custom(values),
            ["Gi1/1", "Te1/2", "Te2/1"],
        )

    def test_registers_filter_with_ansible(self):
        self.assertIs(
            PLUGIN.FilterModule().filters()["sort_custom"],
            PLUGIN.sort_custom,
        )


if __name__ == "__main__":
    unittest.main()
