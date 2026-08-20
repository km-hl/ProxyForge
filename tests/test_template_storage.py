import ast
import logging
import os
import shutil
import tempfile
import unittest
from pathlib import Path


def load_initializer(name):
    source = Path(__file__).resolve().parents[1] / "main.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace = {
        "os": os,
        "shutil": shutil,
        "logger": logging.getLogger("template-storage-test"),
        "TEMPLATE_PATH": "",
        "LEGACY_TEMPLATE_PATH": "",
        "TEMPLATE_EXAMPLE_PATH": "",
        "CUSTOM_NODES_PATH": "",
        "LEGACY_CUSTOM_NODES_PATH": "",
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
    return namespace[name]


class TemplateStorageTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.runtime = root / "data" / "template.yaml"
        self.runtime.parent.mkdir()
        self.legacy = root / "template.yaml"
        self.example = root / "template.example.yaml"
        self.initialize = load_initializer("initialize_template_storage")
        self.initialize.__globals__.update({
            "TEMPLATE_PATH": str(self.runtime),
            "LEGACY_TEMPLATE_PATH": str(self.legacy),
            "TEMPLATE_EXAMPLE_PATH": str(self.example),
        })

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_existing_runtime_template_is_never_overwritten(self):
        self.runtime.write_text("source: runtime\n", encoding="utf-8")
        self.legacy.write_text("source: legacy\n", encoding="utf-8")

        result = self.initialize()

        self.assertEqual(result, str(self.runtime))
        self.assertEqual(self.runtime.read_text(encoding="utf-8"), "source: runtime\n")

    def test_legacy_template_is_migrated_before_example(self):
        self.legacy.write_text("source: legacy\n", encoding="utf-8")
        self.example.write_text("source: example\n", encoding="utf-8")

        result = self.initialize()

        self.assertEqual(result, str(self.runtime))
        self.assertEqual(self.runtime.read_text(encoding="utf-8"), "source: legacy\n")

    def test_new_install_is_initialized_from_example(self):
        self.example.write_text("source: example\n", encoding="utf-8")

        result = self.initialize()

        self.assertEqual(result, str(self.runtime))
        self.assertEqual(self.runtime.read_text(encoding="utf-8"), "source: example\n")

    def test_legacy_custom_nodes_are_migrated_to_data(self):
        runtime_nodes = self.runtime.parent / "custom_nodes.yaml"
        legacy_nodes = self.runtime.parent.parent / "custom_nodes.yaml"
        legacy_nodes.write_text("- name: legacy\n", encoding="utf-8")
        initialize_nodes = load_initializer("initialize_custom_nodes_storage")
        initialize_nodes.__globals__.update({
            "CUSTOM_NODES_PATH": str(runtime_nodes),
            "LEGACY_CUSTOM_NODES_PATH": str(legacy_nodes),
        })

        result = initialize_nodes()

        self.assertEqual(result, str(runtime_nodes))
        self.assertEqual(runtime_nodes.read_text(encoding="utf-8"), "- name: legacy\n")


if __name__ == "__main__":
    unittest.main()
