from __future__ import annotations
import importlib.util, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("nobledns_comparator_differential",ROOT/"tools"/"comparator_differential.py")
module=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(module)
class ComparatorDifferentialTests(unittest.TestCase):
 def test_supported_exact_differences_and_unsupported_visibility(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp); n=root/"n.txt"; o=root/"o.txt"
   n.write_text("||shared.example^\n||noble-only.example^\n",encoding="utf-8")
   o.write_text("||shared.example^\n||other-only.example^\n||unsupported.example^$third-party\n",encoding="utf-8")
   r=module.compare(n,o,"test","https://example.test/list")["supported_syntax_subset"]
   self.assertEqual(r["exact_shared_blocks"],1); self.assertEqual(r["nobledns_only_blocks"],1)
   self.assertEqual(r["comparator_only_blocks"],1); self.assertEqual(r["comparator_unsupported_lines"],1)
   self.assertIn("$third-party",r["comparator_unsupported_examples"][0])
 def test_exceptions_are_reported_separately(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp); n=root/"n.txt"; o=root/"o.txt"
   n.write_text("@@||safe.example^\n||ads.example^\n",encoding="utf-8")
   o.write_text("@@||safe.example^\n@@||safe2.example^\n||ads.example^\n",encoding="utf-8")
   r=module.compare(n,o,"test","https://example.test/list")["supported_syntax_subset"]
   self.assertEqual(r["exact_shared_exceptions"],1); self.assertEqual(r["comparator_only_exceptions"],1)
   self.assertEqual(r["exact_shared_blocks"],1)
if __name__=="__main__": unittest.main()
