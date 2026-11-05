"""Unit tests for the 15-pair Ghera-style OWASP Mobile Top 10 Benchmark Suite."""

import unittest
from benchmarks.evaluate_benchmark import evaluate_all_pairs


class TestBenchmarkSuite(unittest.TestCase):
    def test_full_15_pair_benchmark_metrics(self):
        results = evaluate_all_pairs(use_llm=False)
        self.assertEqual(results["total_pairs"], 15)
        self.assertEqual(results["total_test_executions"], 30)

        m = results["overall_metrics"]
        self.assertEqual(m["TP"], 15)
        self.assertEqual(m["FP"], 0)
        self.assertEqual(m["TN"], 15)
        self.assertEqual(m["FN"], 0)
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 1.0)
        self.assertEqual(m["f1_score"], 1.0)
        self.assertEqual(m["plausibility_rate"], 100.0)


if __name__ == "__main__":
    unittest.main()
