import unittest

from auth_rate_limit import LoginRateLimiter


class LoginRateLimiterTest(unittest.TestCase):
    def test_blocks_after_repeated_failures_and_recovers(self):
        limiter = LoginRateLimiter(max_failures=3, window_seconds=60, block_seconds=120)

        self.assertEqual(limiter.record_failure("client", now=10), 0)
        self.assertEqual(limiter.record_failure("client", now=20), 0)
        self.assertEqual(limiter.record_failure("client", now=30), 120)
        self.assertEqual(limiter.retry_after("client", now=31), 119)
        self.assertEqual(limiter.retry_after("client", now=151), 0)

    def test_successful_login_reset_clears_failures(self):
        limiter = LoginRateLimiter(max_failures=2)
        limiter.record_failure("client", now=10)

        limiter.reset("client")

        self.assertEqual(limiter.record_failure("client", now=11), 0)
        self.assertEqual(limiter.retry_after("client", now=11), 0)


if __name__ == "__main__":
    unittest.main()
