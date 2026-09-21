import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from runtime_security import (
    RuntimeConfigError,
    RuntimeConfigStore,
    create_session_token,
    hash_admin_token,
    verify_session_token,
)


class RuntimeConfigTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name) / "data"
        self.config_path = self.data_dir / "config.json"
        self.bootstrap_path = self.data_dir / "admin_token.txt"

    def tearDown(self):
        self.temp_dir.cleanup()

    def store(self, environ=None):
        return RuntimeConfigStore(
            self.config_path,
            self.bootstrap_path,
            environ={} if environ is None else environ,
        )

    def read_config(self):
        return json.loads(self.config_path.read_text(encoding="utf-8"))

    def test_legacy_environment_subscription_token_is_migrated(self):
        store = self.store({
            "SECRET_TOKEN": "existing-subscription-token",
            "ADMIN_TOKEN": "separate-admin-token",
        })

        config = store.load_or_create()

        self.assertEqual(config["schema_version"], 2)
        self.assertEqual(config["subscription_token"], "existing-subscription-token")
        self.assertTrue(store.verify_admin_token("separate-admin-token"))
        self.assertFalse(store.verify_admin_token("existing-subscription-token"))
        self.assertNotIn("admin_token", config)
        self.assertFalse(self.bootstrap_path.exists())

    def test_v1_file_migrates_subscription_token_without_reusing_it_for_admin(self):
        self.data_dir.mkdir(parents=True)
        self.config_path.write_text(
            json.dumps({"secret_token": "legacy-client-token"}),
            encoding="utf-8",
        )
        store = self.store({"ADMIN_TOKEN": "new-management-token"})

        config = store.load_or_create()

        self.assertEqual(config["subscription_token"], "legacy-client-token")
        self.assertTrue(store.verify_admin_token("new-management-token"))
        self.assertFalse(store.verify_admin_token("legacy-client-token"))
        self.assertNotIn("secret_token", self.read_config())

    def test_persisted_v2_config_wins_over_stale_environment(self):
        original = self.store({
            "SECRET_TOKEN": "persisted-subscription-token",
            "ADMIN_TOKEN": "persisted-management-token",
        })
        original.load_or_create()

        reloaded = self.store({
            "SECRET_TOKEN": "stale-subscription-token",
            "ADMIN_TOKEN": "stale-management-token",
        })
        config = reloaded.load_or_create()

        self.assertEqual(config["subscription_token"], "persisted-subscription-token")
        self.assertTrue(reloaded.verify_admin_token("persisted-management-token"))
        self.assertFalse(reloaded.verify_admin_token("stale-management-token"))

    def test_missing_credentials_generate_separate_private_values(self):
        store = self.store()

        config = store.load_or_create()

        self.assertGreaterEqual(len(config["subscription_token"]), 32)
        self.assertTrue(self.bootstrap_path.exists())
        admin_token = self.bootstrap_path.read_text(encoding="utf-8").strip()
        self.assertGreaterEqual(len(admin_token), 32)
        self.assertNotEqual(admin_token, config["subscription_token"])
        self.assertTrue(store.verify_admin_token(admin_token))
        self.assertNotIn(admin_token, self.config_path.read_text(encoding="utf-8"))
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.bootstrap_path.stat().st_mode), 0o600)

    def test_public_default_subscription_token_is_rotated(self):
        store = self.store({
            "SECRET_TOKEN": "my_secret_token",
            "ADMIN_TOKEN": "separate-admin-token",
        })

        config = store.load_or_create()

        self.assertNotEqual(config["subscription_token"], "my_secret_token")

    def test_short_explicit_admin_token_fails_closed(self):
        store = self.store({"ADMIN_TOKEN": "short"})

        with self.assertRaises(RuntimeConfigError):
            store.load_or_create()

        self.assertFalse(self.config_path.exists())

    def test_new_config_rejects_reused_subscription_token_for_admin(self):
        store = self.store({
            "SECRET_TOKEN": "same-token-for-both-roles",
            "ADMIN_TOKEN": "same-token-for-both-roles",
        })

        with self.assertRaises(RuntimeConfigError):
            store.load_or_create()

        self.assertFalse(self.config_path.exists())

    def test_updates_reject_reusing_the_other_credential(self):
        store = self.store({
            "SECRET_TOKEN": "subscription-token-value",
            "ADMIN_TOKEN": "management-token-value",
        })
        store.load_or_create()

        with self.assertRaises(ValueError):
            store.update_subscription_token("management-token-value")
        with self.assertRaises(ValueError):
            store.update_admin_token("subscription-token-value")

    def test_persisted_v2_config_rejects_public_default_admin_token(self):
        self.data_dir.mkdir(parents=True)
        salt, token_hash = hash_admin_token("my_secret_token")
        self.config_path.write_text(
            json.dumps({
                "schema_version": 2,
                "subscription_token": "safe-subscription-token",
                "admin_token_salt": salt,
                "admin_token_hash": token_hash,
                "session_secret": "safe-session-secret",
            }),
            encoding="utf-8",
        )

        with self.assertRaises(RuntimeConfigError):
            self.store().load_or_create()

    def test_corrupt_persisted_config_fails_closed_without_using_environment(self):
        self.data_dir.mkdir(parents=True)
        self.config_path.write_text("{not-json", encoding="utf-8")
        store = self.store({
            "SECRET_TOKEN": "stale-subscription-token",
            "ADMIN_TOKEN": "stale-management-token",
        })

        with self.assertRaises(RuntimeConfigError):
            store.load_or_create()

        self.assertEqual(self.config_path.read_text(encoding="utf-8"), "{not-json")

    def test_admin_rotation_invalidates_existing_sessions(self):
        store = self.store({
            "SECRET_TOKEN": "subscription-token-value",
            "ADMIN_TOKEN": "initial-management-token",
        })
        store.load_or_create()
        old_session = store.create_session(3600)

        store.update_admin_token("replacement-management-token")

        self.assertFalse(store.verify_admin_token("initial-management-token"))
        self.assertTrue(store.verify_admin_token("replacement-management-token"))
        self.assertFalse(store.verify_session(old_session, 3600))

    def test_signed_session_rejects_tampering_and_expiry(self):
        token = create_session_token("session-secret", ttl_seconds=60, now=100)

        self.assertTrue(verify_session_token(token, "session-secret", 60, now=120))
        self.assertFalse(verify_session_token(token + "x", "session-secret", 60, now=120))
        self.assertFalse(verify_session_token(token, "session-secret", 60, now=161))


if __name__ == "__main__":
    unittest.main()
