from services import identity_service


def test_user_creation_and_identity_lookup(app):
    with app.app_context():
        users = identity_service.list_users()
        assert len(users) == 3
        rahul = identity_service.get_user_by_student_id("23MIC0007")
        assert rahul is not None
        assert rahul["name"] == "Rahul Kumar"
        assert rahul["email"] == "rahul@student.local"
        assert rahul["public_key"]
        missing = identity_service.get_user_by_student_id("NO-SUCH-ID")
        assert missing is None


def test_seed_is_idempotent(app):
    from database import get_db, seed_demo_users
    from pathlib import Path

    with app.app_context():
        seed_demo_users(get_db(), Path(app.config["KEYS_DIR"]))
        seed_demo_users(get_db(), Path(app.config["KEYS_DIR"]))
        count = get_db().execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        assert count == 3
