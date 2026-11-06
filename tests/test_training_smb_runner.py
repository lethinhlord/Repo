import pytest

from scripts.run_training_account_remote import parse_plan, run


class SessionError(Exception):
    def __init__(self, code):
        self.code = code

    def getErrorCode(self):
        return self.code


def test_smb_performs_one_auth_per_action_and_cleans_up_without_password_logs(capsys):
    users, actions, gaps = parse_plan("datn_lab01", "datn_lab01:fail,datn_lab01:success", "2")
    assert users == ["datn_lab01"]
    connections = []

    class Connection:
        def __init__(self, *args, **kwargs):
            assert args == ("WIN11-TARGET", "10.20.0.10")
            self.closed = 0
            self.logoffs = 0
            connections.append(self)

        def login(self, user, password, domain, ntlmFallback):
            assert domain == "" and ntlmFallback is False
            if "__DATN_WRONG_" in password:
                raise SessionError(0xC000006D)

        def isGuestSession(self):
            return False

        def logoff(self):
            self.logoffs += 1

        def close(self):
            self.closed += 1

    now = [0.0]
    run(
        actions,
        gaps,
        {"datn_lab01": "PRIVATE-UNIT"},
        "unitnonce123",
        Connection,
        SessionError,
        clock=lambda: now[0],
        sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
    )
    assert len(connections) == 2 and all(c.closed == 1 for c in connections)
    assert sum(c.logoffs for c in connections) == 1
    assert "PRIVATE-UNIT" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "users,actions,gaps",
    [
        ("administrator", "administrator:success", ""),
        ("datn_lab01", "datn_lab02:success", ""),
        ("datn_lab01", "datn_lab01:fail,datn_lab01:success", "NaN"),
        ("datn_lab01", "datn_lab01:fail,datn_lab01:success", "0"),
    ],
)
def test_invalid_smb_plan_rejected_before_credentials(users, actions, gaps):
    with pytest.raises(ValueError):
        parse_plan(users, actions, gaps)
