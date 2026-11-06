"""Single-authentication SMB actions to the fixed, disposable Windows lab target."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import math
import time
from pathlib import Path


def parse_plan(accounts_csv: str, attempts_csv: str, gaps_csv: str):
    users = accounts_csv.split(",")
    actions = [a.split(":") for a in attempts_csv.split(",")]
    gaps = [] if not gaps_csv else [float(s) for s in gaps_csv.split(",")]
    if (
        not 1 <= len(users) <= 3
        or len(set(users)) != len(users)
        or not set(users) <= {"datn_lab01", "datn_lab02", "datn_lab03"}
        or not 1 <= len(actions) <= 64
        or any(len(a) != 2 or a[0] not in users or a[1] not in {"fail", "success"} for a in actions)
        or len(gaps) != len(actions) - 1
        or any(not math.isfinite(g) or not 0.7 <= g <= 300 for g in gaps)
        or sum(gaps) > 240
    ):
        raise ValueError("Invalid bounded disposable-account schedule")
    return users, actions, gaps


def run(
    actions,
    gaps,
    passwords,
    nonce,
    factory,
    session_error,
    *,
    clock=time.monotonic,
    sleep=time.sleep,
):
    previous = clock()
    for index, (user, expected) in enumerate(actions):
        scheduled = previous if index == 0 else previous + gaps[index - 1]
        remaining = scheduled - clock()
        if remaining > 0:
            sleep(remaining)
        if clock() - scheduled > 2:
            raise ValueError("SMB missed frozen schedule; abort run")
        previous = clock()
        conn = factory("WIN11-TARGET", "10.20.0.10", sess_port=445, timeout=4)
        authenticated = False
        try:
            password = passwords[user]
            if expected == "fail":
                password += "__DATN_WRONG_" + nonce
            try:
                conn.login(user, password, "", ntlmFallback=False)
                authenticated = True
                if expected != "success" or conn.isGuestSession():
                    raise ValueError("Unexpected successful/guest authentication")
            except session_error as exc:
                if expected != "fail" or exc.getErrorCode() not in {0xC000006D, 0xC000006A}:
                    raise ValueError("Authentication failed for an unexpected reason") from exc
            finally:
                password = None
            print(f"ACCOUNT_ATTEMPT_OK seq={index + 1} user={user} expected={expected}", flush=True)
        finally:
            try:
                if authenticated:
                    conn.logoff()
            finally:
                conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accounts-csv", required=True)
    parser.add_argument("--attempts-csv", required=True)
    parser.add_argument("--gaps-csv", required=True)
    parser.add_argument("--run-nonce", required=True)
    parser.add_argument("--pre-action-delay", type=float, default=0)
    parser.add_argument("--enrollment", action="store_true")
    args = parser.parse_args()
    if not math.isfinite(args.pre_action_delay) or not 0 <= args.pre_action_delay <= 5:
        raise ValueError("Invalid frozen pre-action delay")
    users, actions, gaps = parse_plan(args.accounts_csv, args.attempts_csv, args.gaps_csv)
    if args.enrollment and (
        len(actions) != len(users)
        or len(set(actions)) != len(users)
        or any(result != "success" for _, result in actions)
    ):
        raise ValueError("Enrollment permits one successful authentication per account only")
    import re

    if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", args.run_nonce):
        raise ValueError("Invalid run nonce")
    from impacket.smbconnection import SessionError, SMBConnection

    passwords = {user: getpass.getpass(f"Lab password for {user}: ") for user in users}
    print(f"ACCOUNT_READY count={len(actions)} nonce={args.run_nonce}", flush=True)
    input(
        "Confirm SOC enrollment capture cursor is open, then press Enter: "
        if args.enrollment
        else "Start SOC begin-action, then press Enter here: "
    )
    try:
        time.sleep(args.pre_action_delay)
        run(actions, gaps, passwords, args.run_nonce, SMBConnection, SessionError)
        time.sleep(5)
        print(f"ACCOUNT_ACTION_COMPLETE count={len(actions)}")
    finally:
        passwords.clear()


if __name__ == "__main__":
    # Optional JSON launcher keeps operators from manually retyping a schedule.
    import sys

    if len(sys.argv) == 4 and sys.argv[1] == "--frozen-file":
        raw = Path(sys.argv[2]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != sys.argv[3].lower():
            raise ValueError("Parameter export transport hash mismatch")
        document = json.loads(raw)
        p = document["scenario_parameters"]
        if p["transport"] != "smb" or p["execution_profile_version"] != "lab-action-profile-v1":
            raise ValueError("Not a frozen SMB profile")
        sys.argv = [
            sys.argv[0],
            "--accounts-csv",
            p["accounts_csv"],
            "--attempts-csv",
            p["attempts_csv"],
            "--gaps-csv",
            p["expected_intervals_seconds"],
            "--run-nonce",
            p["run_nonce"],
            "--pre-action-delay",
            str(p["pre_action_delay_seconds"]),
        ]
    main()
