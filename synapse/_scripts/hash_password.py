#!/usr/bin/env python

import argparse
import getpass
import sys
import unicodedata

import bcrypt
import yaml


def prompt_for_pass() -> str:
    password = getpass.getpass("Password: ")

    if not password:
        raise Exception("Password cannot be blank.")

    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        raise Exception("Passwords do not match.")

    return password


def main() -> None:
    bcrypt_rounds = 12
    password_pepper = ""

    parser = argparse.ArgumentParser(
        description=(
            "Calculate the hash of a new password, so that passwords can be reset"
        )
    )
    parser.add_argument(
        "-p",
        "--password",
        default=None,
        help="New password for user. Will prompt if omitted.",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=argparse.FileType("r"),
        help=(
            "Path to server config file. "
            "Used to read in bcrypt_rounds and password_pepper."
        ),
        required=True,
    )

    args = parser.parse_args()
    config = yaml.safe_load(args.config)
    bcrypt_rounds = config.get("bcrypt_rounds", bcrypt_rounds)
    password_config = config.get("password_config", None) or {}
    password_pepper = password_config.get("pepper", password_pepper)
    password = args.password

    if not password:
        password = prompt_for_pass()

    # On Python 2, make sure we decode it to Unicode before we normalise it
    if isinstance(password, bytes):
        try:
            password = password.decode(sys.stdin.encoding)
        except UnicodeDecodeError:
            print(
                "ERROR! Your password is not decodable using your terminal encoding (%s)."
                % (sys.stdin.encoding,)
            )

    pw = unicodedata.normalize("NFKC", password)

    hashed = bcrypt.hashpw(
        pw.encode("utf8") + password_pepper.encode("utf8"),
        bcrypt.gensalt(bcrypt_rounds),
    ).decode("ascii")

    print(hashed)


if __name__ == "__main__":
    main()
