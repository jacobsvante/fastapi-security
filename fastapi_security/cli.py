"""fastapi_security command-line interface"""

import argparse
import sys
import textwrap
from getpass import getpass
from typing import Optional, Sequence, Text

from fastapi_security.basic import generate_digest


def _wrap_paragraphs(s):
    paragraphs = s.strip().split("\n\n")
    wrapped_paragraphs = [
        "\n".join(textwrap.wrap(paragraph)) for paragraph in paragraphs
    ]
    return "\n\n".join(wrapped_paragraphs)


main_parser = argparse.ArgumentParser(
    description=_wrap_paragraphs(__doc__),
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
subcommand_parsers = main_parser.add_subparsers(
    help="Specify a sub-command",
    dest="subcommand",
    # This would remove the need to manually print an error message if
    # subcommand is not specified, but it is only available for Python 3.7+
    #
    # required=True,
)

gendigest_description = """
Generate digest for basic_auth_with_digest credentials.

Example:

$ fastapi-security gendigest --salt=very-strong-salt
Password:
Confirm password:

Here is your digest:
0jFS-cNapwQf_lpyULF7_hEelbl_zreNVHbxqKwKIFmPRQ09bYTEDQLrr_UEWZc9fdYFiU5F3il3rovJQ_UEpg==

$ cat fastapi_security_conf.py
from fastapi_security import FastAPISecurity

security = FastAPISecurity()
security.init_basic_auth_with_digest(
    [
        {'user': 'me', 'password': '0jFS-cNapwQf_lpyULF7_hEelbl_zreNVHbxqKwKIFmPRQ09bYTEDQLrr_UEWZc9fdYFiU5F3il3rovJQ_UEpg=='}
    ],
    salt='very-strong-salt',
)
"""

gendigest_parser = subcommand_parsers.add_parser(
    "gendigest",
    description=gendigest_description,
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
gendigest_parser.add_argument(
    "--salt",
    help="Salt value used in fastapi_security configuration.",
    required=True,
)


def gendigest(parsed_args):
    # if not parsed_args.salt:
    #     print("Cannot generate digest: --salt must be non-empty",
    #           file=sys.stderr)
    #     sys.exit(1)

    password = getpass(prompt="Password: ")
    password_confirmation = getpass(prompt="Confirm password: ")

    if password != password_confirmation:
        print("Cannot generate digest: passwords don't match", file=sys.stderr)
        sys.exit(1)

    print("\nHere is your digest:", file=sys.stderr)
    print(generate_digest(password, salt=parsed_args.salt))


def main(args: Optional[Sequence[Text]] = None):
    parsed_args = main_parser.parse_args(args)
    if parsed_args.subcommand == "gendigest":
        return gendigest(parsed_args)

    main_parser.print_usage(file=sys.stderr)
    if not parsed_args.subcommand:
        # Error message mimicking that of Python 3.7+ where add_subcommand(...)
        # function has "required=True" kwarg.
        required_subcommand_msg = (
            "fastapi-security: error:"
            " the following arguments are required: subcommand"
        )
        print(required_subcommand_msg, file=sys.stderr)
    sys.exit(2)  # invalid usage: missing subcommand


if __name__ == "__main__":
    main()
