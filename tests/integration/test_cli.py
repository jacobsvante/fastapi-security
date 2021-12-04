import subprocess
from unittest import mock

from fastapi_security import cli


def test_usage_output_without_params():
    result = subprocess.run(["fastapi-security"], capture_output=True)
    assert result.returncode == 2
    assert result.stdout.decode().splitlines() == []
    assert result.stderr.decode().splitlines() == [
        "usage: fastapi-security [-h] {gendigest} ...",
        "fastapi-security: error: the following arguments are required: subcommand",
    ]


def test_usage_with_help_param():
    result = subprocess.run(["fastapi-security", "-h"], capture_output=True)
    assert result.returncode == 0
    assert result.stdout.decode().splitlines() == [
        "usage: fastapi-security [-h] {gendigest} ...",
        "",
        "fastapi_security command-line interface",
        "",
        "positional arguments:",
        "  {gendigest}  Specify a sub-command",
        "",
        "optional arguments:",
        "  -h, --help   show this help message and exit",
    ]
    assert result.stderr.decode().splitlines() == []


def test_gendigest_without_params():
    result = subprocess.run(["fastapi-security", "gendigest"], capture_output=True)
    assert result.returncode == 2
    assert result.stdout.decode().splitlines() == []
    assert result.stderr.decode().splitlines() == [
        "usage: fastapi-security gendigest [-h] --salt SALT",
        "fastapi-security gendigest: error: the following arguments are required: --salt",
    ]


def test_gendigest_smoke_test(capsys, monkeypatch):
    # gendigest smoke test is performed not in a subprocess, because getpass
    # uses /dev/tty instead of stdin/stdout for security reasons, and it is
    # much more tricky to intercept it, so instead go for a simple monkeypatch.
    monkeypatch.setattr(cli, "getpass", mock.Mock(return_value="hello"))
    cli.main(["gendigest", "--salt=very-strong-salt"])
    captured = capsys.readouterr()
    assert (
        captured.out
        == "xRPfDaQHwpcXlzfWeR_uqOBTytcjEAUMv98SDnbHmpajmT_AxeJTHX6FyeM8H1T4otOe81PMWAOqAD5_tO4gYg==\n"
    )
    assert captured.err == "\nHere is your digest:\n"
