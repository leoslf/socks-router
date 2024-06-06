from click.testing import CliRunner

from socks_router.cli import cli

def test_cli():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0