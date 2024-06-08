import logging

import pytest
import click.testing

from collections.abc import Iterator

from pathlib import Path

from socks_router.cli import cli

logger = logging.getLogger(__name__)

keyboard_interrupt = "\x03"

empty_logging_config = """version: 1"""


def describe_cli():
    @pytest.fixture
    def runner(capsys: pytest.CaptureFixture[str]) -> Iterator[click.testing.CliRunner]:
        """
        Convenience fixture to return a click.CliRunner for cli testing
        """

        class CliRunner(click.testing.CliRunner):
            """Override CliRunner to disable capsys"""

            def invoke(self, *args, **kwargs) -> click.testing.Result:
                # Way to fix https://github.com/pallets/click/issues/824
                with capsys.disabled():
                    result = super().invoke(*args, **kwargs)
                return result

        yield CliRunner()

    def when_no_logging_config():
        def it_should_not_fail(mocker, runner):
            mocker.patch("socks_router.cli.SocksRouter.serve_forever", side_effect=SystemExit(0))

            with runner.isolated_filesystem():
                result = runner.invoke(cli, env={"SOCKS_ROUTER_ROUTES": ""}, catch_exceptions=False)
                assert not result.exception
                assert result.exit_code == 0

    def when_there_is_logging_file():
        @pytest.mark.parametrize(
            "logging_config,filename",
            [
                (empty_logging_config, "logging.yaml"),
                (empty_logging_config, "foo.bar.yaml"),
            ],
        )
        def it_should_not_fail(mocker, runner, logging_config, filename):
            mocker.patch("socks_router.cli.SocksRouter.serve_forever", side_effect=SystemExit(0))

            with runner.isolated_filesystem():
                Path(filename).write_text(logging_config)

                result = runner.invoke(cli, env={"LOGGING_CONFIG": filename, "SOCKS_ROUTER_ROUTES": ""})
                assert not result.exception
                assert result.exit_code == 0

    def when_routes_file_present():
        @pytest.mark.parametrize(
            "filename",
            [
                "routes",
            ],
        )
        def it_should_not_fail(mocker, runner, filename):
            mocker.patch("socks_router.cli.SocksRouter.serve_forever", side_effect=SystemExit(0))

            with runner.isolated_filesystem():
                Path(filename).write_text("")

                result = runner.invoke(cli, env={"SOCKS_ROUTER_ROUTES_FILE": filename})
                assert not result.exception
                assert result.exit_code == 0
