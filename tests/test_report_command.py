"""Phase 6 tests for report metadata and the supported report CLI."""

import logging
import os
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from BadZure import cli
from src.cli import ReportCommand
from src.config_manager import ConfigManager
from src.entity_generator import EntityGenerator


_REPO = Path(__file__).resolve().parents[1]
_CHAINED = _REPO / "examples" / "chained"
_DATA = _REPO / "entity_data"


def _fixture(name):
    return str(_CHAINED / name)


def _command():
    command = ReportCommand()
    command.generator = EntityGenerator(data_dir=str(_DATA))
    return command


def test_report_metadata_is_optional_and_validated():
    manager = ConfigManager()

    assert manager.validate_report_config({}) == {}
    assert manager.validate_report_config({"report": {
        "title": "Contoso Lab",
        "lab_description": "Training environment",
        "organization_description": "Fictional organization",
    }})["title"] == "Contoso Lab"
    with pytest.raises(ValueError, match="must be a mapping"):
        manager.validate_report_config({"report": "Contoso"})
    with pytest.raises(ValueError, match="unknown field.*titel"):
        manager.validate_report_config({"report": {"titel": "Typo"}})
    with pytest.raises(ValueError, match="must be strings.*title"):
        manager.validate_report_config({"report": {"title": 42}})


def test_command_uses_metadata_and_explicit_output(tmp_path):
    source = yaml.safe_load(Path(_fixture("chained_kv_theft.yml")).read_text())
    source["report"] = {
        "title": "Contoso Identity Lab",
        "lab_description": "Purple-team exercise.",
        "organization_description": "Contoso training tenant.",
    }
    config = tmp_path / "lab.yml"
    config.write_text(yaml.safe_dump(source), encoding="utf-8")
    output = tmp_path / "custom.html"

    assert _command().execute(str(config), str(output), open_browser=False) == 0
    html = output.read_text(encoding="utf-8")
    assert "Contoso Identity Lab" in html
    assert "Purple-team exercise." in html
    assert "Contoso training tenant." in html
    assert "posture-kv_theft" in html
    assert "attack-kv_theft" in html


def test_missing_metadata_uses_deterministic_descriptions(tmp_path):
    output = tmp_path / "baseline.html"

    assert _command().execute(
        _fixture("chained_org_baseline.yml"), str(output), open_browser=False,
    ) == 0
    html = output.read_text(encoding="utf-8")
    assert "BadZure lab: chained_org_baseline.yml" in html
    assert "This lab contains" in html
    assert "0 enabled attack path(s)" in html
    assert "The organization contains" in html


def test_explicit_empty_descriptions_are_not_replaced(tmp_path):
    source = yaml.safe_load(Path(_fixture("chained_org_baseline.yml")).read_text())
    source["report"] = {"lab_description": "", "organization_description": ""}
    config = tmp_path / "lab.yml"
    config.write_text(yaml.safe_dump(source), encoding="utf-8")
    output = tmp_path / "baseline.html"

    assert _command().execute(str(config), str(output), open_browser=False) == 0
    html = output.read_text(encoding="utf-8")
    assert "This lab contains" not in html
    assert "The organization contains" not in html


@pytest.mark.parametrize("fixture", [
    "chained_org_baseline.yml",       # baseline only
    "chained_kv_theft.yml",           # macro, single path
    "chained_apex.yml",               # explicit, reachable
    "chained_fullstack.yml",          # multi-path
    "chained_unreachable.yml",        # unreachable but reportable
])
def test_representative_configs_generate_without_azure(fixture, tmp_path):
    output = tmp_path / f"{Path(fixture).stem}.html"

    assert _command().execute(
        _fixture(fixture), str(output), open_browser=False,
    ) == 0
    assert output.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


@pytest.mark.parametrize("body", [
    "report: [broken\n",
    "report: {title: 123}\nbaseline: {identities: {users: 1}}\n",
    "report: {unknown: value}\nbaseline: {identities: {users: 1}}\n",
])
def test_invalid_yaml_or_metadata_exits_two_without_output(body, tmp_path):
    config = tmp_path / "bad.yml"
    config.write_text(body, encoding="utf-8")
    output = tmp_path / "report.html"

    assert _command().execute(str(config), str(output), open_browser=False) == 2
    assert not output.exists()


def test_atomic_replace_failure_preserves_existing_report(monkeypatch, tmp_path):
    output = tmp_path / "report.html"
    output.write_text("previous complete report", encoding="utf-8")

    def fail_replace(source, destination):
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    assert _command().execute(
        _fixture("chained_kv_theft.yml"), str(output), open_browser=False,
    ) == 2
    assert output.read_text(encoding="utf-8") == "previous complete report"
    assert not list(tmp_path.glob(".report.html.*.tmp"))


def test_browser_failure_is_warning_not_command_failure(monkeypatch, caplog, tmp_path):
    monkeypatch.setattr("src.cli.webbrowser.open", lambda _uri: False)
    output = tmp_path / "report.html"

    with caplog.at_level(logging.WARNING):
        code = _command().execute(
            _fixture("chained_kv_theft.yml"), str(output), open_browser=True,
        )

    assert code == 0
    assert output.exists()
    assert "Could not open browser automatically" in caplog.text


def test_click_report_supports_default_output_and_no_open(monkeypatch):
    monkeypatch.setattr(
        "src.cli.EntityGenerator",
        lambda: EntityGenerator(data_dir=str(_DATA)),
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, [
            "report", "--config", _fixture("chained_kv_theft.yml"), "--no-open",
        ])

        assert result.exit_code == 0, result.output
        output = Path("chained_kv_theft.report.html")
        assert output.exists()
        assert "Key Vault" in output.read_text(encoding="utf-8")
