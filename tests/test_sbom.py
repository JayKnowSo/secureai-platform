from click.testing import CliRunner
from secureai.cli import cli


def test_sbom_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["sbom", "--help"])
    assert result.exit_code == 0


def test_sbom_requires_path():
    runner = CliRunner()
    result = runner.invoke(cli, ["sbom"])
    assert result.exit_code != 0


def test_sbom_invalid_path_raises_error():
    runner = CliRunner()
    result = runner.invoke(cli, ["sbom", "--path", "/nonexistent/path", "--format", "cyclonedx-json"])
    assert result.exit_code != 0
    assert "invalid" in result.output.lower() or "error" in result.output.lower()


def test_sbom_generates_json_output(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["sbom", "--path", str(tmp_path), "--format", "cyclonedx-json"])
    assert result.exit_code == 0
    assert "cyclonedx" in result.output.lower() or "bom" in result.output.lower()


def test_sbom_generates_xml_output(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["sbom", "--path", str(tmp_path), "--format", "cyclonedx-xml"])
    assert result.exit_code == 0


def test_sbom_output_contains_components(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nclick==8.1.7\n")
    runner = CliRunner()
    result = runner.invoke(cli, ["sbom", "--path", str(tmp_path), "--format", "cyclonedx-json"])
    assert result.exit_code == 0
    assert "components" in result.output.lower() or "requests" in result.output.lower()
