"""Command line interface for RepoLens."""
import dataclasses
import json
import os
import shutil
import tempfile
from typing import Optional

import typer

from . import fetch
from .pipeline import _optional, run_pipeline

app = typer.Typer(help="RepoLens: compare a published package with its source.")


@app.command()
def analyze(
    package: Optional[str] = typer.Argument(None, help="npm package name (optional with --tarball)"),
    version: Optional[str] = typer.Argument(None, help="package version (default: latest)"),
    tarball: Optional[str] = typer.Option(None, "--tarball", help="analyze a local .tgz instead of downloading"),
    source_dir: Optional[str] = typer.Option(None, "--source-dir", help="use a local source folder instead of git clone"),
    repo_url: Optional[str] = typer.Option(None, "--repo-url", help="override the repository URL"),
    out: str = typer.Option("reports", "--out", help="output directory"),
    keep: bool = typer.Option(False, "--keep", help="keep the temporary sandbox"),
) -> None:
    """Analyze one package version against its source repository."""
    workdir = tempfile.mkdtemp(prefix="repolens_")
    try:
        report = run_pipeline(package, version, workdir, tarball, source_dir, repo_url)
    except fetch.FetchError as e:
        typer.echo(f"[repolens] ERROR: {e}", err=True)
        raise typer.Exit(code=1)
    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)

    os.makedirs(out, exist_ok=True)
    report_mod = _optional("report")
    if report_mod and hasattr(report_mod, "write_reports"):
        report_mod.write_reports(report, out)  # Person C: report.json + report.html
    else:
        with open(os.path.join(out, "report.json"), "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(report), f, indent=2)

    c = report.metadata["file_counts"]
    typer.echo(f"[repolens] {report.package_name}@{report.version}  source ref: {report.commit_or_tag or 'NOT FOUND'}")
    typer.echo(f"[repolens] files: {c['identical']} identical, {c['modified']} modified, "
               f"{c['only_in_package']} only-in-package, {c['only_in_source']} only-in-source")
    for fd in report.findings[:30]:
        typer.echo(f"  [{fd.risk_level:6}] {fd.classification:11} {fd.file_path}  {','.join(fd.signals)}")
    if len(report.findings) > 30:
        typer.echo(f"  ... and {len(report.findings) - 30} more (see report.json)")
    typer.echo(f"[repolens] VERDICT: {report.overall_verdict} (risk {report.overall_risk_score}/100) -> {out}/")
    if report.overall_verdict == "SUSPICIOUS":
        raise typer.Exit(code=2)


@app.command()
def watch() -> None:
    """Watch a list of packages for new releases."""
    typer.echo("watch: not implemented yet")


@app.command()
def web(
    port: int = typer.Option(8000, "--port", "-p", help="Port for localhost server"),
) -> None:
    """Start the interactive RepoLens localhost web dashboard."""
    import socketserver
    from web_server import RepoLensHandler
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("0.0.0.0", port), RepoLensHandler)
    typer.echo(f"[repolens] Web dashboard running at http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        typer.echo("\n[repolens] Shutting down web server...")
        server.server_close()


if __name__ == "__main__":
    app()
