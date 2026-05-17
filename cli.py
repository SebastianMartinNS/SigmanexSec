#!/usr/bin/env python3
"""
cli.py — Security Assessment Platform CLI

Usage:
  python cli.py engage   — Create a new engagement (interactive wizard)
  python cli.py run      — Run the LLM agent on an engagement
  python cli.py status   — Show engagement status and findings
  python cli.py report   — Generate the final report
  python cli.py servers  — Start all MCP servers (for VS Code Copilot)
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))
from datetime import UTC

from core.logging import configure_logging, get_logger
from core.models import Engagement, EngagementCreate
from core.session_store import SessionStore

configure_logging(service="cli")
_log = get_logger("cli")

console = Console()
store = SessionStore(os.environ.get("SESSION_DB_PATH", "./sessions/assessments.db"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _on_message(role: str, text: str) -> None:
    colors = {
        "assistant":   "green",
        "tool_call":   "yellow",
        "tool_result": "dim cyan",
    }
    color = colors.get(role, "white")
    if role == "tool_call":
        console.print(f"\n[{color}]🔧 {text}[/{color}]")
    elif role == "tool_result":
        preview = text[:300] + ("…" if len(text) > 300 else "")
        console.print(f"[{color}]   → {preview}[/{color}]")
    else:
        console.print(Panel(text, title=f"[bold {color}]Agent[/]", border_style=color))


# ── engage command ────────────────────────────────────────────────────────────

@click.group()
def cli():
    """Security Assessment Platform — Ethical Red/Blue Team with LLM Orchestration."""
    pass


@cli.command()
def engage():
    """Interactive wizard to create a new security assessment engagement."""
    console.print(Panel(
        "[bold red]⚠️  AUTHORIZATION REQUIRED[/bold red]\n\n"
        "This platform performs active security testing.\n"
        "You MUST have explicit written authorization from the target owner\n"
        "before creating an engagement. Unauthorized testing is illegal.",
        title="[bold]Security Assessment Platform[/bold]",
        border_style="red",
    ))

    confirmed = click.confirm("\nDo you have written authorization for this assessment?", default=False)
    if not confirmed:
        console.print("[red]Aborted. Obtain authorization first.[/red]")
        sys.exit(1)

    console.print("\n[bold cyan]── New Engagement Setup ──[/bold cyan]\n")

    name      = click.prompt("Engagement name", default="Q2-2026 Internal Assessment")
    client    = click.prompt("Client / organization")
    tester    = click.prompt("Lead tester name")
    auth_ref  = click.prompt("Authorization document reference (e.g. email ID, doc path, ticket #)")
    cidrs     = click.prompt("Scope CIDRs (comma-separated, e.g. 10.0.0.0/24)", default="")
    domains   = click.prompt("Scope domains (comma-separated)", default="")
    urls      = click.prompt("Scope URLs (comma-separated)", default="")

    # ── Identity / OSINT scope (Phase 8) ────────────────────────────────
    console.print(
        "\n[bold yellow]Identity / OSINT scope (optional)[/bold yellow] "
        "\u2014 leave blank if not authorized to perform person-OSINT."
    )
    emails    = click.prompt("Scope emails (comma-separated)", default="")
    usernames = click.prompt("Scope usernames (comma-separated)", default="")
    persons   = click.prompt("Scope real persons / full names (comma-separated)", default="")
    handles   = click.prompt("Scope social handles (comma-separated, '@' optional)", default="")
    has_identity = any(
        s.strip() for s in (emails + "," + usernames + "," + persons + "," + handles).split(",")
    )
    osint_auth_ref = ""
    if has_identity:
        osint_auth_ref = click.prompt(
            "OSINT authorization document reference (REQUIRED for identity scope)"
        )
        if not osint_auth_ref.strip():
            console.print(
                "[red]Identity scope set but OSINT authorization is empty \u2014 aborting.[/red]"
            )
            sys.exit(2)

    roe       = click.prompt(
        "Rules of Engagement",
        default="No DoS. No data exfiltration. Business hours only. Stop if production impact."
    )

    eng_create = EngagementCreate(
        name=name, client=client, tester=tester,
        authorization_ref=auth_ref,
        scope_cidrs=[c.strip() for c in cidrs.split(",") if c.strip()],
        scope_domains=[d.strip() for d in domains.split(",") if d.strip()],
        scope_urls=[u.strip() for u in urls.split(",") if u.strip()],
        scope_emails=[s.strip() for s in emails.split(",") if s.strip()],
        scope_usernames=[s.strip() for s in usernames.split(",") if s.strip()],
        scope_persons=[s.strip() for s in persons.split(",") if s.strip()],
        scope_social_handles=[s.strip() for s in handles.split(",") if s.strip()],
        osint_authorization_ref=osint_auth_ref,
        rules_of_engagement=roe,
    )
    eng = Engagement(**eng_create.model_dump())

    async def _create():
        await store.init()
        await store.create_engagement(eng)

    asyncio.run(_create())
    console.print("\n[bold green]✅ Engagement created![/bold green]")
    console.print(f"   ID: [yellow]{eng.id}[/yellow]")
    console.print(f"   Scope CIDRs: {eng.scope_cidrs}")
    if eng.scope_emails or eng.scope_usernames or eng.scope_persons or eng.scope_social_handles:
        console.print(
            f"   Identity scope: emails={eng.scope_emails} usernames={eng.scope_usernames} "
            f"persons={eng.scope_persons} handles={eng.scope_social_handles}"
        )
        console.print(f"   OSINT auth ref: [yellow]{eng.osint_authorization_ref}[/yellow]")
    console.print(f"\nNext: [bold]python cli.py run --engagement {eng.id} --objective 'Perform full assessment'[/bold]")


# ── list command ──────────────────────────────────────────────────────────────

@cli.command("list")
def list_engagements():
    """List all engagements."""

    async def _list():
        await store.init()
        return await store.list_engagements()

    engs = asyncio.run(_list())
    if not engs:
        console.print("[yellow]No engagements found. Run: python cli.py engage[/yellow]")
        return

    table = Table(title="Engagements", show_lines=True)
    table.add_column("ID", style="dim", width=36)
    table.add_column("Name", style="bold cyan")
    table.add_column("Client")
    table.add_column("Status", style="green")
    table.add_column("Phase")
    table.add_column("Created")

    for e in engs:
        table.add_row(
            e.id, e.name, e.client,
            e.status.value, e.current_phase.value,
            e.created_at.strftime("%Y-%m-%d"),
        )
    console.print(table)


# ── run command ───────────────────────────────────────────────────────────────

@cli.command()
@click.option("--engagement", "-e", required=True, help="Engagement ID")
@click.option("--objective",  "-o", required=True, help="Assessment objective")
@click.option("--max-iter",         default=50,    help="Max LLM iterations")
@click.option("--mode", "-m",
              type=click.Choice(["planning", "execution", "step"]),
              default="execution", help="Agent run mode")
def run(engagement: str, objective: str, max_iter: int, mode: str):
    """
    Run the LLM agent on an engagement.

    Example:
        python cli.py run -e <engagement_id> -o "Find all vulnerabilities on 10.0.0.1"
    """
    console.print(Panel(
        f"[bold cyan]Engagement:[/bold cyan] {engagement}\n"
        f"[bold cyan]Objective:[/bold cyan] {objective}\n"
        f"[bold cyan]Mode:[/bold cyan] {mode}\n"
        f"[bold cyan]LLM:[/bold cyan] {os.environ.get('LLM_PROVIDER','anthropic')} / {os.environ.get('LLM_MODEL', 'claude-opus-4-5')}",
        title="[bold]Starting Security Assessment Agent[/bold]",
        border_style="cyan",
    ))

    from agent.orchestrator import run_agent  # late import to avoid startup cost
    from agent.run_modes import RunMode

    async def _run():
        return await run_agent(
            engagement_id=engagement,
            objective=objective,
            on_message=_on_message,
            mode=RunMode(mode),
        )

    try:
        result = asyncio.run(_run())
        console.print(Panel(
            result or "Assessment complete.",
            title="[bold green]Final Agent Response[/bold green]",
            border_style="green",
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Assessment interrupted by user.[/yellow]")


# ── status command ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--engagement", "-e", required=True, help="Engagement ID")
def status(engagement: str):
    """Show current status of an engagement: hosts, findings summary."""

    async def _status():
        await store.init()
        eng      = await store.get_engagement(engagement)
        hosts    = await store.get_hosts(engagement)
        findings = await store.get_findings(engagement)
        creds    = await store.get_credentials(engagement)
        return eng, hosts, findings, creds

    eng, hosts, findings, creds = asyncio.run(_status())

    if not eng:
        console.print(f"[red]Engagement '{engagement}' not found.[/red]")
        return

    console.print(Panel(
        f"[bold]Name:[/bold] {eng.name}\n"
        f"[bold]Client:[/bold] {eng.client}\n"
        f"[bold]Status:[/bold] {eng.status.value}\n"
        f"[bold]Phase:[/bold] {eng.current_phase.value}\n"
        f"[bold]Scope:[/bold] {', '.join(eng.scope_cidrs + eng.scope_domains) or 'Not defined'}",
        title="[bold cyan]Engagement Status[/bold cyan]",
    ))

    # Hosts table
    if hosts:
        ht = Table(title=f"Discovered Hosts ({len(hosts)})", show_lines=True)
        ht.add_column("IP")
        ht.add_column("Hostname")
        ht.add_column("OS")
        ht.add_column("Open Ports")
        for h in hosts:
            ports = ", ".join(str(s.port) for s in h.services[:8])
            ht.add_row(h.ip, h.hostname or "-", h.os_guess or "?", ports)
        console.print(ht)

    # Findings table
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_colors = {"critical": "red", "high": "dark_orange", "medium": "yellow", "low": "cyan", "info": "dim"}

    if findings:
        ft = Table(title=f"Findings ({len(findings)})", show_lines=True)
        ft.add_column("Severity")
        ft.add_column("CVSS")
        ft.add_column("Title")
        ft.add_column("Category")
        ft.add_column("MITRE")

        sorted_findings = sorted(findings, key=lambda f: sev_order.index(f.severity.value))
        for f in sorted_findings:
            color = sev_colors.get(f.severity.value, "white")
            ft.add_row(
                f"[{color}]{f.severity.value.upper()}[/{color}]",
                str(f.cvss_score),
                f.title[:60],
                f.category.value,
                ", ".join(f.mitre_techniques[:2]),
            )
        console.print(ft)

    console.print(f"\n[bold]Credentials found:[/bold] {len(creds)}")


# ── report command ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--engagement", "-e", required=True, help="Engagement ID")
@click.option("--format", "fmt", default="markdown", type=click.Choice(["markdown", "json"]))
@click.option("--output", "-o", default="", help="Output file path (default: auto)")
def report(engagement: str, fmt: str, output: str):
    """Generate the full security assessment report (Red + Blue Team)."""

    async def _report():
        from mcp_servers.blueteam_server import generate_assessment_report
        return await generate_assessment_report(
            engagement_id=engagement,
            format_type=fmt,
        )

    console.print("[cyan]Generating report…[/cyan]")
    result = asyncio.run(_report())

    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        return

    saved = result.get("saved_to", "")
    summary = result.get("summary", {})

    console.print(Panel(
        f"[bold]Risk Level:[/bold] {summary.get('risk_level', 'N/A')}\n"
        f"[bold]Findings:[/bold] {summary.get('findings', 0)}\n"
        f"[bold]Hosts:[/bold] {summary.get('hosts', 0)}\n"
        f"[bold]Saved to:[/bold] {saved}",
        title="[bold green]Report Generated[/bold green]",
        border_style="green",
    ))

    if output:
        Path(output).write_text(result.get("report", ""), encoding="utf-8")
        console.print(f"[green]Also saved to: {output}[/green]")


# ── dashboard command ─────────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
@click.option("--reload", is_flag=True, help="Auto-reload (dev)")
@click.option("--cert", default="", help="TLS certificate file (PEM)")
@click.option("--key",  default="", help="TLS private key file (PEM)")
@click.option("--no-tls", is_flag=True, help="Force plain HTTP (loopback only — INSECURE).")
def dashboard(host: str, port: int, reload: bool, cert: str, key: str, no_tls: bool):
    """Launch the SAP Control Dashboard (FastAPI). HTTPS by default with auto-generated self-signed cert."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn not installed. pip install -r requirements.txt[/red]")
        return

    # Auto-generate self-signed cert under $SAP_STATE_DIR/tls/ if neither
    # --cert/--key nor --no-tls were provided. This makes HTTPS the default.
    if not no_tls and not (cert and key):
        cert, key = _ensure_self_signed_cert(host)

    if not (cert and key) and host not in ("127.0.0.1", "localhost"):
        console.print("[red]Refusing to bind a non-loopback host without TLS. Use --cert/--key.[/red]")
        return

    scheme = "https" if cert and key else "http"
    if scheme == "http":
        console.print("[yellow]WARNING: serving HTTP (no TLS). Use only on loopback.[/yellow]")

    console.print(Panel(
        f"[bold]Host:[/bold] {host}\n"
        f"[bold]Port:[/bold] {port}\n"
        f"[bold]URL:[/bold] {scheme}://{host}:{port}/\n"
        f"[bold]API docs:[/bold] {scheme}://{host}:{port}/docs\n\n"
        f"[yellow]Set dashboard.auth.user/password in config.yaml or via\n"
        f"SAP_DASHBOARD_USER / SAP_DASHBOARD_PASS env vars before opening.[/yellow]",
        title="[bold cyan]SAP Control Dashboard[/bold cyan]",
        border_style="cyan",
    ))
    uvicorn.run(
        "sap_dashboard.backend.app:app",
        host=host, port=port, reload=reload, log_level="info",
        ssl_certfile=cert or None, ssl_keyfile=key or None,
    )


def _ensure_self_signed_cert(host: str) -> tuple[str, str]:
    """Ensure a self-signed cert/key pair exists under $SAP_STATE_DIR/tls/.
    Returns ("","") if generation is unavailable (caller falls back to HTTP).
    """
    import os as _os
    state = _os.environ.get("SAP_STATE_DIR") or str(
        Path(_os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")) / "sap"
    )
    tls_dir = Path(state) / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert_path = tls_dir / "dashboard.crt"
    key_path  = tls_dir / "dashboard.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)
    try:
        import ipaddress as _ip
        from datetime import datetime, timedelta

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        console.print("[yellow]cryptography not available; cannot auto-generate TLS cert.[/yellow]")
        return "", ""

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAP Local"),
        x509.NameAttribute(NameOID.COMMON_NAME, host or "localhost"),
    ])
    san = [x509.DNSName("localhost"), x509.DNSName(host or "localhost")]
    try:
        san.append(x509.IPAddress(_ip.ip_address(host)))
    except (ValueError, TypeError):
        pass
    san.append(x509.IPAddress(_ip.ip_address("127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    # Write key first (0600), then cert.
    fd = _os.open(str(key_path), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
    try:
        _os.write(fd, key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    finally:
        _os.close(fd)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert_path.chmod(0o644)
    console.print(f"[green]Generated self-signed TLS cert: {cert_path}[/green]")
    return str(cert_path), str(key_path)


# ── outputs command group ────────────────────────────────────────────────────

@cli.group()
def outputs():
    """Inspect / manage persisted tool outputs (ToolOutputStore)."""


@outputs.command("ls")
@click.option("--run", "run_id", default="", help="Filter by run_id")
@click.option("--engagement", "-e", default="", help="Filter by engagement_id")
@click.option("--tool", default="", help="Filter by tool name")
@click.option("--limit", default=50, type=int)
def outputs_ls(run_id: str, engagement: str, tool: str, limit: int):
    """List persisted tool outputs."""
    import asyncio as _aio

    from core.tool_output_store import get_tool_output_store
    refs = _aio.run(get_tool_output_store().list(
        run_id=run_id or None,
        engagement_id=engagement or None,
        tool=tool or None,
        limit=limit,
    ))
    if not refs:
        console.print("[yellow]no outputs[/yellow]")
        return
    from rich.table import Table
    t = Table(title=f"{len(refs)} tool output(s)")
    t.add_column("call_id")
    t.add_column("tool")
    t.add_column("rc")
    t.add_column("stdout")
    t.add_column("stderr")
    t.add_column("created_at")
    for r in refs:
        t.add_row(
            r.call_id, r.tool, str(r.returncode),
            f"{r.stdout_bytes}B", f"{r.stderr_bytes}B", r.created_at,
        )
    console.print(t)


@outputs.command("show")
@click.argument("call_id")
def outputs_show(call_id: str):
    """Show metadata for a call_id."""
    import asyncio as _aio

    from core.tool_output_store import get_tool_output_store
    ref = _aio.run(get_tool_output_store().get(call_id))
    if ref is None:
        console.print(f"[red]not found: {call_id}[/red]")
        return
    import json as _json
    console.print_json(_json.dumps(ref.to_dict()))


@outputs.command("cat")
@click.argument("call_id")
@click.option("--kind", type=click.Choice(["stdout", "stderr"]), default="stdout")
@click.option("--head", type=int, default=None)
@click.option("--tail", type=int, default=None)
def outputs_cat(call_id: str, kind: str, head, tail):
    """Print stdout/stderr for a call_id."""
    import asyncio as _aio

    from core.tool_output_store import get_tool_output_store
    try:
        data = _aio.run(get_tool_output_store().read(
            call_id, kind, head=head, tail=tail,
        ))
    except FileNotFoundError:
        console.print(f"[red]not found: {call_id}/{kind}[/red]")
        return
    click.echo(data.decode("utf-8", errors="replace"))


@outputs.command("download")
@click.argument("call_id")
@click.argument("dest_dir", type=click.Path())
def outputs_download(call_id: str, dest_dir: str):
    """Copy all artifacts for a call_id to dest_dir/."""
    import asyncio as _aio
    import shutil
    from pathlib import Path as _P

    from core.tool_output_store import get_tool_output_store
    ref = _aio.run(get_tool_output_store().get(call_id))
    if ref is None:
        console.print(f"[red]not found: {call_id}[/red]")
        return
    src = _P(ref.artifacts_dir or "")
    if not src.exists():
        console.print("[yellow]no artifacts directory[/yellow]")
        return
    dst = _P(dest_dir) / call_id
    dst.mkdir(parents=True, exist_ok=True)
    n = 0
    for p in src.rglob("*"):
        if p.is_file():
            target = dst / p.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
            n += 1
    console.print(f"[green]copied {n} file(s) → {dst}[/green]")


@outputs.command("gc")
@click.option("--retention-days", default=90, type=int)
@click.option("--dry-run/--no-dry-run", default=True)
@click.option(
    "--keep-engagement", "keep_eids", multiple=True,
    help="engagement_id to exclude from deletion (repeatable)",
)
def outputs_gc(retention_days: int, dry_run: bool, keep_eids: tuple[str, ...]):
    """Run the ToolOutputStore garbage collector."""
    import asyncio as _aio

    from core.tool_output_store import get_tool_output_store
    stats = _aio.run(get_tool_output_store().gc(
        retention_days=retention_days,
        keep_engagement_ids=set(keep_eids) or None,
        dry_run=dry_run,
    ))
    console.print(stats)


# ── GDPR command group (P2.2) ────────────────────────────────────────────────

@cli.group()
def gdpr():
    """GDPR / privacy-by-design data lifecycle (purge + retention + verify)."""


@gdpr.command("purge")
@click.argument("engagement_id")
@click.option("--reason", default="gdpr_request",
              help="Free-text reason recorded in the audit trail.")
@click.option("--actor", default="operator",
              help="Who is initiating the purge (recorded in the audit log).")
@click.option("--yes", is_flag=True,
              help="Skip the interactive confirmation prompt.")
def gdpr_purge(engagement_id: str, reason: str, actor: str, yes: bool):
    """Permanently erase every record tied to ENGAGEMENT_ID (Art. 17)."""
    import asyncio as _aio

    from core.gdpr import purge_engagement
    if not yes:
        click.confirm(
            f"Purge ALL data for engagement {engagement_id!r}? This is irreversible.",
            abort=True,
        )
    res = _aio.run(purge_engagement(engagement_id, actor=actor, reason=reason))
    console.print(f"[bold]Purge result for {engagement_id}[/bold]")
    console.print({
        "deleted_engagement":      res.deleted_engagement,
        "findings":                res.deleted_findings,
        "credentials":             res.deleted_credentials,
        "hosts":                   res.deleted_hosts,
        "audit_lines":             res.deleted_audit_lines,
        "report_files":            res.deleted_report_files,
        "tool_output_rows":        res.deleted_tool_output_rows,
        "tool_output_dirs":        res.deleted_tool_output_dirs,
        "errors":                  res.errors,
    })
    if res.errors:
        raise SystemExit(1)


@gdpr.command("retention")
@click.option("--audit-days", default=180, type=int,
              help="Drop audit log entries older than N days (0 to disable).")
@click.option("--tool-output-days", default=180, type=int,
              help="Drop tool outputs older than N days (0 to disable).")
def gdpr_retention(audit_days: int, tool_output_days: int):
    """Apply the configured retention policy across audit log + tool outputs."""
    import asyncio as _aio

    from core.gdpr import apply_retention
    res = _aio.run(apply_retention(
        audit_max_age_days=audit_days,
        tool_output_max_age_days=tool_output_days,
    ))
    console.print({
        "audit_lines_removed":      res.audit_lines_removed,
        "audit_chain_rewritten":    res.audit_chain_rewritten,
        "tool_output_rows_removed": res.tool_output_rows_removed,
        "tool_output_dirs_removed": res.tool_output_dirs_removed,
    })


@gdpr.command("verify-audit")
@click.option("--path", default=None,
              help="Audit log path (default: $AUDIT_LOG_PATH or logs/audit.jsonl).")
def gdpr_verify_audit(path):
    """Verify the BLAKE2b hash chain integrity of the audit log."""
    from core.audit_log import verify_audit_chain
    from core.paths import audit_log_path
    p = path or str(audit_log_path())
    ok, n, msg = verify_audit_chain(p)
    if ok:
        console.print(f"[green]OK[/green] — {n} entries verified ({p})")
    else:
        console.print(f"[red]TAMPERED[/red] at line {n}: {msg} ({p})")
        raise SystemExit(2)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
