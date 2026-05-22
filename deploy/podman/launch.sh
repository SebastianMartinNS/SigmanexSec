#!/usr/bin/env sh
# deploy/podman/launch.sh — dispatch entrypoint for the SAP-Pentest service
# image. Selects the right Python command line for the chosen service.
#
# Invoked by the container CMD as:
#     launch.sh <service-id>
#
# Recognised service ids:
#     orchestrator
#     mcp-recon, mcp-exploit, mcp-blueteam,
#     mcp-parrot, mcp-engagement, mcp-osint
#
# Any other id exits non-zero so an upstream misconfiguration of the
# Helm chart / docker-compose file surfaces immediately.

set -eu

SERVICE="${1:-${SAP_SERVICE:-}}"

if [ -z "$SERVICE" ]; then
    echo "launch.sh: SAP_SERVICE not set" >&2
    exit 2
fi

case "$SERVICE" in
    orchestrator)
        exec python /opt/sap/cli.py run "$@"
        ;;
    mcp-recon)        exec python /opt/sap/mcp_http_runner.py recon ;;
    mcp-exploit)      exec python /opt/sap/mcp_http_runner.py exploit ;;
    mcp-blueteam)     exec python /opt/sap/mcp_http_runner.py blueteam ;;
    mcp-parrot)       exec python /opt/sap/mcp_http_runner.py parrot ;;
    mcp-engagement)   exec python /opt/sap/mcp_http_runner.py engagement ;;
    mcp-osint)        exec python /opt/sap/mcp_http_runner.py osint ;;
    *)
        echo "launch.sh: unknown SAP_SERVICE='$SERVICE'" >&2
        exit 3
        ;;
esac
