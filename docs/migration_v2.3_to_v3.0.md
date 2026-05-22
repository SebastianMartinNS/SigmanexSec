# Migrazione da SAP-Pentest v2.3 a v3.0

Questo documento è il riferimento operativo per chi aggiorna un deployment
self-hosted di SAP-Pentest dalla v2.3 alla v3.0. La filosofia della v3.0 è
**backward-compatible by default**: ogni nuova capability è dietro a una
feature flag e l'esecuzione single-agent legacy continua a funzionare
senza modifiche.

> Se la tua `.env` di v2.3 funziona oggi, continuerà a funzionare in v3.0
> senza interventi. La migrazione descritta qui è facoltativa — ti permette
> di adottare le nuove funzionalità (tracking compliance-grade, multi-agent,
> metriche Prometheus) un pezzo alla volta.

## TL;DR — i flag che decidono il comportamento

| Flag | Default v3.0.0 | Effetto quando = `1` |
|------|----------------|----------------------|
| `SAP_V3_TRACKING_V2` | `0` | Ogni decisione del LLM (prompt, reasoning, tool call, observation, reflection) entra nella audit-chain BLAKE2b |
| `SAP_AUDIT_ENCRYPT` | `1` | Cifra at-rest i payload sensibili con Fernet (chiave da `CREDENTIAL_ENCRYPTION_PASSPHRASE`) |
| `SAP_METRICS_ENABLED` | `1` | Espone `/metrics` Prometheus (no-op se `prometheus_client` non installato) |
| `SAP_OTEL_ENDPOINT` | *(vuoto)* | Quando settato, esporta span OpenTelemetry verso quell'endpoint |
| `SAP_V3_PROVIDER_ABSTRACT` | `0` | L'orchestrator usa `agent/providers/` invece dei due loop hardcoded *(in transizione: arriva con B4 follow-up)* |
| `SAP_AGENT_MODE` | `single` | `multi` attiva il Coordinator con i 6 ruoli specialistici |
| `SAP_REFLECTION_MODE` | `off` | `sync` aggiunge una chiamata LLM di reflection dopo ogni tool result |

## 1) Cosa NON cambia

- Tutte le variabili d'ambiente legacy (`LLM_PROVIDER`, `ANTHROPIC_API_KEY`,
  `LOCAL_BASE_URL`, `LLM_MODEL`, ecc.).
- La struttura di `core/scope_validator`, `core/executor.run()`,
  `core/audit_log` (sono i chokepoint che non vengono mai duplicati — vedi
  `docs/THREAT_MODEL.md`).
- Il formato del file `parrot_tools.yaml` e dei playbook YAML.
- L'hash-chain BLAKE2b dell'audit log: i record v2.3 e quelli v3.0
  convivono nello stesso file; `verify_audit_chain()` funziona su catene
  miste.

## 2) Cosa puoi attivare per primo (zero rischio)

### Metriche Prometheus

```bash
pip install '.[observability]'
export SAP_METRICS_ENABLED=1
```

Il dashboard espone `/metrics` su porta 8765. Grafana board di esempio in
`examples/grafana/sap-pentest-dashboard.json` (in arrivo con Milestone D).

### Tracing OpenTelemetry

```bash
export SAP_OTEL_ENDPOINT=http://otel-collector:4317
export SAP_OTEL_SERVICE_NAME=sap-pentest
```

Senza endpoint, il tracer è no-op.

## 3) Tracking compliance-grade

Per abilitare l'audit completo del decision-making LLM:

```bash
export SAP_V3_TRACKING_V2=1
# SAP_AUDIT_ENCRYPT=1 è già attivo di default
```

A questo punto ogni iterazione del loop produce 4-5 eventi nella catena
BLAKE2b: `llm_prompt_sent`, `llm_response_received`, `llm_reasoning` (se
presente), `agent_step`, e — quando il loop ne ha bisogno —
`reflection_completed`. Volume tipico: ~10-50 MB per run di engagement.

Per replay forensico:

```bash
python -m scripts.replay_run --run-id run_abc123 \
    --audit-log logs/audit.jsonl \
    --output sessions/replays/
```

## 4) Multi-agent (opt-in)

```bash
export SAP_AGENT_MODE=multi
```

L'orchestrator istanzia un Coordinator che orchestra 6 ruoli specialistici
(planner → recon_analyst → exploit_dev → post_exploit_operator →
blueteam_observer → reporter). Ogni handoff è auditato come `role_handoff`
con un `AgentContext` strutturato.

I ruoli vivono in `agent/roles/*.yaml` e sono editabili dalla community —
vedi `docs/CONTRIBUTING_ROLES.md` (in arrivo con Milestone D) per aggiungere
una nuova specializzazione.

> Default v3.0.0 = `single` per evitare sorprese su deployment esistenti.
> Il default diventerà `multi` in v3.1 dopo feedback community.

## 5) Recovery della chiave Fernet

Quando attivi `SAP_AUDIT_ENCRYPT=1` la chiave deriva da
`CREDENTIAL_ENCRYPTION_PASSPHRASE` (la stessa passphrase che protegge le
credenziali salvate nel session store). **Se perdi la passphrase, perdi la
capacità di decifrare i prompt LLM auditati** — la BLAKE2b chain resta
verificabile, ma i payload all'interno restano cifrati.

Backup raccomandato della passphrase: gestore di password offline +
hardware token, **mai** in chiaro nello stesso filesystem del session
store.

Per fare il backup di una chiave Fernet esplicita (separata dal
credential store):

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Salva l'output, poi:
export SAP_AUDIT_FERNET_KEY="<key-from-above>"
```

## 6) Migrazione roadmap

| Fase | Quando | Effort |
|------|--------|--------|
| Attiva metriche + tracing | subito | 5 minuti |
| Abilita `SAP_V3_TRACKING_V2=1` su un engagement test | settimana 1 | 30 minuti |
| Verifica catena con `replay_run` | settimana 1 | 10 minuti |
| Sperimenta `SAP_AGENT_MODE=multi` su un engagement non-critico | settimana 2 | 1 ora |
| Adotta `multi` come default per nuovi engagement | settimana 3+ | nessuno |

## 7) Rollback

Tornare al comportamento v2.3 è triviale: rimuovi i flag v3 dal `.env`. Il
codice è strutturato in modo che senza flag, ogni nuovo modulo si comporta
come no-op. Niente migrazioni di schema, niente migrazioni di file
config, niente migrazioni di audit log.
