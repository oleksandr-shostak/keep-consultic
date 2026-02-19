# Salesforce Cases Provider Architecture And Contracts

## Goal

Design a production-safe Salesforce provider for Keep incidents, similar to PagerDuty behavior:

1. Keep incident -> create/update Salesforce Case.
2. Keep incident status changes -> sync Case status.
3. Salesforce Case status changes -> sync back to Keep incident.
4. No feedback loops and no duplicate case creation.


## Implementation Status (2026-02-18)

- Provider implementation is in place at:
  - `keep/providers/salesforce_provider/salesforce_provider.py`
- Workflow example for outbound Keep -> Salesforce sync:
  - `examples/workflows/salesforce-incident-auto-sync.yml`
- Unit tests for provider behavior:
  - `tests/test_salesforce_provider.py`


## Current Baseline In This Repository

- Salesforce provider now implements incident sync primitives:
  - static `client_id + client_secret + instance_url` auth config
  - `_notify` create/update/upsert for Cases
  - `_query` for single/list/SOQL querying
  - `_get_incidents` pull-based status sync for linked incidents
  - `_format_incident` for Salesforce -> Keep webhook ingestion
  - `setup_incident_webhook` manual/optional auto-setup hook
  - `keep/providers/salesforce_provider/salesforce_provider.py`
- PagerDuty remains the incident sync reference for behavior parity:
  - action/query contract via `_notify`/`_query`
  - incident webhook ingestion via `_format_incident` + `setup_incident_webhook`
  - periodic status pull via `_get_incidents`
  - anti-loop and stale update guards
  - `keep/providers/pagerduty_provider/pagerduty_provider.py`
- Keep incident webhook pipeline for incident providers:
  - `keep/api/routes/incidents.py`
- Provider webhook installation path (`/incidents/event/{provider_type}` for incident providers):
  - `keep/providers/providers_service.py`


## Proposed Provider Shape

```python
class SalesforceProvider(BaseIncidentProvider):
    PROVIDER_DISPLAY_NAME = "Salesforce"
    PROVIDER_CATEGORY = ["CRM", "Incident Management"]
    PROVIDER_TAGS = ["ticketing", "incident", "data"]
    PROVIDER_COMING_SOON = False
```

Required methods:

- `validate_config(self)`
- `validate_scopes(self)`
- `_notify(self, ...)` for create/update/upsert case
- `_query(self, ...)` for case retrieval/search
- `setup_incident_webhook(self, ...)`
- `_get_incidents(self)` for pull-based status sync fallback
- `_format_incident(event, provider_instance=None)` for webhook events
- `dispose(self)`


## Contract 1: Authentication

### `SalesforceProviderAuthConfig` (proposed)

- `instance_url` (required, non-sensitive)
- `api_version` (optional, default `v61.0`)
- `client_id` (required, sensitive=False)
- `client_secret` (required, sensitive=True)
- `ticket_creation_url` (optional)
- `default_owner_id` (optional)
- `default_record_type_id` (optional)

Validation rule:

- valid auth requires:
  - `client_id + client_secret + instance_url`.

Runtime behavior:

- provider sends static `client_id/client_secret` with each request using agreed auth scheme
  (exact header/auth format is implementation-specific and must be confirmed with Salesforce developer).


## Contract 2: Salesforce Case Schema

To guarantee idempotent upsert and deterministic reverse sync, use one required custom field on Case:

- `Keep_Incident_Id__c`:
  - type: Text(36)
  - marked as External ID
  - Unique + indexed

Recommended (optional but useful):

- `Keep_Incident_Url__c` (URL)
- `Keep_Tenant_Id__c` (Text)

Without `Keep_Incident_Id__c`, status sync becomes fuzzy and duplicate-prone.


## Contract 3: Workflow Action (`_notify`)

### Input parameters (proposed)

- `subject: str = ""`
- `description: str = ""`
- `case_id: str = ""` (direct update path)
- `keep_incident_id: str = ""` (defaults from incident context)
- `status: str = ""`
- `priority: str = ""`
- `origin: str = ""`
- `owner_id: str = ""`
- `record_type_id: str = ""`
- `case_type: str = ""`
- `mode: Literal["upsert", "create", "update"] = "upsert"`
- `fields: dict | str | None = None` (custom fields passthrough)
- `add_comment: str = ""`

### Behavior

- `mode=upsert`:
  - if `case_id` provided -> update by id
  - else upsert by `Keep_Incident_Id__c = keep_incident_id`
- `mode=create`: always create new case
- `mode=update`: require `case_id` (or find by `keep_incident_id`, fail if missing)

### Output shape

```json
{
  "case": {
    "id": "500XXXXXXXXXXXX",
    "number": "00012345",
    "url": "https://<instance>.salesforce.com/500XXXXXXXXXXXX",
    "status": "Working",
    "priority": "High"
  },
  "existing": true,
  "action": "upsert",
  "synced_from": "keep"
}
```

This structure keeps workflow enrichments simple: `results.case.id`, `results.case.number`, `results.case.url`.


## Contract 4: Workflow Step (`_query`)

### Input parameters (proposed)

- `case_id: str = ""`
- `keep_incident_id: str = ""`
- `soql: str = ""`
- `limit: int = 100`
- `fields: list[str] | str | None = None`

### Resolution order

1. `case_id` -> get single case
2. `keep_incident_id` -> query by `Keep_Incident_Id__c`
3. `soql` -> custom query
4. default list query for keep-linked cases

### Output

- single object for single-case queries
- list payload for multi-case queries
- never return provider-specific raw response without normalization keys.


## Contract 5: Incident Webhook Ingest (`_format_incident`)

Keep endpoint (already provided by platform):

- `/incidents/event/salesforce?provider_id=<provider_id>`

Expected payload from Salesforce Flow/Apex callout (JSON):

```json
{
  "event_type": "case.updated",
  "occurred_at": "2026-02-18T09:00:00Z",
  "case": {
    "Id": "500XXXXXXXXXXXX",
    "CaseNumber": "00012345",
    "Subject": "API outage",
    "Status": "Closed",
    "Priority": "High",
    "Description": "details",
    "LastModifiedDate": "2026-02-18T08:59:58Z",
    "KeepIncidentId": "c2509cb3-6168-4347-b83b-a41da9df2d5b"
  },
  "actor": {
    "Id": "005XXXXXXXXXXXX",
    "Email": "oncall@company.com",
    "Name": "On Call"
  }
}
```

Rules:

- if `KeepIncidentId` exists and incident exists in Keep:
  - return `IncidentDto` with status change only (no alert ingestion)
- if no mapping and `allow_external_case_creation=false`:
  - return `[]`
- if no mapping and `allow_external_case_creation=true`:
  - create new Keep incident from case (fingerprint = Salesforce Case Id)

`allow_external_case_creation` default: `false`.


## Contract 6: Pull Sync (`_get_incidents`)

Like PagerDuty strategy, `_get_incidents()` should be status-only for already-linked incidents:

1. query Salesforce cases where `Keep_Incident_Id__c != null`
2. map case status -> Keep status
3. load Keep incident by id
4. emit `IncidentDto` only when status changed

No case import flood, no duplicate incident creation.


## Contract 7: Mapping Tables

### Default status mapping (Salesforce -> Keep)

- `New` -> `firing`
- `Working` / `In Progress` / `Escalated` -> `acknowledged`
- `Closed` / `Resolved` -> `resolved`

### Default status mapping (Keep -> Salesforce)

- `firing` -> `New`
- `acknowledged` -> `Working`
- `resolved` -> `Closed`

### Default severity/priority mapping

- `critical|high` -> `High`
- `warning` -> `Medium`
- `info|low` -> `Low`

These should be overridable via provider config (`status_map_*`, `priority_map_*`).


## Contract 8: Keep Enrichment Keys

Persist on incident enrichment after successful sync:

- `salesforce_case_id`
- `salesforce_case_number`
- `salesforce_case_url`
- `sf_last_sync_status`
- `sf_last_sync_at`
- `sf_sync_actor`
- `sf_sync_actors` (optional list)

This mirrors PagerDuty anti-loop strategy and gives deterministic debugging.


## Contract 9: Loop Prevention And Ordering

On inbound Salesforce event, skip update when any condition is true:

1. incoming status already equals current Keep status
2. event actor matches `sf_sync_actor`/`sf_sync_actors`
3. `event_time <= sf_last_sync_at` (out-of-order or echo)

On outbound Keep -> Salesforce status update:

- write sync metadata (`sf_last_sync_*`) immediately after successful API call.


## Contract 10: Error Model

Normalize API errors:

```json
{
  "error_type": "salesforce_api_error",
  "status_code": 400,
  "message": "...",
  "details": ["..."]
}
```

Retry policy:

- retry on `429`, `5xx`, network timeouts with exponential backoff + jitter
- no retry on validation/auth errors (`400`, `401`, `403`, `404` for missing object)


## Contract 11: Security

- never log raw tokens or secrets
- hash sensitive identifiers in logs when needed
- webhook endpoint must use Keep webhook API key
- optional: shared secret header verification for Salesforce callout


## Recommended Delivery Phases

1. Replace stub provider auth + HTTP client + `_query`.
2. Implement `_notify` upsert/update + workflow output contract.
3. Implement Keep incident enrichments for case mapping.
4. Implement `setup_incident_webhook` + `_format_incident` status sync.
5. Implement `_get_incidents` pull fallback.
6. Add tests:
   - upsert idempotency
   - status mapping
   - anti-loop
   - webhook payload parsing


## Open Decisions Before Coding

1. Confirm exact request auth format for static `client_id/client_secret` (header names or auth scheme).
2. Can we add `Keep_Incident_Id__c` on Case as External ID (required for safe upsert)?
3. Exact status values in your Salesforce org for "acknowledged/in-progress" and "resolved/closed"?
4. Should external Salesforce cases be allowed to create new Keep incidents, or only sync linked ones?
