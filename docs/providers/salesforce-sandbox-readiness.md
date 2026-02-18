# Salesforce Sandbox Readiness (Keep)

Date: 2026-02-18

## Current State

- Salesforce provider is implemented in:
  - `keep/providers/salesforce_provider/salesforce_provider.py`
- Provider tests exist in:
  - `tests/test_salesforce_provider.py`
- Example outbound workflow exists in:
  - `examples/workflows/salesforce-incident-auto-sync.yml`

Server (`keep-zpz9.consultic.tech`) is prepared as follows:

- `PagerDuty Incident Auto Sync` excludes Salesforce rules (`d2c259ef-afcc-49a9-9f02-820ecbeb59af`, `65ea991e-41f3-4a4c-843f-a4428043e794`).
- `Salesforce Incident Auto Sync` is created and kept disabled:
  - workflow id: `2cd05c69-4e0b-4293-bae3-408126794f27`
  - `is_disabled=1`
  - scoped only to `Salesforce from email` correlation rule:
    - `d2c259ef-afcc-49a9-9f02-820ecbeb59af`

## What We Still Need From Salesforce Sandbox

1. `instance_url` (sandbox org URL).
2. Static `client_id`.
3. Static `client_secret`.
4. Confirmed Case field:
   - `Keep_Incident_Id__c` as `External ID` + `Unique`.
5. Outbound webhook sender in Salesforce (Flow/Apex):
   - sends Case status events to Keep endpoint.

## Agreed Inbound Status Contract (Salesforce -> Keep)

Salesforce webhook should send normalized Keep statuses directly:

- `firing`
- `acknowledged`
- `resolved`

Payload transport: JSON body (not URL query params), for example:

```json
{
  "event_type": "case.updated",
  "occurred_at": "2026-02-18T09:00:00Z",
  "case": {
    "Id": "500XXXXXXXXXXXX",
    "Status": "acknowledged",
    "Priority": "High",
    "KeepIncidentId": "c2509cb3-6168-4347-b83b-a41da9df2d5b"
  },
  "actor": {
    "Email": "agent@example.com",
    "Name": "Agent One"
  }
}
```

Keep endpoint:

- `POST https://keep-zpz9.consultic.tech/incidents/event/salesforce?provider_id=<provider_id>`
- `X-API-KEY: <keep_webhook_api_key>`
- `Content-Type: application/json`

## Enablement Steps After Sandbox Access

1. Create/update Salesforce provider in Keep with `instance_url`, `client_id`, `client_secret`.
2. Configure Salesforce outbound webhook to Keep endpoint above.
3. Enable workflow `2cd05c69-4e0b-4293-bae3-408126794f27`.
4. Run smoke tests:
   - Keep incident `firing` -> Case upserted.
   - Keep incident `acknowledged` -> Case status updated.
   - Keep incident `resolved` -> Case status updated.
   - Salesforce webhook `acknowledged/resolved` -> Keep status updated.
5. Verify no cross-sync:
   - Salesforce incidents do not create/update PagerDuty incidents.

## Quick Rollback

1. Disable workflow `2cd05c69-4e0b-4293-bae3-408126794f27`.
2. Keep provider can remain configured; no outbound sync occurs while workflow is disabled.
