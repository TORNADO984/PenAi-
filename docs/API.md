# API reference

[Back to the README](../README.md) · [Setup guide](SETUP.md)

Default base URL: `http://localhost:5000`. Send JSON request bodies with `Content-Type: application/json`.

## Authentication and responses

Registration and login return the user record and a signed JWT at `data.token`. Protected routes require:

```http
Authorization: Bearer <your-token>
```

Tokens currently expire after 30 days. There is no refresh-token endpoint. Scan reads and deletion are scoped to the authenticated owner.

Most successful responses use `{ "success": true, "data": ... }`. Errors generally use `{ "success": false, "message": "..." }`; validation failures use an `errors` array. Development error responses may include a stack trace.

## Health response

### `GET /`

Public. Returns the API welcome message, `status: "running"`, and version `1.0.0`. This is an HTTP availability check, not a dependency readiness check.

## Accounts

### `POST /api/auth/register`

Public. Creates an account and returns HTTP `201` with `_id`, `name`, `email`, and `token` inside `data`.

```json
{
  "name": "Alex",
  "email": "alex@example.com",
  "password": "replace-with-a-strong-password"
}
```

The name is required, the email must be valid, and the password must be at least six characters. Duplicate emails and validation failures return HTTP `400`.

### `POST /api/auth/login`

Public. Returns HTTP `200` with the same user/token fields as registration. Invalid credentials return HTTP `401`.

```json
{
  "email": "alex@example.com",
  "password": "replace-with-a-strong-password"
}
```

## Scans

All `/api/scans` endpoints require a bearer token.

### `POST /api/scans`

Starts a scan for an authorized target. Returns HTTP `201` with a scan record before the background scan finishes.

```json
{
  "targetUrl": "https://your-authorized-target.example"
}
```

Poll `GET /api/scans/:id` using the returned `data._id`. A scan progresses through `pending`, `scanning`, and `complete`, or ends in `failed`.

Useful fields include:

- `_id`, `targetUrl`, `scannedAt`, and `user`.
- `status`, `progressMessage`, and `progressPct`.
- `score` (0–100), `severity`, and `scanTime` (seconds).
- `vulnerabilities`, containing finding `name`, `description`, `severity`, `solution`, and `url`.
- Optional `aiRemediation` on findings and `aiSummary` on the scan.

**ZAP unavailable:** A normal target-only request returns HTTP `503`. The API also supports directly saving supplied results when ZAP is unavailable and the request includes `score` or `vulnerabilities`. Such records contain client-supplied data and do not prove a live scan occurred.

### `GET /api/scans`

Returns the authenticated user's scans, newest first, with `success`, `count`, and `data`. The current endpoint has no pagination parameters.

### `GET /api/scans/:id`

Returns one scan record, including its latest progress and results. A missing scan returns HTTP `404`; accessing another user's scan returns HTTP `401`.

### `DELETE /api/scans/:id`

Deletes an owned scan record. Returns HTTP `200` with `success`, `message`, and the deleted record's `id`. Deleting a record does not cancel background ZAP work.

## Remediation and briefings

All `/api/ai` endpoints require a bearer token. Without a working Gemini configuration, responses use built-in or generic fallback guidance. The `generatedBy` field identifies the source.

### `POST /api/ai/remediate`

Generates guidance for a finding. `name` is required; other finding details provide context. Supply both `scanId` and zero-based `vulnIndex` to attempt caching on an owned scan.

```json
{
  "name": "Content Security Policy (CSP) Header Not Set",
  "description": "The response does not include a CSP header.",
  "severity": "Medium",
  "solution": "Define an application-specific Content-Security-Policy.",
  "url": "https://your-authorized-target.example/",
  "targetUrl": "https://your-authorized-target.example"
}
```

Returns HTTP `200` with guidance in `data`, including `cwe`, `summary`, `impact`, `exploitScenario`, `codeFixes`, `verification`, and `generatedBy`. Suggested changes require developer review before use.

### `POST /api/ai/executive-summary`

Generates an assessment and action plan. Pass an owned scan's ID to load its stored results:

```json
{
  "scanId": "replace-with-a-scan-object-id"
}
```

Alternatively, supply `targetUrl`, `score`, `severity`, `scanTime`, and a `vulnerabilities` array directly. A target URL is required after resolving scan data.

Returns HTTP `200` with `executiveBrief`, `topPriorities`, `threatPosture`, `developerChecklist`, and `generatedBy` inside `data`. When a matching owned scan is available, the summary is cached on it.

## Example: register and list scans in PowerShell

Run against your local API after completing the [setup guide](SETUP.md). Replace the example credentials; registration creates an account.

```powershell
$baseUrl = 'http://localhost:5000'
$registration = @{
    name = 'Alex'
    email = 'alex@example.com'
    password = 'replace-with-a-strong-password'
} | ConvertTo-Json

$account = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/auth/register" `
    -ContentType 'application/json' -Body $registration

$headers = @{ Authorization = "Bearer $($account.data.token)" }
Invoke-RestMethod -Uri "$baseUrl/api/scans" -Headers $headers
```

PDF/JSON exports and clipboard sharing run in the browser. There are no dedicated export API endpoints.
