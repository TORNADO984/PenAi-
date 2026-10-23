# Local setup

[Back to the README](../README.md) · [API reference](API.md)

## Requirements

- **Frontend preview:** Python 3 or another static HTTP server, a modern browser, and internet access for CDN assets.
- **Full application:** Node.js 22 or newer, npm, MongoDB, and an OWASP ZAP daemon. Docker is optional and can run ZAP.
- **AI generation:** An optional Gemini API key. Without it, the backend returns built-in guidance and fallback summaries.

## 1. Clone and serve the frontend

```bash
git clone https://github.com/TORNADO984/PenAi-.git
cd PenAi-
python -m http.server 8000 --bind 127.0.0.1
```

Visit [localhost:8000](http://localhost:8000). Leave this terminal running. You can explore the library and run a simulated guest scan now.

Use port `8000` for the frontend so port `8080` remains available for ZAP. On Windows, `py` can replace `python` if needed.

## 2. Configure MongoDB and the backend

Start your local MongoDB service or prepare a reachable MongoDB connection string. From the repository root in a second terminal:

```bash
cd penai-backend
npm ci
```

Copy the configuration template with the command for your shell:

**PowerShell**

```powershell
Copy-Item .env.example .env
```

**Bash**

```bash
cp .env.example .env
```

Edit `penai-backend/.env` before starting the API:

```dotenv
PORT=5000
NODE_ENV=development
MONGODB_URI=mongodb://127.0.0.1:27017/penai
JWT_SECRET=replace-with-a-long-random-secret
ZAP_HOST=127.0.0.1
ZAP_PORT=8080
ZAP_API_KEY=replace-with-your-zap-api-key
GEMINI_API_KEY=
```

- `MONGODB_URI` must point to your database. Replace the local URI with your MongoDB service URI if applicable.
- `JWT_SECRET` signs access tokens. Generate your own secret; do not use the example value.
- `ZAP_HOST`, `ZAP_PORT`, and `ZAP_API_KEY` must match the ZAP daemon.
- `GEMINI_API_KEY` is optional. Leave it empty for fallback guidance; the example template's placeholder is not a working key.
- `NODE_ENV=production` suppresses stack traces in API error responses. It does not configure a production deployment.

For a random JWT secret, run:

```bash
node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"
```

Keep `.env` local. The backend's `.gitignore` already excludes it.

## 3. Start OWASP ZAP

You can use a local ZAP installation in daemon mode or a Docker container. The [official ZAP Docker guide](https://www.zaproxy.org/docs/docker/about/) describes the daemon options. For Docker, run the following as a single line, replacing the key with the same value used in `.env`:

```bash
docker run --rm --name penai-zap -p 127.0.0.1:8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=replace-with-your-zap-api-key -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

This example assumes the Node.js backend runs on the host machine. The port is published on host loopback only, while ZAP listens on all interfaces inside the container. Leave the terminal running and allow ZAP to finish initializing.

Check its API in PowerShell:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8080/JSON/core/view/version/?apikey=replace-with-your-zap-api-key'
```

A working connection returns a ZAP version. A host-local target addressed as `localhost` from ZAP inside Docker refers to the container, so use a target address reachable from the container when testing local applications.

## 4. Start the API

From `penai-backend`, after editing `.env`:

```bash
npm start
```

For development with automatic restarts:

```bash
npm run dev
```

Open [localhost:5000](http://localhost:5000) for the API's welcome response. This endpoint confirms the HTTP server is responding; it does not verify ZAP connectivity. Check the backend console for MongoDB connection status.

## 5. Run an authorized scan

1. Open the frontend at [localhost:8000](http://localhost:8000).
2. Register an account or sign in.
3. Submit an application URL you are authorized to test and that ZAP can reach.
4. Follow the progress indicator through crawling and scanning.
5. Review the findings and request remediation guidance or an executive briefing.
6. Export a PDF or JSON report, copy a summary, or revisit saved scans in **My History**.

Run one live scan at a time with the current shared ZAP integration. Scan duration depends on target size and connectivity; active scanning may fall back to passive findings when it cannot complete.

## Troubleshooting

### The frontend works, but login fails

Confirm the backend is running at `http://localhost:5000`, MongoDB connected successfully, and `.env` was loaded by starting Node from `penai-backend`. Inspect the browser's Network panel and the API console for the actual error.

### The scanner reports that ZAP is not running

Verify the daemon's version endpoint, host, port, and API key. Authenticated requests containing only a target URL return HTTP `503` when ZAP is unavailable; they do not silently switch to guest mode.

### AI responses use built-in guidance

That is expected when `GEMINI_API_KEY` is empty or a model request fails. Set a valid key and restart the backend to enable Gemini requests. Finding details and target information are sent to Google when this integration is enabled.

### PDF export or styling does not load

Check access to the CDN scripts and Google Fonts referenced in `index.html`. PDF generation relies on jsPDF and its AutoTable plugin loading in the browser.

### The API runs on a different host or port

Update the hardcoded API URLs in `js/auth.js` and `js/scanner.js`. Changing backend `PORT` alone does not update frontend requests. Hosted HTTPS frontends also need an HTTPS API URL to avoid mixed-content blocking.

### A report looks inconsistent with the stored results

The frontend uses demo templates when building reports, including for live scans. Inspect `GET /api/scans/:id` to validate the saved findings. A high score or an empty alert list does not establish complete security coverage.
