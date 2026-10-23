# Contributing to PenAI

Thanks for helping improve PenAI. Small, focused changes make it easier to review fixes and keep the frontend, API, and documentation consistent.

## Start here

1. Read the [README](README.md) and [local setup guide](docs/SETUP.md).
2. Check [existing issues](https://github.com/TORNADO984/PenAi-/issues) before opening a new report.
3. For a substantial feature, describe the intended behavior and scope in an issue before implementation.
4. Fork the repository and create a branch for your change.

```bash
git clone https://github.com/YOUR_USERNAME/PenAi-.git
cd PenAi-
git switch -c docs/clarify-setup
```

Use a descriptive branch name suited to your change.

## Make a focused change

- Follow the surrounding style: vanilla JavaScript in the frontend and CommonJS modules in the backend.
- Keep route definitions, controller behavior, and service integrations separate.
- Update [API documentation](docs/API.md) when changing endpoints or response fields.
- Keep demonstration data distinguishable from findings produced by a live scan.
- Keep credentials, `.env` files, database dumps, private targets, and exported security reports out of commits.
- Avoid bundling unrelated formatting, dependency updates, or generated artifacts with a fix.

## Validate your work

The repository currently has no automated test script. Describe the checks you actually performed in your pull request.

- **Documentation:** Check relative links, code fences, file paths, and commands against the repository.
- **Frontend:** Serve the project over HTTP and check the affected flow on desktop and mobile sizes. For report changes, check guest mode and a saved live result, including an empty result.
- **API:** Start MongoDB and the backend, exercise the changed endpoint, and check relevant validation and authentication failures.
- **Scanning:** Use only a dedicated target you own or have permission to test. Confirm ZAP connectivity before attempting a live scan.
- **AI:** Check fallback behavior with an empty Gemini key; check model responses only when you have a configured key and appropriate data to send.

## Open a pull request

Explain the problem, resulting behavior, and validation performed. Include screenshots for visible interface changes and note configuration changes or remaining limitations.

For bug reports, include reproduction steps, expected and actual behavior, relevant runtime versions, and sanitized logs. Do not publish sensitive target details or credentials. For sensitive security findings, contact the maintainer privately through an available contact channel before publishing exploit details.
