# CYBER RADAR: static delivery and feed publication

The website is static. Python scripts in `combiner/` and `security-audit/` are offline utilities, not web entrypoints. Feed collection runs in GitHub Actions, never during a Vercel build.

## Vercel project settings

Apply these settings only to **cyber-radar-zylr** (`prj_455hBHf9L6GUcGBJIyKgq0aM7xC7`) in SNB Core. Other projects are connected to this repository, so there is deliberately no shared root `vercel.json`.

```json
{
  "framework": null,
  "rootDirectory": null,
  "installCommand": "",
  "buildCommand": "node scripts/build-static.mjs",
  "outputDirectory": "public"
}
```

`null` framework means Other; root directory is the repository root. The build uses only Node built-ins and installs no dependency. It validates the committed JSON and copies exactly:

- `index.html`
- `data.json`
- `combiner/index.html`
- `combiner/catalog.json`
- `combiner/playbooks.json`

Project authentication and the requirement for verified commits must remain enabled.

## Verification

```sh
node --test tests/*.test.mjs
node scripts/build-static.mjs
```

Tests cover data shape, safe links, metrics, source outages, stale data, publication conflicts, signature checks, ambiguous network failures, allowed public files, JavaScript syntax and relative HTTP paths. Publication API responses are mocked in unit tests; a successful real workflow and a READY Vercel deployment are still required to verify the integration.

After deploying, verify `/`, `/data.json`, `/combiner/`, `/combiner/catalog.json` and `/combiner/playbooks.json`; test refresh, audience filters, combiner scenarios and search. Source scripts, workflows and audit utilities must return 404. Protected deployments should be tested through an authenticated session without disabling protection.

## Scheduled collection

`.github/workflows/refresh.yml` runs hourly at minute 17 UTC, on manual dispatch and on main code changes. Pull requests validate/build but never publish data.

The refresh job checks out main, records its exact SHA, runs the tests and collector, then publishes **only data.json** with GitHub GraphQL `createCommitOnBranch`. GitHub signs this API's commits. The publisher checks the returned signature and uses `expectedHeadOid` to reject concurrent updates without rebasing or force-pushing. It uses the workflow's short-lived `GITHUB_TOKEN` with `contents: write`; no personal token or signing key is required.

Fresh publication requires a snapshot generated within one hour, consistent source statuses/KPIs and at least one working source. Partial failures remain visible in the interface. If all sources fail, publication fails and the previously committed snapshot remains available. Rebuilding an older valid snapshot remains possible; its actual collection date is retained.

If a publication request times out, inspect main before restarting: the request may have succeeded. Do not blindly retry mutations. A failed signature check also requires inspection because the API may already have created the commit.

`GITHUB_TOKEN` changes do not generally start new GitHub Actions workflows. Do not assume that a successful data commit proves Vercel delivery or GitHub Pages delivery: inspect the external deployment status for that exact SHA. Vercel's Git integration and deployment protection are separate gates.

Official references: [GitHub commit API](https://docs.github.com/en/graphql/reference/commits#createcommitonbranch), [GITHUB_TOKEN behavior](https://docs.github.com/en/actions/concepts/security/github_token), [Vercel build settings](https://vercel.com/docs/deployments/configure-a-build).
