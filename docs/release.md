# Releasing kubesentry

GitHub Actions builds and publishes every release from a version tag (`.github/workflows/release.yml`). Nothing is built or pushed from a workstation.

## What a release publishes

| What | Where | Notes |
|---|---|---|
| Server image | `ghcr.io/byrongary/kubesentry:0.1.0`, `:0.1`, `:latest` | linux/amd64 and linux/arm64, distroless, uid 65532 |
| Agent image | `ghcr.io/byrongary/kubesentry-agent:0.1.0`, `:0.1`, `:latest` | the same |
| Server binaries | the GitHub release: `kubesentry_0.1.0_{darwin_arm64,darwin_amd64,linux_amd64,linux_arm64}.tar.gz`, `kubesentry_0.1.0_windows_amd64.zip` | static, the UI built in |
| Agent binaries | `kubesentry-agent_0.1.0_linux_{amd64,arm64}.tar.gz` | |
| Checksums | `SHA256SUMS` on the release | |
| Helm chart | `oci://ghcr.io/byrongary/charts/kubesentry`, version `0.1.0` | `appVersion` 0.1.0, so it deploys the images above |

Every image carries an SBOM and a SLSA provenance attestation (BuildKit's, stored with the image) and a cosign signature made with the workflow's GitHub identity (keyless; no key to manage). The binaries report the tag: `kubesentry -version` prints `kubesentry v0.1.0`.

## Cutting a release

1. Check that CI is green on master (the Actions tab).
2. Optional: set `version` and `appVersion` in `charts/kubesentry/Chart.yaml` to the new version and commit. The workflow packages the chart with the tag's version whatever the file says, so this only matters to people installing from a checkout.
3. Tag the commit and push the tag:

   ```bash
   git switch master && git pull
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. Follow the **Release** workflow in the Actions tab. Its jobs:

   | Job | Does |
   |---|---|
   | `version` | checks the tag is `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-PRERELEASE` |
   | `ci` | the whole CI workflow on the tagged commit; nothing is published if it fails |
   | `images` (server, agent) | builds both architectures, pushes with SBOM and provenance, signs with cosign |
   | `binaries` | `hack/release-binaries.sh`, then a **draft** GitHub release with the archives, `SHA256SUMS` and generated notes |
   | `chart` | `helm package --version 0.1.0 --app-version 0.1.0`, `helm push` to `oci://ghcr.io/byrongary/charts` |
   | `publish` | publishes the draft once all of the above succeeded |

A tag with a pre-release suffix, such as `v0.2.0-rc.1`, makes a pre-release: the images get only the `0.2.0-rc.1` tag (no `0.2`, no `latest`), and the GitHub release is marked as a pre-release. Helm needs `--version 0.2.0-rc.1` (or `--devel`) to pick it.

### The first release: make the packages public

GHCR creates a package as private the first time it is pushed. After the first release, once for each of `kubesentry`, `kubesentry-agent` and `charts/kubesentry`:

1. Open github.com/ByronGary, **Packages**, then the package.
2. **Package settings**, **Danger Zone**, **Change visibility**, **Public**.

Until then, pulling needs `docker login ghcr.io` with a token that can read packages.

The workflow's `GITHUB_TOKEN` can push to a package that this repository's workflow created. If a package of the same name was created another way (pushed by hand, from another repository), give the repository access first: **Package settings**, **Manage Actions access**, add `ByronGary/kubesentry` with the **Write** role. A push that fails with 403 points to this, or to the repository's **Settings**, **Actions**, **General**, **Workflow permissions** being restricted by an organization policy.

## Verifying a release

**Checksums** of downloaded archives:

```bash
sha256sum -c SHA256SUMS --ignore-missing          # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing      # macOS
```

On Windows, compare `(Get-FileHash <file> -Algorithm SHA256).Hash` with the file's line in `SHA256SUMS` (`docs/run-remote.md` shows a script).

**Image signatures**, with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.x or later:

```bash
cosign verify ghcr.io/byrongary/kubesentry:0.1.0 \
  --certificate-identity-regexp '^https://github\.com/ByronGary/kubesentry/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The same for `kubesentry-agent`. The check proves the image was signed by this repository's release workflow running for a tag.

**SBOM and provenance:**

```bash
docker buildx imagetools inspect ghcr.io/byrongary/kubesentry:0.1.0 --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/byrongary/kubesentry:0.1.0 --format '{{ json .Provenance }}'
```

**The chart:**

```bash
helm show chart oci://ghcr.io/byrongary/charts/kubesentry --version 0.1.0
helm upgrade --install kubesentry oci://ghcr.io/byrongary/charts/kubesentry --version 0.1.0 \
  -n kubesentry --create-namespace -f my-values.yaml
```

## When a release fails

- **Re-run** the failed jobs from the run's page. Every job can run again: images and the chart are pushed again under the same tags, and the binaries job replaces the draft's assets.
- **Fixing the code** before anyone has used the release: delete the draft release on GitHub, delete the tag (`git push --delete origin v0.1.0 && git tag -d v0.1.0`), fix, and tag again. Images already pushed under `0.1.0` are overwritten by the next run. Never move a tag of a published release; release a new patch version instead.

## Trying the parts locally

- `hack/release-binaries.sh v0.0.0-test /tmp/dist` builds the same archives and `SHA256SUMS` (Linux, GNU tar).
- `hack/build-images.sh` builds the images for your own architecture into the local Docker, without pushing.
- `docker run --rm -v "$PWD":/repo -w /repo rhysd/actionlint:1.7.12` checks the workflows.

## Keeping the workflows current

Third-party actions are pinned to a commit SHA, with the release in a comment (`uses: docker/build-push-action@<sha> # v7.4.0`), so a moved tag cannot change what runs. To update one, look up the new release's commit (`git ls-remote https://github.com/docker/build-push-action refs/tags/v7.5.0`) and change both. Dependabot's `github-actions` ecosystem can propose these updates.

The Go version is set in three places that move together: `GO_VERSION` in `ci.yml` and `release.yml`, and the `golang` image in the `Dockerfile`. The Helm version in `ci.yml` and `release.yml` must render the golden files in `charts/kubesentry/testdata` byte for byte (`hack/helm-test.sh --update` after an intended change).
