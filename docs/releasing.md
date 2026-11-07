# Releasing Gazua

Releases are published to PyPI by the `release.yml` workflow, using trusted publishing. No PyPI password or token exists in the repository or in its secrets. Publication waits for manual approval in the protected `pypi` environment.

## One-time setup

Finish all of the following before the first release. If the repository's GitHub plan or visibility does not allow one of them, resolve that first, because the workflow must not publish without them.

1. **PyPI project:** confirm control of the `gazua` name.
2. **Trusted publisher:** on PyPI, register owner `JoaoVictorVM`, repository `gazua`, workflow `release.yml` and environment `pypi`. For a project that does not exist yet, register it as a pending publisher.
3. **Protected environment:** create the `pypi` environment in GitHub with a required reviewer, prevent self-review where available, and restrict deployments to tags matching `v*`.
4. **Artifact attestations:** confirm that they are available for the repository's visibility and plan. A failed attestation blocks publication.
5. **Private vulnerability reporting:** enable it in the repository's security settings, so that the channel in `SECURITY.md` works.

## Publishing a version

1. Set `version` in `pyproject.toml`, refresh the lockfile with `uv lock`, and merge the change into the default branch.
2. Tag that commit with `v` plus the exact version, then push the tag:

   ```console
   git tag v0.1.0.dev0
   git push origin v0.1.0.dev0
   ```

3. The workflow then:
   - rejects a tag that differs from the manifest version or that points outside the default branch;
   - re-runs the quality gates for the tagged commit;
   - builds the wheel and the sdist once, and records their SHA-256 digests;
   - installs exactly those files on Windows and Ubuntu and runs their tests;
   - creates a build provenance attestation for both files;
   - waits for approval in the `pypi` environment.
4. Review the run's digests and attestation, then approve the deployment. The publishing job uploads the same files, without rebuilding them.
5. The final job compares the digests on PyPI with the validated ones, then installs the published version with pip and uv on both systems.

## Checking a release

Verify the provenance of a downloaded file:

```console
gh attestation verify gazua-0.1.0.dev0-py3-none-any.whl --repo JoaoVictorVM/gazua
```

Keep the workflow run URL, commit, version and digests as the release evidence. Never add attack payloads, evidence from tested targets, or secrets to release artifacts.

## When something fails

- **Failure before approval:** nothing reached PyPI. Fix the cause and use a new version if the tagged commit has to change. Do not move a tag that already exists.
- **Missing or mismatched identity:** publication fails before any upload. Check the trusted publisher's fields against the workflow name and environment. Never fall back to a token.
- **Version already published:** the upload fails and PyPI keeps the existing files, because they cannot be replaced. Inspect what is published and release a new version.
- **Partial upload:** PyPI has no atomic upload for several files, so a network failure can leave only some of them published. Compare the files on PyPI with the inventory from the run. If a published digest differs, stop and yank the version. If the digests match and a file is missing, release a new version instead of overwriting anything.

A successful upload alone is not a verified release. The release is complete only when the final verification job passes and the attestation verifies.
