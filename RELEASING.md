# Releasing vulnify

Giovanni cuts releases. This repository does not publish on merge, and a `v*` tag is what starts [`.github/workflows/release.yml`](.github/workflows/release.yml). Do not push a tag until the PyPI trusted publisher and the GitHub `pypi` environment below are in place.

The workflow checks out the tagged commit, runs the tests, checks that the tag matches `project.version` and `vulnify.__version__`, builds an sdist and a wheel, runs `twine check`, and requires `py.typed` in both artifacts. The publish job then uses PyPI Trusted Publishing (GitHub OIDC). It does not use an API token. Attestations are enabled (`attestations: true` on `pypa/gh-action-pypi-publish`). If that version is already on PyPI, the publish step is skipped. The action also sets `skip-existing: true`, so a second upload of the same files is not treated as a failure.

## PyPI

The project `vulnify` already exists (0.1.0 and 0.1.1). Add a trusted publisher on that project. Do not create a pending publisher for a new project name.

Open [https://pypi.org/manage/project/vulnify/settings/publishing/](https://pypi.org/manage/project/vulnify/settings/publishing/) and add a GitHub trusted publisher with these values:

| PyPI field | Value |
| --- | --- |
| Owner | `vulnify` |
| Repository | `vulnify-sdk-python` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

PyPI asks for the workflow filename, not the path. The environment name must match the GitHub environment exactly, including case.

No PyPI API token belongs in GitHub. After the first trusted publish of 0.2.0 succeeds, remove any API token that was used to upload 0.1.0 and 0.1.1 if it is still active.

## GitHub

Create an environment named `pypi` (Settings, Environments). The workflow's publish job will not receive an OIDC token for this publisher until that environment exists.

Protection rules to set on `pypi`:

- Required reviewers: yourself, so a tag push waits for your approval before the publish job runs.
- Deployment branches and tags: only tags matching `v*`.

Do not add a `PYPI_API_TOKEN` (or any other publish password) to the environment or the repository. The publish job's only credential is `id-token: write`.

## Cut a release

1. On `main`, set the same version in `pyproject.toml` and `vulnify/__init__.py`, and add a `CHANGELOG.md` entry.
2. Merge that change. The tag has to point at a commit that already contains `release.yml`.
3. From that commit:

```bash
git checkout main
git pull origin main
git tag -a v0.2.0 -m "vulnify 0.2.0"
git push origin v0.2.0
```

4. Approve the `pypi` deployment when GitHub asks.
5. Confirm [https://pypi.org/project/vulnify/0.2.0/](https://pypi.org/project/vulnify/0.2.0/) and that the files have attestations.

The job fails before publishing if the tag does not match the version in that commit. Tag `v0.2.0` for version `0.2.0`, not `0.2.0` without the `v`.

## Backfill tags for 0.1.0 and 0.1.1

These commands are for you to run later. This change set does not create or push them.

PyPI `vulnify` 0.1.0 was uploaded at `2026-09-30T23:51:25Z`. The sdist's packaged files (newline-normalized) are identical to commit `2a1daa1dcffd88c682241aa59d3b25c368bf9ec3` (`Prepare vulnify 0.1.0 for PyPI`, PR #1): `pyproject.toml` version `0.1.0`, `vulnify/__init__.py` `__version__ == "0.1.0"`, and the same `client.py`, `adapters.py`, `README.md`, `LICENSE`, and `MANIFEST.in`. The earlier commit `d4f2407457bd0f8352535b2e7cd658f8d6f7af7a` already had version `0.1.0` in code, but its `README.md` and `pyproject.toml` differ and it has no `MANIFEST.in`, so it is not the published artifact.

PyPI `vulnify` 0.1.1 was uploaded at `2026-10-01T00:02:38Z`. The sdist matches commit `00d070b0dce59f542f05da38fab63e7cf1895b39` (`Document a production export check in 0.1.1`, PR #2), which was `main` before 0.2.0. `__version__` is `0.1.1`. `client.py` and `adapters.py` are unchanged from 0.1.0; the release is the README, changelog, and version bump. Tests are not inside the sdist (`MANIFEST.in` prunes them), and the test file added in that commit is only on git.

```bash
git fetch origin
git tag v0.1.0 2a1daa1dcffd88c682241aa59d3b25c368bf9ec3
git tag v0.1.1 00d070b0dce59f542f05da38fab63e7cf1895b39
git push origin v0.1.0 v0.1.1
```

Pushing those two tags does not start `release.yml`. GitHub loads workflow files from the commit a tag points at. Neither `2a1daa1` nor `00d070b` contains `.github/workflows/release.yml`.

Do not move either tag onto `main` or any later commit that contains `release.yml`. That push would start the workflow. It would still not republish those versions: the tag must match `project.version` in the checked-out commit, and a version that is already on PyPI is skipped. Retargeting `v0.1.0` at the 0.2.0 commit fails the version check and does not upload 0.2.0 under the wrong tag.

GitHub does not emit a `push` event when more than three tags are pushed at once. These two tags are under that limit. Push them on their own, not together with `v0.2.0`, so a backfill is not mixed into the first real release.
