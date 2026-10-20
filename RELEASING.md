# Releasing SymVeil 0.1.0

This repository is ready to publish. Nothing here publishes it. Do not run `cargo publish` without `--dry-run` until you mean to. Do not push a tag until step 7. Do not create the GitHub Release by hand. Do not create the Homebrew tap until step 3.

The two crates publish in order: `symveil-core`, then `symveil`. The binary crate depends on `symveil-core` version `0.1.0` from crates.io once it is packaged. Both versions are already `0.1.0`. crates.io will not let you reuse a version, including after a yank.

The crates contain this Apache-2.0 tree only. `symveil-core` has no identifier masker. The `symveil` package does not declare the `identifiers` feature and does not depend on `symveil_identifiers`.

## 1. Merge

Merge the release pull request into `main`. Tag the merge commit, not a side branch.

## 2. crates.io token

1. Open <https://crates.io/settings/tokens> and create an API token.
2. On the machine you publish from, run `cargo login` and paste the token.
3. Do not commit the token and do not put it in the repository.

You can do this any time before step 10. It does not publish.

## 3. Homebrew tap

The release workflow pushes `Formula/symveil.rb` to `magnusmalm/homebrew-symveil` when a `v*` tag is pushed. Create that repository before the tag. Skip this step only if you use the manual formula in step 9 instead, and then remove `homebrew` from `installers` and `publish-jobs` in `dist-workspace.toml` and regenerate with `dist generate` before tagging.

1. Create a public repository `https://github.com/magnusmalm/homebrew-symveil`. The name must be exactly `homebrew-symveil` under the `magnusmalm` user.
2. Initialize it with a README so the default branch has a commit. The workflow checks that branch out and commits `Formula/symveil.rb`.
3. Create a GitHub token that can push commits to that repository only. A fine-grained personal access token with Contents read and write on `magnusmalm/homebrew-symveil` is enough. A classic token needs the `repo` scope.
4. On `https://github.com/magnusmalm/symveil/settings/secrets/actions`, add an Actions secret named `HOMEBREW_TAP_TOKEN`. The workflow reads that name. Store the token there, not in git.

After a successful formula push, the install command is:

```bash
brew install magnusmalm/symveil/symveil
```

## 4. Check the commit you will ship

On the merge commit:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo package --workspace --locked
cargo publish --workspace --dry-run --locked
```

Run those two publish commands on the workspace together. `cargo publish -p symveil --dry-run` by itself looks up `symveil-core` 0.1.0 on crates.io and fails until step 10. `cargo package --workspace` and `cargo publish --workspace --dry-run` verify the binary against the library package just built.

Confirm `cargo package --list` does not mention `tests/`, `assets/`, `.github/`, or `packaging/`.

## 5. Stop if the dry run is wrong

Fix the tree and return to step 1. Do not yank a version you have not published, and do not push a tag yet.

## 6. Confirm the one-time secrets exist

`HOMEBREW_TAP_TOKEN` is present on `magnusmalm/symveil`, and `https://github.com/magnusmalm/homebrew-symveil` exists and has a default branch. If either is missing, the binary job can still create the GitHub Release and the Homebrew job will fail afterwards.

## 7. Push the tag

In `CHANGELOG.md`, replace the `0.1.0` heading's `Unreleased` with the date you are tagging (`YYYY-MM-DD`), commit that on `main`, and tag the new commit. The release notes are copied from that section.

From that commit:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

That push starts `.github/workflows/release.yml`. The same workflow runs on pull requests, builds the archives, and uploads them as workflow artifacts. A pull request does not create a Release and does not push the formula.

The tag workflow builds and uploads:

- `symveil-x86_64-unknown-linux-gnu.tar.gz`
- `symveil-aarch64-unknown-linux-gnu.tar.gz`
- `symveil-x86_64-apple-darwin.tar.gz`
- `symveil-aarch64-apple-darwin.tar.gz`
- `symveil-x86_64-pc-windows-msvc.zip`
- a `.sha256` file for each archive
- `sha256.sum`
- `symveil-installer.sh` and `symveil-installer.ps1`
- `symveil.rb`, which the Homebrew job commits to the tap

Each archive contains `symveil` (or `symveil.exe` on Windows), `LICENSE`, and `README.md`.

## 8. Watch the Release workflow

Wait until the workflow on the tag is green. Open `https://github.com/magnusmalm/symveil/releases/tag/v0.1.0` and check that the archives and `.sha256` files are attached. Check `https://github.com/magnusmalm/homebrew-symveil` for `Formula/symveil.rb` if you created the tap.

## 9. Manual formula, if you did not give CI the tap token

Skip this step when step 8 already pushed the formula.

1. Copy `packaging/homebrew/symveil.rb` to `Formula/symveil.rb` in `magnusmalm/homebrew-symveil`.
2. Replace each `sha256` placeholder with the digest in the matching `.sha256` asset from the GitHub Release. The file contents are the same format as `sha256sum`.
3. Commit and push that file to the tap's default branch.

Do not also let the CI Homebrew job push a formula for the same tag.

## 10. Publish the crates

From the same commit as the tag, after the library dry run in step 4 is still clean:

```bash
cargo publish -p symveil-core --locked
```

Wait until <https://crates.io/crates/symveil-core/0.1.0> is visible, then:

```bash
cargo publish -p symveil --locked
```

`cargo install symveil` works after the second publish. Publish the library first. The binary package will not build from crates.io without it.

## Rollback

GitHub Release and tag, before anyone depends on the binaries and before step 10: delete the Release, then delete the remote tag.

```bash
gh release delete v0.1.0 --yes --cleanup-tag
git push origin :refs/tags/v0.1.0
```

Fix `main`, then tag again. You can reuse `v0.1.0` only if that version was not published to crates.io.

GitHub Release created, Homebrew job failed: the archives are already public. Fix the tap or `HOMEBREW_TAP_TOKEN` and re-run the failed job, or follow step 9. Deleting the tag does not unpublish the archives from anyone who already downloaded them.

Homebrew formula wrong: revert the formula commit on `magnusmalm/homebrew-symveil`, or push a corrected `Formula/symveil.rb`. Homebrew keeps a single version of the formula.

crates.io: yank, do not expect the version number back.

```bash
cargo yank -p symveil --version 0.1.0
cargo yank -p symveil-core --version 0.1.0
```

Yank hides the version from new resolution. It does not delete the crate and it does not free `0.1.0`. Ship the fix as `0.1.1`, library first, then the binary. If the binaries for `v0.1.0` are bad as well, leave that tag where it is and release `v0.1.1`. Do not move `v0.1.0` onto a different commit after crates.io has published that version.
