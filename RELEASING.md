# Releasing

Only `gatepass-spring-boot-starter` is published. Its POM is flattened, so neither the parent nor the
integration test modules ever reach Maven Central.

## One-time setup

1. **GitHub.** In the repository settings, enable *Private vulnerability reporting*: `SECURITY.md` points reporters
   to it.
2. **Central Portal account.** Sign in at <https://central.sonatype.com> with the `danimmll` GitHub account. Signing
   in through GitHub verifies the `io.github.danimmll` namespace; check it under *Namespaces*.
3. **Publishing token.** *Account → Generate User Token*. It gives a username and a password.
4. **GPG key.**
   ```bash
   gpg --full-generate-key                      # RSA 4096, no expiry or a long one
   gpg --list-secret-keys --keyid-format long   # note the key id
   gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
   gpg --armor --export-secret-keys <KEY_ID>    # goes into the GPG_PRIVATE_KEY secret
   ```
5. **Repository secrets** (*Settings → Secrets and variables → Actions*):
   `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE`.

## Each release

1. Set the version in every POM, for example `0.1.0-SNAPSHOT` to `0.1.0`:
   `./mvnw versions:set -DnewVersion=0.1.0 -DgenerateBackupPoms=false`, and check with `git diff` that the parent,
   the starter and the three integration test modules all changed. Move the *Unreleased* section of `CHANGELOG.md`
   under that version.
2. Commit, push, wait for CI to pass, then tag and push the tag: `git tag v0.1.0 && git push origin v0.1.0`.
3. The *Release* workflow checks that the tag matches the version, runs every test, signs the starter and uploads
   it to the Central Portal, which validates it.
4. Open *Deployments* on the Central Portal, check the bundle and press **Publish**. It shows up on Maven Central
   within about half an hour. A published version can never be changed or removed.
5. Create a GitHub release from the tag with the changelog section.
6. Bump the POMs to the next `-SNAPSHOT` version.

To try the release build locally without uploading anything: `./mvnw -P release -pl gatepass-spring-boot-starter verify`
(it needs your GPG key).
