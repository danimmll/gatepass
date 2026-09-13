# Releasing

Three modules are published: `gatepass-core`, `gatepass-spring-boot-starter` and `gatepass-spring-boot3-starter`.
Their POMs are flattened, so neither the parent nor the build-only modules (test support, integration tests,
benchmarks) ever reach Maven Central.

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
   `./mvnw versions:set -DnewVersion=0.1.0 -DgenerateBackupPoms=false`, and check with `git diff --stat` that all ten
   POMs changed. Move the *Unreleased* section of `CHANGELOG.md` under that version.
2. Commit, push, wait for CI to pass on both Spring Boot lines, then tag and push the tag:
   `git tag v0.1.0 && git push origin v0.1.0`.
3. The *Release* workflow checks that the tag matches the version, runs every test on Spring Boot 4 and 3.5, signs the
   three artifacts and uploads them to the Central Portal as one deployment, which it validates.
4. Open *Deployments* on the Central Portal, check the deployment and press **Publish**. It shows up on Maven Central
   within about half an hour. A published version can never be changed or removed.
5. Create a GitHub release from the tag with the changelog section.
6. Bump the POMs to the next `-SNAPSHOT` version.

To try the release build locally without uploading or signing anything:

```bash
./mvnw install -DskipTests
./mvnw -P release deploy -Dmaven.test.skip=true -Dgpg.skip=true -DskipPublishing=true \
  -pl gatepass-core,gatepass-spring-boot-starter,gatepass-spring-boot3-starter
```

With a `-SNAPSHOT` version this checks that the jars, sources and javadoc of the three artifacts build; the upload bundle itself is only assembled for a release version.
