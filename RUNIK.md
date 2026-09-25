# Runik NetBird fork

This Forgejo repository is the source of truth for the smallest NetBird
Community patch series required by Runik. GitHub mirrors and public registries
are publication outputs and must never receive development commits or tags
directly.

The current vendor baseline is NetBird `v0.78.2`, commit
`300b6695012158bdede367738a0389a25d83cf04`. The unmodified vendor tag is kept
in this repository. Runik changes are reviewed as independent commits on the
Forgejo `upstream` branch.

## Branch and version contract

- `netbird-upstream` is the read-only remote for
  `https://github.com/netbirdio/netbird.git`.
- `origin/upstream` is Runik's protected integration branch.
- Official `vX.Y.Z` tags always identify the exact NetBird commit; never move or
  recreate them.
- Fork releases use `vX.Y.Z-runik.N`. The first release from the current
  baseline is `v0.78.2-runik.0`. Container builds use the same version and
  carry both the fork commit and the official upstream version as OCI labels.
- Each functional Runik patch is isolated in its own commit and PR. Unrelated
  cleanup does not belong in this repository.

## Reproducing the management image

The root `Containerfile` builds only the Management Server, which is the
component extended by Runik. From a clean checkout:

```bash
git diff --exit-code
podman build \
  --build-arg NETBIRD_VERSION=0.78.2-runik.0 \
  --build-arg NETBIRD_UPSTREAM_VERSION=v0.78.2 \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --tag netbird-management:0.78.2-runik.0 \
  --file Containerfile .
podman inspect netbird-management:0.78.2-runik.0 \
  --format '{{ index .Config.Labels "org.opencontainers.image.revision" }} {{ index .Config.Labels "io.runik.netbird.upstream-version" }}'
```

`VCS_REF` is mandatory: the build fails when it is missing or set to
`unknown`. This prevents publishing an image whose immutable source cannot be
recovered from its metadata.

Public releases publish
`ghcr.io/runik-platform/netbird-management:<fork-version>`. The immutable version tag
and resolved digest are the deployment and rollback identities; mutable tags
must not be used by production.

## PostgreSQL compatibility gate

The Runik compatibility test starts a disposable PostgreSQL 16 instance,
applies Management's complete migration chain, persists an account, then
starts the store a second time against the same database. This proves the
migration path is idempotent and preserves user data:

```bash
go test ./management/server/store \
  -run '^TestRunikPostgresUpgrade$' \
  -count=1 -timeout=5m
```

NetBird `v0.77.1..v0.78.2` contains no model or migration changes under
`management/server/{store,migration}`. For a future baseline that changes the
schema, this gate must additionally be run against a disposable restore made
by the previous release before updating the compatibility matrix.

## Sealed operator bootstrap

Set `NB_RUNIK_BOOTSTRAP_SECRET_FILE` to a read-only file containing at least
32 characters to enable the two mutation endpoints. Management never stores
that credential in its database. The complementary operator uses this flow:

1. `GET /api/runik/bootstrap?instance_id=<stable-id>` reads `pending`,
   `bootstrapping`, or `sealed` status and never returns a credential.
2. `POST /api/runik/bootstrap`, authenticated as `Bearer <bootstrap-secret>`,
   creates the declared account, the non-OIDC `operator-owner` service user and
   one non-expiring Owner PAT. Only this response contains the plaintext PAT.
3. Before acknowledgement, an identical retry revokes the unclaimed PAT and
   returns one replacement. Conflicting account identity fails closed.
4. After the operator persists and reads back the PAT Secret, it calls
   `POST /api/runik/bootstrap/ack` through normal PAT authentication. The body
   contains only `instance_id`. Management verifies the authenticated account,
   owner and PAT hash, then persists the seal.
5. The bootstrap Secret mount and environment variable can then be removed.
   Status remains queryable, but bootstrap mutation is no longer registered
   after restart and a sealed database never accepts bootstrap again.

The PAT plaintext is not written to bootstrap state, status or logs. Losing
the Kubernetes PAT Secret after sealing is a recovery event: restore the
matching Secret or the database-and-Secret backup set; do not reopen bootstrap.

The focused compatibility checks are:

```bash
go test ./management/server ./management/server/http/handlers/instance \
  -run '^TestRunikBootstrap' -count=1
```

## Updating from NetBird

1. Read the official release and upgrade notes, then fetch both sources:

   ```bash
   git fetch origin upstream
   git fetch netbird-upstream --tags
   ```

2. Confirm that the selected official tag is a descendant of the previous
   baseline and that both remotes resolve it to the same commit:

   ```bash
   git merge-base --is-ancestor v0.78.2 vX.Y.Z
   git rev-parse vX.Y.Z
   git ls-remote netbird-upstream refs/tags/vX.Y.Z
   ```

3. Create a topic branch from the exact Forgejo head and merge the vendor tag.
   Never rewrite `origin/upstream`:

   ```bash
   git switch --create chore/sync-netbird-vX.Y.Z origin/upstream
   git merge --no-ff vX.Y.Z
   ```

4. Resolve conflicts only in the Runik patch surface. Update the version build
   arguments and the compatibility matrix below in the same PR.
5. Run upstream Management tests, build the image, and exercise startup and
   migrations against a disposable restore of the production PostgreSQL
   backup. A successful empty-database boot is not a migration test.
6. Push the topic branch to Forgejo and merge a reviewed PR. Copy the official
   vendor tag to Forgejo only after verifying its commit; do not create a fork
   release yet.

## Compatibility baseline

| Component | Validated baseline | Responsibility |
| --- | --- | --- |
| NetBird Management | `v0.78.2` | This repository |
| NetBird Signal | `0.78.2` | Official image |
| NetBird Relay | `0.78.2` | Official image |
| NetBird Dashboard | `v2.92.0` | Official image |
| PostgreSQL | `16` | Disposable restore required before deployment |
| NetBird Kubernetes operator | `v0.8.0` | Compatibility consumer |
| Complementary operator | `1.4.1` | Compatibility consumer and bootstrap owner |
| Runik NetBird glyph | `3.7.2` | Declarative consumer contract |

The matrix records the integration target, not proof of validation. Record the
test evidence and immutable image digest in the release PR before changing the
production deployment.

## Rollback

The immediate application rollback is the official
`netbirdio/management:0.78.2` image with the same command, configuration and
PostgreSQL instance. Pin the previous immutable fork SHA when the failure is in
a newer Runik build.

Database migrations can make an image-only rollback unsafe. Before rollout,
take a recoverable CNPG backup and validate the candidate against a disposable
restore. If the migration is not backward compatible, rollback means restoring
that backup and the previous image together. Never experiment on the live
database or edit NetBird tables directly.
