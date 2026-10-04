# Production Release Integrity

CloudSentinel production images are published through the tag-triggered release workflow.

## Release chain

A version tag (`v*`) must first pass:

1. PostgreSQL/Redis-backed full regression suite
2. Python compilation
3. frontend JavaScript validation
4. strict dependency vulnerability audit
5. immutable container build
6. BuildKit SBOM generation
7. maximum-detail build provenance
8. GitHub artifact provenance attestation
9. Sigstore keyless image signing
10. signature verification against the GitHub Actions OIDC identity for the release workflow

The production image is addressed by an immutable digest, not by a mutable `latest` tag.

## Verify a release

Resolve the published image to its digest and verify the signature with Cosign:

```bash
cosign verify \
  ghcr.io/pentest-sourav/cloudsentinel@sha256:<DIGEST> \
  --certificate-identity-regexp='https://github.com/pentest-sourav/cloudsentinel/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

The deployment system should promote only a digest whose signature matches the expected GitHub Actions workflow identity.

## Why this matters

Signed, attested digests provide stronger release provenance and reduce the risk of deploying an image built from an unexpected source or workflow.

The signing flow is keyless: no long-lived signing private key is stored in the repository or CI secrets. Sigstore obtains the signing identity from GitHub Actions OIDC.

## Deployment rule

Production deployments should use:

```text
ghcr.io/pentest-sourav/cloudsentinel@sha256:<verified-digest>
```

Do not deploy `latest`.