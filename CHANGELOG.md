# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Passes signed with HMAC-SHA256 and a shared secret, or with a per-service Ed25519 key pair, bound to the issue time,
  a random nonce, the HTTP method, the raw path and the raw query string, with a configurable clock skew.
- Replay protection: a pass is accepted once. In memory by default; any shared store through a `ReplayGuard` bean.
- Optional body signing: senders cover the SHA-256 of the body, receivers check it once the pass is verified, with a
  size limit on both sides.
- Per-service identity with Ed25519 keys: the verified caller is exposed as a request attribute, and
  `gatepass.inbound.callers` restricts which services may call which paths.
- `gatepass.inbound.require-tls`, which rejects requests that did not arrive over TLS on their own connection,
  whatever forwarded headers say.
- A key pair generator: `java -jar gatepass-spring-boot-starter.jar`.
- Shared-secret mode for callers that cannot sign.
- Rotation without downtime for secrets and key pairs.
- Spring Cloud Gateway (WebFlux) filter that signs forwarded requests after route filters and load balancing, and
  strips client-sent pass headers on every route.
- Servlet and WebFlux filters that reject requests before Spring Security.
- Feign interceptor limited to the clients named in `gatepass.feign.clients`.
- `RestClient`/`RestTemplate` interceptor and `WebClient` filter, never applied automatically.
- Startup failure analysis that names the property to fix.
