# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Three artifacts: `gatepass-core` (plain Java), `gatepass-spring-boot-starter` (Spring Boot 4.0 and 4.1) and
  `gatepass-spring-boot3-starter` (Spring Boot 3.5), the two starters compiled from the same sources.
- Passes signed with HMAC-SHA256 and a shared secret, or with a per-service Ed25519 key pair, bound to the issue time,
  a random nonce, the HTTP method, the raw path and the raw query string, with a configurable clock skew.
- Replay protection: a pass is accepted once. In memory by default, at about 31 bytes per pass; any shared store
  through a `ReplayGuard` bean.
- Optional body signing: senders cover the SHA-256 of the body, receivers check it once the pass is verified, with a
  size limit on both sides.
- Per-service identity with Ed25519 keys: the verified caller is exposed as a request attribute, and
  `gatepass.inbound.callers` restricts which services may call which paths.
- `gatepass.inbound.require-tls`, which rejects requests that did not arrive over TLS on their own connection,
  whatever forwarded headers say.
- A key pair generator: `java -jar gatepass-core.jar`.
- Shared-secret mode for callers that cannot sign.
- Rotation without downtime for secrets and key pairs.
- Spring Cloud Gateway Server WebFlux filter that signs forwarded requests after route filters and load balancing, and
  strips client-sent pass headers on every route.
- Spring Cloud Gateway Server MVC support: the same signing, stripping and body signing, with load-balanced routes
  recognised through the load balancer.
- Servlet and WebFlux filters that reject requests before Spring Security.
- Feign interceptor limited to the clients named in `gatepass.feign.clients`.
- `RestClient`/`RestTemplate` interceptor and `WebClient` filter, never applied automatically.
- Startup failure analysis that names the property to fix.
- JMH benchmarks, and a weekly CI job against the newest Spring Boot and Spring Cloud releases.
