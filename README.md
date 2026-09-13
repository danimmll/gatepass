# Gatepass

[![CI](https://github.com/danimmll/gatepass/actions/workflows/ci.yml/badge.svg)](https://github.com/danimmll/gatepass/actions/workflows/ci.yml)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.danimmll/gatepass-spring-boot-starter)](https://central.sonatype.com/artifact/io.github.danimmll/gatepass-spring-boot-starter)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Prove that a request came from inside your system, and from which service.** Gatepass puts a short-lived,
single-use, signed pass on every request Spring Cloud Gateway forwards and on the calls your services make to each
other, and has your Spring Boot services turn away anything without one.

```
client ──► Gateway ──[pass]──► orders ──[pass]──► users     ✓ accepted
                                 ▲
anything else ────[no pass]──────┘                          ✗ 403
```

## Why

Behind the gateway, your services still listen on a port. Whatever reaches that port skips authentication, rate
limiting and everything else the gateway does: a port published by mistake, a misconfigured Docker network, a
compromised container next door.

The usual fix is a filter that compares a shared secret header, copied into every service, plus a gateway filter to
add it and an interceptor for every Feign client. Gatepass started as exactly that in a seven-service Spring Cloud
project: five copies of the same filter and five hand-written interceptors, all sending the same never-expiring
secret on every request. This library replaces all of it and fixes what the copies got wrong:

- **The key never travels.** A pass is a signature that expires after 30 seconds and only works for the request it
  was issued for: the method, the path, the query string and, if you want, the body.
- **A pass works once.** Each one carries a random nonce and services remember the passes they have accepted, so a
  pass copied from a log, a trace or the wire is worthless.
- **Services can tell each other apart.** Give each service a key pair and a pass says which service sent it. A
  compromised service cannot pass itself off as another one, and you decide who may call which paths.
- **It signs the request the service actually receives**, after `StripPrefix`, `RewritePath` and load balancing.
- **Clients cannot forge it.** The gateway strips the header from every route before forwarding.
- **Keys rotate without downtime.**
- **Passes never leak to third parties.** The gateway only signs `lb://` routes by default, Feign only signs the
  clients you name, and the `RestClient` and `WebClient` hooks are only added where you add them.
- **It can refuse plain HTTP**, looking at the connection itself rather than at headers a proxy, or an attacker,
  could set.
- **A bad configuration stops the application at startup** with a message that names the property to fix, never
  with a 403 in production.

## Quick start

Requires Java 17+ and Spring Boot 4.0 or 4.1.

```xml
<dependency>
    <groupId>io.github.danimmll</groupId>
    <artifactId>gatepass-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

```kotlin
implementation("io.github.danimmll:gatepass-spring-boot-starter:0.1.0")
```

The simplest setup is one secret shared by the gateway and every service:

```yaml
gatepass:
  secrets:
    - ${GATEPASS_SECRET}   # openssl rand -base64 32
```

That is the whole setup for the two main cases:

- **In a Spring Cloud Gateway** it signs every request forwarded to an `lb://` route.
- **In a servlet or WebFlux service** it rejects every request without a valid pass, with a `403` and an
  [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) body, before Spring Security or your controllers see it.
  `/actuator/health/**` stays open for health checks.

A shared secret proves that a request comes from inside the system. To also know *which* service sent it, use
[a key pair per service](#a-key-pair-per-service).

### Calls between services

**Feign.** Name the clients that call your own services:

```yaml
gatepass:
  feign:
    clients: [ orders, users ]   # the name of each @FeignClient, or * for all
```

**RestClient, RestTemplate and HTTP interface clients.** Add the interceptor to the clients that need it:

```java
@Bean
RestClient ordersClient(RestClient.Builder builder, GatepassClientHttpRequestInterceptor gatepass) {
    return builder.baseUrl("http://orders").requestInterceptor(gatepass).build();
}
```

**WebClient.** Add the filter:

```java
@Bean
WebClient ordersClient(WebClient.Builder builder, GatepassExchangeFilterFunction gatepass) {
    return builder.baseUrl("http://orders").filter(gatepass).build();
}
```

Every one of them signs again on each retry, so retries and single-use passes get along.

## A key pair per service

With a shared secret, everyone who holds it can issue passes. With Ed25519 key pairs, each service signs with its
own private key and the others only hold its public key: they can check its passes, not make them.

**1. Generate a pair per service.** The starter jar prints one:

```bash
java -jar gatepass-spring-boot-starter-0.1.0.jar
```

```
A new Gatepass key pair (key id 3f9a0c1e)

Private key. Give it to this service only, as gatepass.private-key:
MC4CAQAwBQYDK2VwBCIEI...

Public key. Add it under gatepass.trusted-services.<name of this service>
in every service that accepts calls from this one:
MCowBQYDK2VwAyEA...
```

openssl works too, and PEM files are accepted as they are:

```bash
openssl genpkey -algorithm ed25519 -out gateway.pem     # private key
openssl pkey -in gateway.pem -pubout -out gateway.pub   # public key
```

**2. Configure each side.**

```yaml
# The gateway: it only sends passes
gatepass:
  private-key: ${GATEPASS_PRIVATE_KEY}
```

```yaml
# orders: called by the gateway and by users, and calls users itself
gatepass:
  private-key: ${GATEPASS_PRIVATE_KEY}
  trusted-services:
    gateway: [ "${GATEWAY_PUBLIC_KEY}" ]   # MCowBQYDK2VwAyEA...
    users:   [ "${USERS_PUBLIC_KEY}" ]
  inbound:
    callers:
      - paths: [ "/admin/**" ]
        services: [ gateway ]
  feign:
    clients: [ users ]
```

A service that only receives calls needs no private key. `gatepass.inbound.callers` is optional: the first rule whose
path matches decides who may call, and paths no rule matches accept any trusted service.

**3. Use the caller if you need it.**

```java
@GetMapping("/orders/{id}")
Order order(@PathVariable long id, @RequestAttribute(InboundRules.CALLER_ATTRIBUTE) String caller) {
    // caller is "gateway" or "users", under the name orders trusts them by
}
```

**Moving from a shared secret.** A service accepts every pass it has a key for. Add `trusted-services` everywhere
while keeping `secrets`, give each sender its `private-key`, and remove `secrets` once nothing sends HMAC passes.

## Signing the body

```yaml
gatepass:
  body:
    enabled: true      # senders cover request bodies
    max-size: 1MB
  inbound:
    require-signed-body: true   # optional: receivers refuse passes that do not cover the body
```

With `body.enabled`, the gateway, Feign, `RestClient` and `WebClient` add the SHA-256 of the body to the pass.
Receivers always check the body of a pass that covers one, whatever their own settings.

It has a cost, which is why it is off by default: a body has to be held in memory to be signed and to be checked.

- **The gateway reads each signed body into memory** before forwarding it, up to `max-size`, and answers `413` to
  anything larger instead of forwarding it unsigned. Streaming uploads through the gateway stop streaming.
- **Clients fail the request** if the body is over `max-size`.
- **Receivers read the body only once the pass itself has been verified**, so nobody without a genuine pass can make
  them buffer anything, and answer `413` beyond `max-size`. The body is then handed to your application from memory;
  form parameters keep working.
- **Multipart bodies are never signed.** They are usually large uploads, and a servlet container parses them straight
  from the connection. `require-signed-body` lets them through.

## Replay protection

A valid pass is remembered until it expires, and the same pass is rejected as `REPLAYED` from then on. It is on by
default and needs nothing else as long as each service runs a single instance. Only passes whose signature has been
verified are remembered, so memory grows with legitimate traffic alone: at most a minute's worth of requests.

**Several instances of the same service** each remember their own passes, so a copied pass could still be sent to
another instance. Give them a shared store by defining a `ReplayGuard` bean. With Redis, for example:

```java
@Bean
ReplayGuard sharedReplayGuard(StringRedisTemplate redis) {
    return (passId, expiresAt) -> Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(
            "gatepass:" + passId, "", Duration.between(Instant.now(), expiresAt).plusSeconds(5)));
}
```

**Retries.** Feign, `RestClient`, `WebClient` and the gateway's `Retry` filter all go through Gatepass again and get a
fresh pass. An HTTP library that silently resends the exact same bytes after a dropped connection would get a `403`
if the first attempt had arrived. If that happens to you, set `gatepass.replay-protection.enabled=false`.

## TLS

Gatepass does not encrypt anything: that is TLS's job, and it also protects every header and the response. What
Gatepass can do is make sure TLS is there:

```yaml
gatepass:
  inbound:
    require-tls: true
```

A request that did not arrive over TLS on its own connection is rejected. `X-Forwarded-Proto` and similar headers do
not count, even when Spring trusts them for everything else, so a misconfigured service fails closed. Serve HTTPS
with [Spring Boot's SSL support](https://docs.spring.io/spring-boot/reference/features/ssl.html) (`server.ssl.*` or
an SSL bundle), and point your clients at `https://`.

## What a pass looks like

```
v1.hs256.ec609b60.1789293600.AAECAwQFBgcICQoLDA0ODw.KstPWBD4Yz81tbKyjMbCB8Q9-HEsp140gAv5T_Thqv0.k03rMLtTB9ve_Ag1qT79bEPit0Zhbrg2BgyeBUzLMvQ
│  │     │        │          │                      │                                           └─ signature
│  │     │        │          │                      └─ body: base64url(SHA-256(body)), or - when not covered
│  │     │        │          └─ nonce: 16 random bytes, base64url
│  │     │        └─ issued at: epoch seconds
│  │     └─ key id: first 8 hex characters of SHA-256("gatepass-key-id\n" + key)
│  └─ algorithm: hs256 or ed25519
└─ format version
```

The signature covers these nine lines, joined with `\n` and no trailing newline:

```
gatepass-v1
<algorithm>
<key id>
<issued at>
<nonce>
<body>
<METHOD>
<raw path>
<raw query string>
```

- The key is the secret's UTF-8 bytes for `hs256`, and the DER encoding of the public key for `ed25519`.
- `hs256` signs with HMAC-SHA256 and the secret. `ed25519` signs with the service's private key.
- The raw path and query string are exactly what goes on the wire: percent-encoded, the path `/` when empty, the query
  string without its `?` and empty when there is none.
- Every base64url value is unpadded.

The format is fixed by tests that compare against values computed separately with Python and openssl, so callers
outside the JVM can rely on it. A shell script, for example:

```bash
secret="$GATEPASS_SECRET"; method=GET; path=/orders/42; query='expand=true'
now=$(date +%s); nonce=$(openssl rand 16 | base64 | tr '+/' '-_' | tr -d '=')
key_id=$(printf 'gatepass-key-id\n%s' "$secret" | sha256sum | cut -c1-8)
signature=$(printf 'gatepass-v1\nhs256\n%s\n%s\n%s\n-\n%s\n%s\n%s' "$key_id" "$now" "$nonce" "$method" "$path" "$query" \
  | openssl dgst -sha256 -hmac "$secret" -binary | base64 | tr '+/' '-_' | tr -d '=\n')
curl -H "X-Gatepass: v1.hs256.$key_id.$now.$nonce.-.$signature" "http://orders:8080$path?$query"
```

The same with a key pair, where `key.pem` is the service's private key:

```bash
key_id=$({ printf 'gatepass-key-id\n'; openssl pkey -in key.pem -pubout -outform DER; } | sha256sum | cut -c1-8)
printf 'gatepass-v1\ned25519\n%s\n%s\n%s\n-\n%s\n%s\n%s' "$key_id" "$now" "$nonce" "$method" "$path" "$query" > signed.txt
signature=$(openssl pkeyutl -sign -inkey key.pem -rawin -in signed.txt | base64 | tr '+/' '-_' | tr -d '=\n')
curl -H "X-Gatepass: v1.ed25519.$key_id.$now.$nonce.-.$signature" "http://orders:8080$path?$query"
```

Or Python, with nothing but the standard library:

```python
import base64, hashlib, hmac, secrets, time

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def gatepass(secret: str, method: str, raw_path: str, raw_query: str = "", body: bytes | None = None) -> str:
    key_id = hashlib.sha256(b"gatepass-key-id\n" + secret.encode()).hexdigest()[:8]
    issued_at, nonce = str(int(time.time())), b64url(secrets.token_bytes(16))
    digest = b64url(hashlib.sha256(body).digest()) if body is not None else "-"
    signed = "\n".join(["gatepass-v1", "hs256", key_id, issued_at, nonce, digest,
                        method.upper(), raw_path or "/", raw_query])
    signature = b64url(hmac.new(secret.encode(), signed.encode(), hashlib.sha256).digest())
    return ".".join(["v1", "hs256", key_id, issued_at, nonce, digest, signature])
```

In Java, `Gatepass` has no Spring dependency and can issue and verify passes anywhere:

```java
Gatepass gatepass = Gatepass.builder().secrets(secret).build();
RequestParts request = RequestParts.of("GET", "/orders/42", "expand=true");
String pass = gatepass.issue(request);
Verification verification = gatepass.verify(pass, request);   // VALID, the first time
```

A caller that cannot compute a signature at all can use `gatepass.mode: shared-secret`, where the pass is the secret
itself. It loses every protection above, so keep it for trusted networks.

## Rotating keys

**A shared secret**, in three deployments of every service:

1. Add the new secret **second** and deploy. Everything still signs with the old one and now also accepts the new one.
   ```yaml
   gatepass:
     secrets: [ "${GATEPASS_SECRET_OLD}", "${GATEPASS_SECRET_NEW}" ]
   ```
2. Swap the order and deploy. Everything signs with the new one and still accepts the old one, so services that have
   not restarted yet keep working.
3. Remove the old secret and deploy.

**A service's key pair:**

1. Add the new public key next to the old one, under that service in `trusted-services`, wherever it is trusted.
2. Give the service its new private key.
3. Remove the old public key.

A rotation applied on one side only shows up at debug level as `UNKNOWN_KEY` (see [Troubleshooting](#troubleshooting)).

## Configuration

| Property | Default | |
|---|---|---|
| `gatepass.secrets` | | Shared secrets, at least 32 bytes each. The first one signs, all of them verify. |
| `gatepass.private-key` | | This service's Ed25519 private key: PKCS#8, as PEM or base64 of the DER encoding. |
| `gatepass.trusted-services.<name>` | | Public keys of a service whose passes are accepted: X.509, as PEM or base64 of the DER encoding. |
| `gatepass.mode` | `ed25519` with a private key, `hmac` otherwise | How this application signs: `hmac`, `ed25519` or `shared-secret`. |
| `gatepass.enabled` | `true` | Set to `false` to switch everything off, in a test for example. |
| `gatepass.header-name` | `X-Gatepass` | |
| `gatepass.max-clock-skew` | `30s` | How far a pass's issue time may be from the receiver's clock, either way. |
| `gatepass.replay-protection.enabled` | `true` | Whether a pass is accepted only once. |
| `gatepass.body.enabled` | `false` | Whether senders cover request bodies. |
| `gatepass.body.max-size` | `1MB` | Largest body signed by a sender or checked by a receiver. |
| `gatepass.inbound.enabled` | on in services, off in a gateway | Whether incoming requests need a pass. |
| `gatepass.inbound.include-paths` | `/**` | [PathPattern](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html#mvc-ann-requestmapping-uri-templates)s that need a pass, relative to the context path. |
| `gatepass.inbound.exclude-paths` | `/actuator/health/**` | Paths that never need one. Setting it replaces the default. |
| `gatepass.inbound.callers[n].paths` | | Paths only some services may call. |
| `gatepass.inbound.callers[n].services` | | The trusted services allowed to call them. |
| `gatepass.inbound.require-signed-body` | `false` | Whether every pass must cover the body. Multipart requests are exempt. |
| `gatepass.inbound.require-tls` | `false` | Whether requests must arrive over TLS on their own connection. |
| `gatepass.inbound.filter-order` | `Ordered.HIGHEST_PRECEDENCE + 10` | The default runs before Spring Security. |
| `gatepass.gateway.enabled` | `true` | Whether the gateway signs forwarded requests. |
| `gatepass.gateway.routes` | every `lb://` route | Route ids to sign, or `*` for all. The incoming header is stripped from every route regardless. |
| `gatepass.feign.clients` | | Names of the Feign clients that send a pass, or `*`. |

Every piece is a regular bean that backs off if you define your own: `Gatepass`, `ReplayGuard`,
`GatepassServletFilter`, `GatepassWebFilter`, `GatepassGatewayFilter`, `GatepassFeignRequestInterceptor`,
`GatepassClientHttpRequestInterceptor` and `GatepassExchangeFilterFunction`.

## What Gatepass protects against, and what it doesn't

Gatepass answers two questions: *did this request come from inside my system*, and, with a key pair per service,
*which service sent it*. It is a cheap, useful layer, but it is not a zero-trust network.

**It stops:**

- requests that reach a service directly instead of through the gateway or another service;
- clients that send their own pass header through the gateway;
- a pass copied from a log, a trace or the wire being used again, or for another method, path or query string;
- a request body swapped on the way, with body signing on;
- a compromised service passing itself off as another one, or calling paths its caller rules do not allow, with a key
  pair per service;
- a service answering plain HTTP, with `require-tls`;
- a single leaked request revealing a key: keys never travel.

**It does not:**

- **encrypt anything.** TLS does, and `require-tls` makes sure it is in place.
- **sign headers other than its own, or responses.** Someone who can modify traffic in flight can still change them.
  TLS stops that too.
- **stop a replay against another instance of the same service**, unless the instances share a
  [`ReplayGuard`](#replay-protection).
- **tell services apart with a shared secret.** Everyone who holds it can issue passes. Use key pairs.
- **sign multipart bodies.**
- **limit a compromised gateway** beyond what the gateway is allowed to call.

Keep secrets and private keys where you keep other secrets (environment variables, Docker or Kubernetes secrets, a
vault), never in the repository. Public keys are not secret.

## Troubleshooting

Rejected requests get the same `403` whatever the reason, so as not to help whoever is probing. The only exception is
`413`, which is only ever sent in answer to a genuine pass. The reason goes to the log:

```yaml
logging:
  level:
    io.github.danimmll.gatepass: debug
```

Verdicts that only a genuine pass can produce are logged as warnings even without debug: random traffic cannot
trigger them, so they point at something real.

| Verdict | Level | Usually means |
|---|---|---|
| `MISSING` | debug | The caller has no Gatepass: a Feign client not listed in `gatepass.feign.clients`, a `RestClient` without the interceptor, or a route the gateway does not sign. |
| `MALFORMED` | debug | The header holds something else: often one side in `shared-secret` mode and the other not. |
| `UNKNOWN_KEY` | debug | Signed with a key the receiver does not have: a rotation applied on one side only, or a service missing from `trusted-services`. |
| `INVALID` | debug | Wrong key, or the request changed between sender and receiver: a proxy in between rewriting the path or the query string. |
| `NOT_TLS` | debug | Plain HTTP reached a service with `require-tls`. |
| `EXPIRED` | warn | A genuine pass outside `max-clock-skew`: clocks out of sync, or a late replay. |
| `REPLAYED` | warn | A genuine pass used twice: a replay, or an HTTP library resending the same request. |
| `CALLER_NOT_ALLOWED` | warn | A trusted service, or an HMAC pass, on a path its caller rules do not allow. |
| `BODY_NOT_SIGNED` | warn | A pass without a body digest on a service with `require-signed-body`: a sender without `body.enabled`. |
| `BODY_MISMATCH` | warn | The body is not the one that was signed: something in between changed it. |
| `BODY_TOO_LARGE` | warn | A signed body over the receiver's `body.max-size`. Answered with `413`. |

## Compatibility

| | |
|---|---|
| Java | 17, 21, 25 |
| Spring Boot | 4.0.x, 4.1.x |
| Spring Cloud | 2025.1.x |
| Gateway | Spring Cloud Gateway Server WebFlux. Gateway Server MVC is not supported yet. |
| Clients | OpenFeign, `RestClient`, `RestTemplate`, `WebClient`, HTTP interface clients |

Ed25519 is part of the JDK since Java 15, so key pairs need no extra dependency.

Spring Boot 3 is not supported: its open-source support ended in June 2026, and Spring advises against supporting
Boot 3 and Boot 4 in the same artifact.

## Building

```bash
./mvnw verify
```

Besides the unit tests, three integration test modules start real applications: a Spring MVC service with Spring
Security, Feign and `RestClient`; a WebFlux service with `WebClient`; and a Spring Cloud Gateway with load balancing,
retries and route filters in front of a plain HTTP backend. They cover shared secrets and key pairs, signed bodies,
replays, caller rules, and TLS with a certificate generated on the fly, including a forged `X-Forwarded-Proto`. CI
runs everything on Java 17, 21 and 25 against Spring Boot 4.0 and 4.1.

## License

[Apache License 2.0](LICENSE)
