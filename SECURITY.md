# Security policy

Gatepass is a security component, so reports are welcome and taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting instead:
**Security → Report a vulnerability** on this repository. You will get an answer within a week.

Useful things to include: the version, the mode (`hmac` or `shared-secret`), which integration is involved
(gateway, servlet, WebFlux, Feign, RestClient, WebClient) and the smallest setup that shows the problem.

## Supported versions

Only the latest release receives fixes while the project is below 1.0.

## Scope

The [threat model in the README](README.md#what-gatepass-protects-against-and-what-it-doesnt) lists what Gatepass
is designed to stop and what it deliberately leaves to other layers. A way to get past something on the first list
is a vulnerability. Something on the second list is a known limit, though ideas to narrow it are welcome as issues.
