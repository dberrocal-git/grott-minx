# Security Policy

## Supported Versions

grott-minx is not released as versioned packages: it is deployed by checking out
the repository. Only the current `main` branch receives security updates.

| Version                          | Supported          |
| -------------------------------- | ------------------ |
| `main` (latest commit)           | :white_check_mark: |
| Older commits / forks            | :x:                |
| Upstream `johanmeijer/grott`     | :x:                |

If you run an older checkout, update to the latest `main` before reporting an
issue; the fix may already be there.

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub Security Advisories:
[Report a vulnerability](https://github.com/dberrocal-git/grott-minx/security/advisories/new).

Please do **not** open a public issue or pull request for security problems.

Include, if possible:

- the affected file and code path (for example `grottproxy.py` record parsing);
- a description of the impact (remote crash, data exposure, MQTT injection, ...);
- steps or a sample Growatt record that reproduces the problem;
- your configuration, with credentials removed.

What to expect:

- **Acknowledgement:** within 7 days of the report.
- **Status updates:** at least every 14 days while the report is open.
- **Accepted:** a fix is committed to `main` and the advisory is published with
  credit to the reporter unless anonymity is requested.
- **Declined:** you get an explanation of why the behaviour is considered out of
  scope, and the advisory is closed.

## Scope notes

grott-minx is a LAN service: it terminates the TCP session of a Growatt
datalogger and publishes to an MQTT broker. It has no authentication of its own
and is expected to run on a trusted network segment. The following are **not**
considered vulnerabilities:

- credentials stored in plain text in `grott.ini` (protect the file with
  filesystem permissions);
- the proxy accepting any datalogger that connects to it;
- unencrypted MQTT traffic to the broker;
- issues caused by binding the listener to a public interface via `grottip`.
