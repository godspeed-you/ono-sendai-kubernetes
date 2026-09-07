# ADR-0057: A server's path prefix is carried by the one connection that owns the wire

- Status: accepted
- Date: 2026-09-07
- Spec refs: §7.1, §11, §17, §18, §19, §42.1, §43; §17 of the generic provider contract
- Decided by: agent (autonomous)

## Context

§7.1 lists `clusters/server` among the kubeconfig elements this provider MUST support. A `server`
URL is usually a bare host and port — `https://10.0.0.1:6443` — but it is allowed to carry a path,
and managed platforms use that: Rancher addresses a downstream cluster as
`https://rancher.example/k8s/clusters/c-m-xxxxx`, and other API-server proxies do the same. Every
Kubernetes REST path the client then sends — `/api`, `/apis`, `/api/v1/namespaces/.../pods`, a
watch, a log subresource, a `PATCH` — is served *under* that prefix rather than at the API
server's root.

`parse_server` refused such a URL by name: it split the authority from the path and, finding a
non-empty path, returned an error. That was the honest thing to do while nothing prepended the
prefix — dropping it silently would have sent every request to a path the operator never named,
and the answers would have looked like a different cluster's rather than like an error. But it
left a class of real clusters unreachable.

The requirement, then, is to prepend the prefix to *every* request this package sends. The trap is
doing it in the handlers: discovery, list, get, watch, the log subresource and the mutations each
build their own `Request`, and a prefix applied at each call site is a prefix one of them forgets.

## Decision

**The base path is applied once, at the single seam every request passes through: the
`HttpConnection` that owns the byte stream.**

- `parse_server` now returns the base path as a fourth element — a leading `/`, no trailing one,
  or empty — instead of refusing it. A trailing slash is trimmed so the prefix joins the API
  server's own leading-slash paths without doubling one. Nothing is stripped silently.
- `Endpoint` carries the base path, and `Endpoint::client` hands it to the `Client`, which hands
  it to its `HttpConnection`. `Request::with_base_path` prepends it, and
  `HttpConnection::write_and_read_head` — the one function through which `send` and `open` both
  serialise a request — is the only caller. A handler that talks to the connection directly (a
  watch, a discovery read, a mutation) is prefixed by the same rule as one the `Client` builds,
  because both cross that seam. No handler string-concatenates a path.
- The base path is part of `Endpoint::server_url`, and therefore of the session key (ADR-0021) and
  of the endpoint the diagnostic reports. Two clusters at one host and port distinguished only by
  their path are two clusters, not one, and keying a session on the host and port alone would let
  one answer from the other's cache.
- An explicitly named `host` (§7.3) carries no base path: §7.3's endpoint is a host and a port,
  and a path prefix is a property of a kubeconfig `server` URL.

An empty base path — every cluster but one behind a proxy — returns the request unchanged, so the
mechanism costs nothing for the common case.

## Consequences

- A cluster addressed through an API-server proxy connects. `parse_server` no longer refuses a
  `server` URL with a path, and every request travels under it.
- The proof is on the request heads a recorded server saw, not on the mechanism. At the transport
  layer, `should_prepend_the_base_path_to_every_request_a_client_sends` and its siblings assert a
  list and a get arrive under the prefix and that an unset base path leaves the path at the root.
  At the package layer, `should_send_every_request_under_the_server_path_prefix` drives a
  kubeconfig whose `server` carries a path and asserts discovery, a list, a log and a watch all
  arrived prefixed.
- A future request path that is built somewhere new is prefixed automatically, because the seam is
  the connection and not the call site. That is the property this decision exists to buy.

## Alternatives considered

**Prepend in each handler that builds a request.** Rejected: it is the design that guarantees a
future handler forgets, and §42.1's log path, §19's watch path and §43's mutation path are each a
separate place that would have to remember.

**Prepend in `Request::serialise`.** Serialise does not know the base path — it takes only the
host — so it would have to grow a parameter, and every test that serialises a request for
inspection would carry it. The connection already owns the host; owning the base path beside it is
where the address of the far end belongs.

**Leave the base path out of the session key.** Rejected by §10.3 and ADR-0021's rule that the key
may only ever split sessions §6.5 would keep apart: two proxied clusters at one host and port are
two clusters, and a key that ignored their paths would merge them.
