---
title: "ONO-SENDAI Kubernetes Provider Specification"
subtitle: "Reference KUANG/11 Provider for a Dynamic Cloud-Native System"
author: "Provider Architecture Specification"
date: "2026-09-03"
geometry: "paperwidth=157mm,paperheight=210mm,left=13mm,right=13mm,top=14mm,bottom=15mm"
fontsize: 11pt
mainfont: "DejaVu Sans"
monofont: "DejaVu Sans Mono"
colorlinks: true
linkcolor: blue
urlcolor: blue
toc: true
toc-depth: 3
numbersections: false
header-includes: |
  ```{=latex}
  \usepackage{microtype}
  \usepackage{enumitem}
  \setlist{nosep,leftmargin=*}
  \usepackage{fvextra}
  \DefineVerbatimEnvironment{Highlighting}{Verbatim}{breaklines=true,breakanywhere=true,fontsize=\small,commandchars=\\\{\}}
  \setlength{\parskip}{0.45em}
  \setlength{\parindent}{0pt}
  ```
---

# ONO-SENDAI Kubernetes Provider Specification

## Reference KUANG/11 Provider for a Dynamic Cloud-Native System

**Status:** Additive provider-specific architecture specification; not tied to a numbered release  
**Scope:** Kubernetes integration through the generic Ono-Sendai External System Provider contract  
**Provider role:** Reference implementation and architecture stress test for KUANG/11 external-system providers  
**Relationship:** Conforms to `docs/architecture/external-system-provider.md` and `docs/strategy/cloud-native-vision.md` in the [Ono-Sendai repository](https://github.com/godspeed-you/ono-sendai); inherits existing spatial, temporal, prospective-change, live-view, presentation, remote-link and KUANG/11 contracts  
**Normative language:** MUST, MUST NOT, SHOULD, SHOULD NOT, MAY

> Kubernetes is not a command namespace inside Ono. It is a system Ono can understand.

> The provider must learn the cluster that exists, not the cluster its authors expected.

> `kubectl` exposes an API through commands. Ono must expose the system through relationships, evidence, time and safe change.

---

# 0. Document Status and Authority

## 0.1 Provider-specific specification

This document defines the Kubernetes implementation of the generic external-system provider contract.

It is deliberately independent of the numbered Ono-Sendai release sequence. It does not assign Kubernetes support to v0.10, v0.11, v0.12 or any later release, and it does not alter the scope of those releases.

The implementation MAY be delivered incrementally, but any implementation claiming conformance to a capability or maturity level in this document MUST satisfy the corresponding acceptance gates.

## 0.2 Inheritance

The following documents remain authoritative for concepts they already define:

- the existing Ono-Sendai release specifications;
- `docs/strategy/cloud-native-vision.md` in the [Ono-Sendai repository](https://github.com/godspeed-you/ono-sendai);
- `docs/architecture/external-system-provider.md` in the [Ono-Sendai repository](https://github.com/godspeed-you/ono-sendai);
- existing ADRs and canonical repository types.

This provider specification MUST reuse generic concepts such as resource identity, provider facts, coverage, relationships, places, observations, capability negotiation, prospective changes and KUANG/11 sandboxing. Kubernetes-specific code MUST NOT create parallel substitutes merely because Kubernetes uses different terminology.

## 0.3 Provider-specific authority

Where the generic provider contract intentionally leaves Kubernetes details open, this document is authoritative for the Kubernetes provider.

Where this document conflicts with an inherited generic safety or truthfulness invariant, the inherited invariant wins unless an explicit ADR revises the generic contract for all providers.

## 0.4 No core exception by convenience

Kubernetes is the reference external-system provider, but it MUST NOT become a privileged special case in Ono core.

If Kubernetes requires a capability that is broadly meaningful for external systems, the generic provider contract SHOULD be extended through an ADR. If the capability is Kubernetes-specific, it MUST remain inside the provider or a provider-adjacent shared library.

The test is:

> Could an unrelated future provider ignore this concept without carrying Kubernetes baggage?

If not, the concept probably does not belong in core.

## 0.5 Upstream reference snapshot

This specification was written against the Kubernetes API model current on 2026-09-03. Kubernetes v1.37.0 was the latest release at that date, and Kubernetes maintained the three most recent minor release branches v1.37, v1.36 and v1.35.

This snapshot is informative, not a hard-coded compatibility boundary. The provider is discovery-first and MUST not assume that a cluster exposes exactly the APIs present in v1.37.

Canonical upstream references include:

- <https://kubernetes.io/docs/concepts/overview/kubernetes-api/>
- <https://kubernetes.io/docs/reference/using-api/api-concepts/>
- <https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/>
- <https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/>
- <https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/>
- <https://kubernetes.io/docs/reference/access-authn-authz/authorization/>
- <https://kubernetes.io/releases/>

---

# 1. Provider Thesis

## 1.1 Operational problem

Kubernetes presents a structured API, but operators commonly interact with that system through many command invocations whose outputs must be mentally reassembled into one model.

A typical troubleshooting path may cross:

```text
Ingress / Gateway
        |
        v
     Service
        |
        v
   EndpointSlice
        |
        v
       Pod
        |
        v
       Node
        |
        v
 cloud instance
        |
        v
 host / process / socket
```

The Kubernetes API already contains much of the information needed to traverse the upper part of this graph. Ono's Kubernetes provider exists to preserve that structure instead of repeatedly flattening it into terminal text.

## 1.2 User promise

The Kubernetes provider SHOULD make these questions natural:

```text
What exists here?
What owns this?
What selects this?
Where is this scheduled?
What does this expose?
What is this waiting for?
What changed?
What evidence supports that conclusion?
What would this change affect?
Can I move from this Kubernetes object to the infrastructure underneath it?
```

The user SHOULD be able to answer those questions through Ono's existing system grammar rather than by memorizing a parallel Kubernetes command language.

## 1.3 Reference-provider role

Kubernetes is intentionally the first architecture stress test because it combines:

- dynamic API discovery;
- built-in and custom resource types;
- namespaced and cluster-scoped resources;
- desired and observed state;
- controller ownership;
- label and selector relationships;
- ephemeral resources;
- list/watch continuity;
- eventual reconciliation;
- fine-grained authorization;
- API version skew;
- partial visibility;
- asynchronous mutation effects.

If the generic external-system contract cannot represent Kubernetes cleanly, the contract SHOULD be corrected before other providers normalize workarounds.

---

# 2. Goals

The Kubernetes provider MUST support the following architectural goals.

## 2.1 Native Kubernetes objects as typed Ono values

Kubernetes resources MUST remain typed by their native API identity rather than becoming generic JSON blobs.

Examples:

```text
kubernetes.core.v1.Pod
kubernetes.apps.v1.Deployment
kubernetes.discovery.k8s.io.v1.EndpointSlice
kubernetes.example.io.v1alpha1.Widget
```

The exact host-facing type naming scheme MAY differ, but group, version and kind MUST remain inspectable and unambiguous.

## 2.2 Dynamic cluster learning

The provider MUST discover what the connected API server actually serves.

It MUST support:

- core APIs;
- named API groups;
- multiple served versions;
- CRDs;
- aggregated API servers;
- resources appearing or disappearing while Ono is running.

## 2.3 First-class relationships

Important Kubernetes relationships MUST be traversable and inspectable as relationships with evidence, not merely rendered as nested text.

## 2.4 Spatial navigation

Clusters, namespaces and resources MUST participate in the existing Ono place/context model.

## 2.5 Live observation

The provider MUST support Kubernetes list/watch semantics sufficiently to power Ono live views without pretending that an interrupted or expired watch remained complete.

## 2.6 Partial truth

Lack of RBAC permission, unavailable API groups, transient network failures and incomplete pagination MUST remain distinguishable from an empty result.

## 2.7 Safe mutation foundation

Mutation support, when implemented, MUST integrate with Ono's prospective-change, verification and recovery semantics. Read usefulness MUST not depend on mutation support.

## 2.8 Cross-system anchors

The provider MUST export evidence that can later connect Kubernetes resources to cloud and local-system resources without embedding cloud-specific resolvers in the Kubernetes provider.

## 2.9 Contributor ownership

A contributor familiar with Kubernetes SHOULD be able to extend resource mappings, relationship rules or fixtures without understanding Ono parser internals or terminal rendering.

---

# 3. Non-Goals

## 3.1 `kubectl` parity

The provider is not required to reproduce every `kubectl` subcommand, output mode, flag or plugin behavior.

## 3.2 Kubernetes dashboard

The provider does not define a graphical Kubernetes console.

## 3.3 Helm implementation

The provider does not implement Helm chart resolution, release storage or templating as part of its base contract.

Helm resources MAY be recognized through labels, secrets or an optional extension, but Helm is not part of the Kubernetes provider's required semantic core.

## 3.4 GitOps controller

The provider does not become Argo CD, Flux or a generic GitOps reconciliation engine.

## 3.5 Persistent cluster inventory

The base provider does not require a daemon that continuously mirrors whole clusters into a local database.

## 3.6 Metrics backend

Kubernetes Metrics API, Prometheus or OpenTelemetry data MAY be added through separate capabilities, but the provider is not a monitoring backend and MUST not require metrics to understand the resource graph.

## 3.7 Secret revelation

The provider MUST NOT make secret data easier to expose merely because Secret objects are ordinary API resources.

## 3.8 Generic YAML editor

Ono MAY present and change Kubernetes objects, but the provider is not a terminal YAML IDE and MUST not make raw manifest editing the primary interaction model.

---

# 4. Core Invariants

The following invariants are normative.

1. The API server is the authority for Kubernetes state visible through the provider.
2. Discovery is authoritative for what APIs are served; compile-time assumptions are secondary.
3. Native Kubernetes identity remains inspectable.
4. Object `metadata.uid` is the canonical lifetime identity when available.
5. A name is not a lifetime identity.
6. `resourceVersion` is an API continuity/version token, not a wall-clock timestamp.
7. `generation` and `resourceVersion` MUST NOT be conflated.
8. Desired state and observed state MUST remain distinguishable.
9. Conditions are structured observations, not one synthetic status string.
10. Owner references are stronger evidence than label-name heuristics.
11. Selectors define set membership semantics but do not imply ownership.
12. Kubernetes Events are best-effort supplemental observations, not durable audit history.
13. Missing permission is not absence.
14. An expired watch is a continuity break until the provider re-establishes a known state.
15. CRDs are normal resources.
16. Aggregated APIs are normal discovered APIs.
17. Unknown fields MUST be preservable even when not promoted into typed convenience fields.
18. A provider mutation result is not proof that reconciliation reached the intended outcome.
19. Finalizers and deletion propagation MUST be visible in destructive-change reasoning.
20. Cross-system relationships MUST be evidence-driven and resolved outside Kubernetes domain logic.
21. Secret payloads MUST be protected by default.
22. Provider-specific commands MUST NOT create a hidden Kubernetes mini-shell.

---

# 5. Upstream Compatibility Policy

## 5.1 Support window

The initial provider SHOULD target Kubernetes minor versions that are actively supported upstream at implementation time.

At the time this specification was written, that means v1.35 through v1.37.

The support statement MUST be expressed as a tested compatibility matrix, not as a parser guard that rejects other versions.

## 5.2 Discovery-first compatibility

A cluster outside the tested matrix MAY still work if its API behavior satisfies the contracts used by the provider.

The provider SHOULD degrade by capability:

```text
connected
  -> discovery works
  -> schema works
  -> list/get works
  -> watch works
  -> optional mutation features work
```

It MUST NOT reject an otherwise usable cluster solely because `gitVersion` is unfamiliar.

## 5.3 No newest-version assumptions

The provider MUST NOT require an API field or feature merely because it exists in the newest Kubernetes release.

Optional upstream capabilities such as streaming lists MUST be negotiated or detected and MUST have a safe fallback where the provider claims compatibility with versions lacking them.

## 5.4 Deprecated APIs

The provider MUST use discovery results rather than a hard-coded list of deprecated endpoints.

When several versions of a resource are served, provider logic SHOULD prefer a stable version when semantics are equivalent, but MUST preserve the object's actual `apiVersion` when reading and displaying native identity.

## 5.5 Version skew testing

CI SHOULD include at minimum:

- oldest actively supported Kubernetes minor release targeted by the provider;
- latest actively supported minor release;
- one intermediate release when practical.

CRD and aggregation fixtures MUST additionally test APIs independent of Kubernetes core release version.

---

# 6. Provider Package, Instance and Session

## 6.1 Package identity

The first-party package SHOULD have a stable provider identity such as:

```text
provider: kubernetes
```

Exact packaging is implementation-defined.

## 6.2 Provider instance

A provider instance corresponds to a configured Kubernetes connection identity, normally derived from one kubeconfig context or an equivalent explicit connection definition.

Examples:

```text
kubernetes:dev
kubernetes:staging
kubernetes:prod-eu
```

Two contexts pointing to the same API server MAY remain separate provider instances because credentials, impersonation and default namespace may differ.

## 6.3 Session

A provider session is the live host-managed connection state for one provider instance. It includes:

- resolved API server endpoint;
- TLS configuration;
- active credential source;
- effective user identity where discoverable;
- discovery snapshot;
- schema snapshot;
- watch/cache state;
- default namespace or namespace scope;
- negotiated optional capabilities.

Secret material MUST remain outside serializable session diagnostics.

## 6.4 Lazy connection

Loading Ono or discovering the provider package MUST NOT automatically contact every configured cluster.

The provider SHOULD connect lazily when a user enters, queries or explicitly connects the provider instance.

## 6.5 Multiple clusters

Multiple Kubernetes provider instances MUST coexist without:

- resource identity collision;
- cache collision;
- watch checkpoint collision;
- credential leakage;
- accidental namespace carry-over.

---

# 7. kubeconfig and Connection Configuration

## 7.1 kubeconfig compatibility

The provider SHOULD consume standard kubeconfig semantics rather than inventing a competing primary configuration format.

It MUST support the practical configuration elements required to connect securely, including:

- clusters/server;
- certificate authority configuration;
- users/auth infos;
- contexts;
- current context as an optional default;
- namespace defaults;
- client certificates where configured;
- bearer tokens where configured;
- exec credential plugins where supported by host policy.

## 7.2 File merge behavior

If the host chooses to honor `KUBECONFIG` multi-file merge semantics, it SHOULD match standard Kubernetes client behavior closely enough that a context usable by `kubectl` resolves predictably in Ono.

Any intentional deviation MUST be documented and surfaced by `explain provider` or equivalent diagnostics.

## 7.3 Explicit configuration

Ono MAY support explicit provider configuration that does not rely on a kubeconfig file, for automation and test-host use.

Such configuration MUST still map to the same provider instance/session model.

## 7.4 Context selection

Selecting a kubeconfig context MUST be visible in the provider instance identity or active context display.

A command MUST NOT silently operate on a different context because `current-context` changed on disk after the session was established.

The provider MAY detect the file change and offer/perform a host-policy-controlled refresh, but context switching MUST remain explicit.

## 7.5 Namespace default

A kubeconfig context's namespace MAY establish the initial namespace scope.

It MUST NOT be mistaken for an authorization boundary. Users MAY navigate to other namespaces if allowed.

---

# 8. Authentication and Credential Handling

## 8.1 Host-owned secret boundary

Credential bytes are sensitive provider inputs and MUST be brokered through the host's credential/sandbox boundary defined by the generic provider contract.

The provider MUST NOT include tokens, private keys or client certificate private material in:

- typed resource values;
- logs;
- crash diagnostics;
- history;
- provider manifests;
- serialized session state.

## 8.2 Exec credential plugins

The provider SHOULD support kubeconfig `exec` authentication because managed Kubernetes services commonly rely on it.

Execution MUST occur only through an explicit KUANG/11 process-execution capability.

The provider/host MUST honor the declared exec plugin interaction mode:

```text
Never
IfAvailable
Always
```

A provider operating in a non-interactive context MUST NOT fake interactive stdin availability.

## 8.3 Exec output

Exec credential output MUST be parsed as the Kubernetes `ExecCredential` contract, not as arbitrary CLI text.

Credential expiry MUST be honored. Refresh SHOULD occur before a request when the credential is expired or according to standard client behavior.

## 8.4 TLS

TLS certificate validation MUST be enabled by default.

Insecure TLS modes MAY be honored only when explicitly configured. The active insecure state MUST be visible in provider diagnostics and SHOULD be visually prominent in destructive-change contexts.

## 8.5 Impersonation

Kubernetes impersonation MAY be supported.

If enabled, the effective impersonated identity MUST be impossible to confuse with the credential identity.

The active context SHOULD expose information equivalent to:

```text
credential identity: alice@example.com
effective identity: system:serviceaccount:demo:debugger
impersonation: active
```

## 8.6 Effective identity

Where allowed, the provider SHOULD use `SelfSubjectReview` or equivalent API truth to expose the user information the API server associates with the current request.

Failure to obtain this information MUST NOT block ordinary read operations.

---

# 9. Scope Model

## 9.1 Cluster is a provider root scope

Each provider instance represents one effective cluster connection and is rooted in a cluster place.

Example:

```text
k8s://prod/
```

## 9.2 Namespace is a primary scope dimension

Namespaced resources MUST carry namespace as an explicit scope component.

Cluster-scoped resources MUST not be assigned a fake namespace.

## 9.3 API group/version scope

API group/version is type identity, not primary user navigation hierarchy.

Users SHOULD normally navigate by operational meaning and namespace rather than through a tree such as:

```text
/apis/apps/v1/...
```

The native group/version remains inspectable and queryable.

## 9.4 No silent all-namespace fan-out

A query scoped to one namespace MUST NOT silently expand to all namespaces.

An explicit all-namespace query MUST preserve per-namespace identity and partial-coverage information.

## 9.5 Cluster-scope queries

Queries for cluster-scoped types such as Node or Namespace MAY be issued from a namespace context because context and type scope are different concepts.

The UI SHOULD make scope escape visible when it matters.

## 9.6 Multi-cluster operations

The provider specification does not introduce transparent multi-cluster fan-out.

A future federated query layer MAY query several provider instances, but one Kubernetes provider session MUST remain scoped to one effective API server connection.

---

# 10. Cluster Identity

## 10.1 Stable local provider identity

The provider instance ID is Ono-local configuration identity and MUST remain stable across reconnects unless configuration is replaced.

## 10.2 Upstream cluster fingerprint

The provider SHOULD derive a non-secret cluster fingerprint to help detect accidental context aliasing.

Potential evidence MAY include:

- normalized API server origin;
- server certificate public-key fingerprint;
- `kube-system` namespace UID where readable;
- other stable, non-secret cluster identifiers if Kubernetes later provides one canonically.

No single optional signal MUST be treated as universally available.

## 10.3 Alias detection

If two provider instances appear to point to the same upstream cluster, Ono MAY report that as an observed alias possibility.

It MUST NOT merge their identities automatically because credentials and effective permissions may differ.

## 10.4 Cluster replacement

If a configuration name remains the same but strong fingerprint evidence changes, the provider MUST invalidate cached object identities and watches associated with the previous cluster before presenting data as current.

---

# 11. API Discovery

## 11.1 Discovery is mandatory

The provider MUST discover served APIs from the connected API server.

It MUST learn at least:

- API groups;
- versions;
- resources;
- namespaced versus cluster scope;
- supported verbs;
- kind identity;
- subresources where discoverable.

## 11.2 Aggregated discovery

The provider SHOULD use the stable aggregated Discovery API when available because it provides an efficient cluster-wide resource summary.

It MUST have a compatible fallback for supported clusters where a required discovery form is unavailable.

## 11.3 Discovery result as provider fact

A discovery snapshot MUST carry:

```text
provider_instance
observed_at
api_server
coverage
source endpoint / mechanism
```

## 11.4 Dynamic change

Discovery results MAY change while a cluster is running because CRDs or aggregated APIs can appear or disappear.

The provider MUST support discovery invalidation and refresh without restarting Ono.

## 11.5 Missing group

A resource type disappearing from discovery MUST NOT immediately erase previously observed objects from history.

Current queries SHOULD report the API as unavailable/not served, while historical values retain their original type identity.

---

# 12. OpenAPI and Schema Discovery

## 12.1 Discovery and schema are separate

The Kubernetes Discovery API identifies resources and verbs but does not fully describe their fields.

The provider SHOULD use Kubernetes OpenAPI v3 when available to obtain resource schemas and MAY use other safe schema sources for gaps.

## 12.2 Dynamic typed projection

The provider MUST be able to construct useful typed Ono schemas for resources not known at Ono compile time.

This is required for CRDs.

## 12.3 Structural schema gaps

Some served APIs may expose incomplete or non-structural schema information.

The provider MUST still preserve native object content and type identity. It MAY degrade field-level type precision while marking the schema source and precision.

## 12.4 Schema cache

Schema documents MAY be cached independently from resource values.

Cache invalidation MUST account for:

- CRD updates;
- API group/version changes;
- reconnect to a different cluster;
- provider instance fingerprint changes.

## 12.5 Unknown fields

Unknown fields MUST remain accessible through a generic structured value representation even when they are not promoted to named Ono schema fields.

The provider MUST NOT discard provider-native data merely because its SDK does not know the field.

---

# 13. Kubernetes Type Identity

## 13.1 GVK and GVR

The implementation MUST model both concepts where needed:

- **GVK** - group, version, kind: object/schema identity;
- **GVR** - group, version, resource: REST collection/endpoint identity.

They MUST NOT be treated as interchangeable strings.

## 13.2 Canonical host type

A typed Ono Kubernetes resource MUST retain at least:

```text
api_group
api_version
kind
resource_name (plural REST resource where known)
scope: namespaced | cluster
```

## 13.3 Core group

The Kubernetes core API group MUST be represented unambiguously even though its REST path and `apiVersion` omit a named group.

For example:

```text
apiVersion: v1
kind: Pod
```

MUST not collide with a hypothetical non-core `Pod` kind.

## 13.4 Version variants

Two served versions of the same conceptual resource MAY map to related host schemas, but the native version observed from the API MUST remain available.

The provider MUST NOT silently rewrite every object into the newest served version for display if doing so can alter semantics or fields.

## 13.5 Kind collisions

Kinds are not globally unique.

Query and rendering shortcuts MAY use `Pod` when unambiguous, but canonical identity MUST include API group.

---

# 14. Common Object Metadata Projection

Every Kubernetes object with `ObjectMeta` SHOULD expose a consistent common metadata projection in addition to native fields.

## 14.1 Required common fields

Where present upstream:

```text
name
namespace
uid
resourceVersion
generation
creationTimestamp
deletionTimestamp
labels
annotations
finalizers
ownerReferences
managedFields summary
```

The provider MAY lazy-load or summarize exceptionally large metadata such as `managedFields` in default views, but it MUST not pretend the data is absent.

## 14.2 UID

`metadata.uid` is the canonical upstream identity for one lifetime of an object.

An object deleted and recreated with the same kind, namespace and name but a different UID MUST be treated as a distinct resource lifetime.

## 14.3 resourceVersion

`resourceVersion` MUST be treated as an opaque Kubernetes concurrency/continuity token.

It MUST NOT be:

- sorted numerically across unrelated resources as a timeline;
- converted into a timestamp;
- used as a cross-resource causal clock.

## 14.4 generation

`metadata.generation` SHOULD be exposed for resources that use it.

It MAY help reason about desired-spec changes and controller observation, but provider logic MUST not assume every kind increments or consumes generation identically.

## 14.5 Labels and annotations

Labels and annotations MUST remain structured maps.

Selectors and well-known keys MAY receive semantic interpretation, but arbitrary user keys MUST be preserved.

## 14.6 Finalizers

Finalizers MUST be visible in inspection and destructive-change planning because they materially affect deletion completion.

## 14.7 managedFields

`managedFields` SHOULD be available for advanced provenance and apply-conflict diagnostics.

Default rendering SHOULD summarize it rather than dumping the full structure.


# 15. Resource Inventory and Implementation Tiers

The provider MUST distinguish architectural support from curated semantic support.

## 15.1 Universal dynamic support

Every discovered readable Kubernetes resource SHOULD be available at a baseline dynamic level when the server provides sufficient schema or structured JSON data.

Baseline dynamic support includes:

- canonical type identity;
- stable resource identity;
- metadata projection;
- get/list where authorized;
- generic field access;
- owner-reference relationships;
- place participation where safe;
- watch when the resource supports it and provider capability is enabled.

This is the minimum meaning of "CRDs are first-class."

## 15.2 Tier 1 - core operational graph

The first curated semantic tier MUST prioritize resources needed for everyday workload troubleshooting:

```text
Namespace
Node
Pod
Deployment
ReplicaSet
StatefulSet
DaemonSet
Service
EndpointSlice
Ingress
Job
CronJob
ConfigMap
Secret metadata
ServiceAccount
PersistentVolumeClaim
PersistentVolume
StorageClass
NetworkPolicy
```

The exact release delivery may be incremental, but the provider specification treats this set as the first complete operational target.

## 15.3 Tier 2 - platform operation

A second tier SHOULD include:

```text
HorizontalPodAutoscaler
PodDisruptionBudget
ResourceQuota
LimitRange
Role
ClusterRole
RoleBinding
ClusterRoleBinding
Lease
PriorityClass
RuntimeClass
CSIDriver
CSINode
VolumeAttachment
MutatingWebhookConfiguration
ValidatingWebhookConfiguration
ValidatingAdmissionPolicy where served
```

## 15.4 Tier 3 - dynamically recognized ecosystems

Well-known extension APIs MAY have semantic adapters layered over universal dynamic support, for example:

- Gateway API;
- cert-manager;
- Prometheus Operator resources;
- Argo CD;
- Flux;
- Crossplane.

Such adapters MUST remain optional and MUST NOT be required for arbitrary CRDs to function as resources.

## 15.5 No all-or-nothing support claim

Documentation MUST state separately:

```text
readable dynamically
semantically curated
relationship enriched
watch capable
mutation capable
```

A resource being discoverable does not imply that Ono understands every field or relationship.

---

# 16. Resource Identity and Lifetime

## 16.1 Canonical identity tuple

For a live Kubernetes object, the provider SHOULD construct canonical identity from:

```text
provider_instance_id
api_group
kind
metadata.uid
```

Version MAY be retained as observed representation metadata rather than lifetime identity when the same object is served through multiple versions.

## 16.2 Locator identity

Human lookup uses a locator such as:

```text
provider instance
GVR or resolved kind
namespace if namespaced
name
```

A locator is not the same as lifetime identity.

## 16.3 Recreate detection

If `name` remains the same but UID changes, the provider MUST emit a lifecycle discontinuity and MUST NOT merge the new object into the previous object's live identity.

## 16.4 Deletion tombstone

A deleted object MAY remain represented as a tombstone in temporal/history contexts.

The tombstone SHOULD retain:

- UID;
- last known type;
- namespace/name;
- last observed resourceVersion;
- deletion observation time;
- provenance;
- last known relationship edges marked historical.

## 16.5 Objects without UID

If an unusual API object lacks UID, the provider MUST degrade identity confidence explicitly. It MAY use a scoped locator identity but MUST mark that identity as weaker and recreation-ambiguous.

---

# 17. Read Operations

## 17.1 Get

Direct lookup SHOULD use the canonical REST resource endpoint resolved from discovery.

A get result MUST carry:

```text
observed_at
resourceVersion
provider_instance
scope
source endpoint category
freshness
```

## 17.2 List

List operations MUST preserve list metadata relevant to completeness and continuity, including:

- collection `resourceVersion` where present;
- `continue` token where present;
- remaining-item metadata where present;
- requested selectors;
- namespace or all-namespace scope.

## 17.3 Server-side filtering

The provider SHOULD push supported label selectors and field selectors to the API server when Ono query semantics map exactly.

It MUST NOT push a filter when the translation changes semantics.

Client-side residual filtering MAY follow a correct server-side subset.

## 17.4 Label selectors

Kubernetes label selector semantics MUST remain Kubernetes semantics.

The provider MUST NOT invent logical OR support and silently translate it into several requests without preserving fan-out and completeness metadata.

If Ono supports richer predicates, the provider MAY execute broader server-side requests and finish filtering locally.

## 17.5 Field selectors

Field selector availability varies by resource type and server implementation.

The provider SHOULD detect rejection and fall back only when safe and affordable. Unsupported field selection MUST not become an empty result.

## 17.6 Query planning

Before an expensive all-namespace/all-resource query, the provider SHOULD estimate or expose query breadth when possible.

A query planner MAY group requests by GVR and namespace, but it MUST preserve which scopes were actually queried.

---

# 18. Pagination and Large Collections

## 18.1 Continue tokens

When the API server returns a `continue` token, the provider MUST treat the collection as incomplete until all required pages have been consumed or the operation is explicitly cancelled/limited.

## 18.2 Snapshot semantics

Kubernetes paginated list behavior can provide a consistent snapshot across continued requests. The provider SHOULD preserve that semantic and MUST NOT mix an unrelated fresh list into the middle of a pagination sequence without marking a continuity break.

## 18.3 Partial-page failure

If pages 1..N succeed and page N+1 fails, the provider MAY return the already received values, but coverage MUST be `partial` and the error MUST be attached to the collection result.

A default table MUST NOT look identical to a complete result.

## 18.4 User limits

User-requested limits such as:

```text
... | first 20
```

are not provider incompleteness if the pipeline intentionally stops consumption.

The value stream SHOULD still know that more upstream results may exist.

## 18.5 Memory bounds

The provider SHOULD stream pages into the Ono pipeline rather than buffering entire large clusters unless an operation explicitly requires a complete set.

---

# 19. Watch Model

## 19.1 List/watch continuity

The provider MUST implement watch semantics around Kubernetes `resourceVersion` correctly.

A canonical fallback algorithm is:

```text
LIST
  -> obtain collection resourceVersion
WATCH from that resourceVersion
  -> ADDED / MODIFIED / DELETED
  -> reconnect from last safe checkpoint when possible
```

The implementation MAY use a standard Kubernetes client primitive equivalent to this behavior.

## 19.2 Streaming lists

Where the server supports streaming lists / initial events, the provider MAY use them to reduce control-plane and client memory pressure.

Use of such a feature MUST be capability-negotiated and MUST have a list/watch fallback for supported clusters where it is unavailable.

## 19.3 Watch event classes

The provider MUST understand upstream watch event classes relevant to continuity, including:

```text
ADDED
MODIFIED
DELETED
BOOKMARK
ERROR
```

A `BOOKMARK` is a continuity/checkpoint signal, not a resource mutation.

## 19.4 410 Gone

If the requested historical resourceVersion is no longer available and the API returns `410 Gone`, the provider MUST:

1. mark continuity as broken for the affected watch;
2. clear or quarantine assumptions that require gap-free change observation;
3. perform a fresh state acquisition;
4. resume from a new known resourceVersion;
5. expose a gap in temporal/coverage metadata.

It MUST NOT stitch pre-gap and post-gap events into a fake continuous history.

## 19.5 Reconnect

Transient network disconnects SHOULD reconnect from the latest safe resourceVersion when upstream semantics allow.

The provider MUST apply bounded backoff and respect host cancellation.

## 19.6 Watch fan-out

Watching every discovered GVR in a large cluster can be expensive and is not required.

Watches SHOULD be demand-driven by:

- active live views;
- explicit temporal observation;
- relationship-maintenance requirements;
- host-approved background capability.

## 19.7 Watch lifecycle

Leaving a place or closing a live view SHOULD release watches that no longer serve another active consumer.

The host MAY multiplex consumers over one internal watch stream.

---

# 20. Cache, Freshness and Consistency

## 20.1 Cache classes

The provider MAY maintain separate caches for:

```text
discovery
OpenAPI/schema
resource objects
relationship indexes
permission hints
watch checkpoints
```

Each cache MUST have independent validity rules.

## 20.2 Object freshness

A cached Kubernetes object MUST retain:

```text
observed_at
resourceVersion
cache_state
watch_synced state where applicable
```

The user MUST be able to distinguish a direct read from a cached observation.

## 20.3 Informer-style cache

An informer/reflector-style synchronized cache MAY be used for active resource sets.

The provider MUST know whether the cache has completed initial synchronization.

Before sync completion, absence in the cache MUST NOT mean upstream absence.

## 20.4 Eventual reconciliation

Kubernetes resource mutation is frequently asynchronous.

The provider MUST distinguish:

```text
API accepted desired-state change
object observed with new spec
controller observed generation
status converged
workload externally healthy
```

No one stage automatically proves the next.

## 20.5 Mutation invalidation

After a successful mutation request, the provider SHOULD invalidate or refresh affected cached objects and relationships.

It MUST NOT simply patch its local cache and label the synthetic result as a server observation.

---

# 21. Authorization and RBAC Truth

## 21.1 API server remains authorization authority

Ono MUST NOT implement its own RBAC evaluator as a substitute for the Kubernetes authorizer.

## 21.2 Permission checks

For a specific action, the provider MAY use `SelfSubjectAccessReview` to ask whether the current identity can perform the relevant request.

Such a check is advisory for UX and planning. The actual API request remains authoritative because authorization can change between check and execution.

## 21.3 Rules summaries

`SelfSubjectRulesReview` MAY be used to improve discoverability of likely available actions within a namespace.

Its result MUST NOT be treated as a complete authorization oracle. Upstream explicitly permits incomplete rule summaries depending on authorizer behavior.

## 21.4 Denied reads

A `403 Forbidden` MUST map to an explicit denied state.

The provider MUST distinguish at least:

```text
resource absent
resource type not served
namespace absent
read denied
list denied
provider disconnected
request failed
not queried
```

## 21.5 Partial namespace visibility

If the current user can list some namespaces/resources but not others, all-namespace operations MUST preserve partial coverage.

The provider MUST NOT infer that unseen namespaces are empty.

## 21.6 Capability UI

Ono MAY hide or de-emphasize actions known to be unauthorized, but `explain` SHOULD state whether an action is:

```text
allowed by preflight check
denied by preflight check
unknown / unchecked
```

---

# 22. Secret Handling

## 22.1 Secret is a resource with restricted presentation

Kubernetes `Secret` objects participate in identity, relationships, metadata and navigation, but payload handling MUST be stricter than ordinary resources.

## 22.2 Default redaction

Default inspection MUST NOT reveal decoded `data`, `stringData` or equivalent secret payload.

A default view SHOULD show safe metadata such as:

```text
name
namespace
type
keys present
creation time
owner references
consumers / mounts where derived
```

## 22.3 Explicit reveal

If the project later supports revealing secret values, it MUST require an explicit high-friction operation governed by host policy and audit semantics.

Secret bytes MUST NOT flow into ordinary command history, terminal scrollback capture or provider logs by default.

## 22.4 Relationships remain useful

The provider SHOULD still model relationships such as:

```text
Pod -> references-secret -> Secret
ServiceAccount -> uses-image-pull-secret -> Secret
```

without exposing payload.

---

# 23. Relationship Model Overview

Kubernetes relationships MUST be categorized by evidence source.

## 23.1 Direct provider-declared relationship

A relationship explicitly encoded by Kubernetes object fields.

Examples:

```text
Pod.spec.nodeName -> scheduled-on -> Node
Pod.spec.serviceAccountName -> runs-as -> ServiceAccount
PVC.spec.volumeName -> bound-to -> PV
```

## 23.2 Owner-reference relationship

A relationship encoded by `metadata.ownerReferences`.

Examples commonly include:

```text
ReplicaSet -> owned-by -> Deployment
Pod -> owned-by -> ReplicaSet
Job -> owned-by -> CronJob
```

The provider MUST preserve the actual owner-reference record and controller flag.

## 23.3 Selector-derived relationship

A relationship derived by evaluating a Kubernetes selector against labels.

Examples:

```text
Service -> selects -> Pod
Deployment -> selector-matches -> Pod/ReplicaSet candidates
NetworkPolicy -> selects -> Pod
```

Selector-derived edges MUST identify the selector and observed label set used as evidence.

## 23.4 Controller convention relationship

Some useful relationships are encoded through well-known labels/annotations rather than generic API structure.

These MUST be tagged as convention-derived with the exact key/value evidence.

## 23.5 Inference

Name similarity, IP matching without unique context, image-name similarity or human conventions MUST NOT be promoted to verified relationships.

They MAY be exposed later as explicit inferences under the cross-system confidence model.

## 23.6 Relationship freshness

A derived edge's freshness is bounded by the freshness of every source fact used to derive it.

---

# 24. Ownership Graph

## 24.1 Owner references

The provider MUST expose every valid owner reference as an inspectable edge even if the owner object cannot be read.

A missing target MUST remain a dangling relationship with target identity evidence rather than disappearing.

## 24.2 Namespace rules

The provider MUST respect Kubernetes owner-reference scope semantics.

It MUST NOT resolve cross-namespace namespaced ownership as if valid merely because an object with the requested name exists elsewhere.

## 24.3 Controller owner

Where `controller: true`, the edge SHOULD carry a stronger semantic label such as:

```text
controlled-by
```

while preserving generic `owned-by` semantics.

## 24.4 Garbage collection relevance

Destructive-change planning SHOULD use ownership edges to identify dependents potentially affected by deletion propagation.

This is impact evidence, not a guarantee of exact deletion order.

---

# 25. Workload Controller Relationships

## 25.1 Deployment

For `apps/v1 Deployment`, curated relationships SHOULD include:

```text
Deployment -> controls/owns -> ReplicaSet
Deployment -> selector-matches -> Pods or ReplicaSets
Deployment -> uses-template -> PodTemplate semantics
```

The owner-reference chain is canonical for actual controlled ReplicaSets.

## 25.2 ReplicaSet

Curated relationships SHOULD include:

```text
ReplicaSet -> owned-by -> Deployment when present
ReplicaSet -> controls/owns -> Pod
ReplicaSet -> selector-matches -> Pod candidates
```

## 25.3 StatefulSet

Curated relationships SHOULD include:

```text
StatefulSet -> controls/owns -> Pod
StatefulSet -> uses -> Service where serviceName resolves
StatefulSet -> creates/relates -> PVC through volumeClaimTemplates evidence
```

The provider MUST distinguish template intent from currently materialized PVC objects.

## 25.4 DaemonSet

Curated relationships SHOULD include:

```text
DaemonSet -> controls/owns -> Pod
Pod -> scheduled-on -> Node
```

This supports traversing rollout coverage across nodes.

## 25.5 Jobs and CronJobs

Curated relationships SHOULD include:

```text
CronJob -> owns -> Job
Job -> owns -> Pod
```

Job history limits and deleted children mean the live graph may be incomplete. Historical absence MUST not be reconstructed without evidence.

---

# 26. Service and Endpoint Relationships

## 26.1 Service selection

For selector-based Services:

```text
Service -> selects -> Pod
```

MUST be derived using the Service's selector against observed Pod labels in the same namespace.

An empty selector or selector-less Service MUST not create guessed Pod edges.

## 26.2 EndpointSlice

EndpointSlice is the preferred endpoint resource for the curated graph.

The provider SHOULD relate:

```text
Service -> represented-by -> EndpointSlice
EndpointSlice -> endpoint-for -> Pod when targetRef resolves
EndpointSlice -> exposes-address -> endpoint address
```

The service relationship SHOULD use the standard service-name label when present and preserve that evidence.

## 26.3 Multiple slices

A Service can be represented by multiple EndpointSlices.

The provider MUST aggregate them only in derived views; each EndpointSlice remains a first-class resource with its own identity and freshness.

## 26.4 External endpoints

EndpointSlice endpoints without Pod target references MUST remain endpoint facts rather than being forced into Pod relationships.

## 26.5 Service type

Service `type`, cluster IPs, external IPs, load-balancer status and ports SHOULD be typed fields available for routing and cross-system reasoning.

---

# 27. Ingress, Gateway and Routing

## 27.1 Ingress

For served `networking.k8s.io/v1 Ingress`, curated relationships SHOULD include:

```text
Ingress -> routes-to -> Service
Ingress -> uses-tls-secret -> Secret
Ingress -> has-address -> status load-balancer address
```

Path, host and port evidence MUST remain attached to routing edges.

## 27.2 Ingress class

The provider SHOULD expose relationships to IngressClass when resolvable from native fields.

## 27.3 Gateway API

Gateway API is not assumed to be present in every cluster.

If installed, its CRDs MUST already work through universal dynamic support.

A curated Gateway API adapter MAY add richer relationships such as:

```text
Gateway -> uses -> GatewayClass
HTTPRoute -> attaches-to -> Gateway
HTTPRoute -> routes-to -> Service
```

Such support MUST be version/schema aware and MUST NOT hard-code the presence of Gateway API into the provider core.

---

# 28. Scheduling and Node Relationships

## 28.1 Scheduled Pod

`Pod.spec.nodeName` provides direct evidence for:

```text
Pod -> scheduled-on -> Node
```

## 28.2 Unscheduled Pod

A Pod without `spec.nodeName` MUST not have a guessed scheduled-on edge.

Scheduler constraints MAY be exposed separately as intent/evidence:

```text
nodeSelector
nodeAffinity
podAffinity
podAntiAffinity
tolerations
topologySpreadConstraints
```

## 28.3 Node placement metadata

Node labels describing zone, region, instance type, hostname and architecture SHOULD remain available as typed properties and may support cross-system resolution.

## 28.4 providerID

`Node.spec.providerID`, when present, MUST be exported as high-value cross-system identity evidence.

The Kubernetes provider MUST NOT itself contain AWS/Azure/GCP parsing policy beyond safe decomposition needed to preserve the raw identifier and recognized URI structure.

## 28.5 Node addresses

Node status addresses MAY be exported as weaker cross-system identity evidence with type information such as:

```text
InternalIP
ExternalIP
Hostname
```

IP equality alone MUST not establish a verified cloud-resource edge.

---

# 29. Configuration Dependencies

## 29.1 ConfigMap references

The provider SHOULD derive relationships from Pod/container specifications for:

```text
envFrom ConfigMapRef
env valueFrom configMapKeyRef
volume configMap source
projected configMap source
```

Example:

```text
Pod -> references-config -> ConfigMap
```

The edge SHOULD retain how the ConfigMap is consumed.

## 29.2 Secret references

Equivalent Secret references SHOULD create redaction-safe relationships.

## 29.3 Optional references

When Kubernetes marks a reference optional, the relationship edge SHOULD preserve that fact.

A missing optional target is not equivalent to an error.

## 29.4 Immutable configuration

Where ConfigMap/Secret immutable flags exist, the provider SHOULD expose them because they affect prospective-change semantics.

---

# 30. Storage Relationships

## 30.1 Pod volumes

The provider SHOULD map typed volume sources rather than flattening all volumes into one string.

For persistent volumes:

```text
Pod -> mounts -> PVC
PVC -> bound-to -> PV
PV -> provisioned-by / storage-class -> StorageClass
```

## 30.2 PVC binding

`PVC.spec.volumeName` and relevant status fields provide direct binding evidence.

A Pending PVC with no volumeName MUST not be treated as bound.

## 30.3 StorageClass

StorageClass provisioner, reclaim policy, volume binding mode and expansion capability SHOULD be exposed for change/risk reasoning.

## 30.4 CSI

Where resolvable, the provider MAY expose relationships among:

```text
PV
CSIDriver
CSINode
VolumeAttachment
Node
```

Provider-specific cloud volume resolution belongs to cross-system resolvers, not Kubernetes core logic.

## 30.5 Deletion implications

Reclaim policy and finalizers MUST be visible when planning PVC/PV deletion because deleting a Kubernetes object may trigger storage consequences outside Kubernetes.


# 31. NetworkPolicy and Network Relationships

## 31.1 Policy selection

For `NetworkPolicy`, the provider SHOULD expose selector-derived relationships to affected Pods.

Example:

```text
NetworkPolicy -> selects -> Pod
```

The edge MUST preserve namespace and selector evidence.

## 31.2 Peer semantics

Ingress and egress peers combine namespace selectors, pod selectors and IP blocks.

The provider MUST preserve their native structure. It MUST NOT reduce a policy to a misleading boolean such as `internet_access = false` unless a later network reasoning layer can prove that claim with complete coverage.

## 31.3 Policy effectiveness

The presence of a NetworkPolicy object does not prove enforcement by the installed networking implementation.

Ono MAY show policy intent from API state, but MUST distinguish intent from observed packet behavior.

## 31.4 Service networking

ClusterIP, ports, target ports, protocols and endpoint addresses SHOULD be exposed as structured fields suitable for later relation to local sockets or cloud load balancers.

---

# 32. Identity and RBAC Resources

## 32.1 ServiceAccount

Curated relationships SHOULD include:

```text
Pod -> runs-as -> ServiceAccount
ServiceAccount -> uses-image-pull-secret -> Secret
```

The provider MUST account for namespace-local ServiceAccount identity.

## 32.2 Role and ClusterRole

Roles and ClusterRoles SHOULD remain structured rule sets.

The provider MAY expose semantic edges such as:

```text
RoleBinding -> binds -> Role
ClusterRoleBinding -> binds -> ClusterRole
RoleBinding -> grants-to -> Subject
```

## 32.3 Subjects

RBAC subjects such as User and Group are not ordinary stored Kubernetes API objects.

The provider MAY represent them as typed external identity references, but MUST NOT invent resource UIDs or imply that Kubernetes stores a corresponding object.

## 32.4 Effective permissions

Relationship traversal through bindings is useful explanatory data but MUST NOT be presented as a complete effective authorization calculation because admission, authorizer configuration and dynamic policy may affect actual decisions.

Specific authorization questions SHOULD defer to SubjectAccessReview APIs where appropriate.

---

# 33. CRDs and Arbitrary Custom Resources

## 33.1 CRDs are mandatory architecture support

The provider is not conformant if custom resources are only displayed as raw JSON while built-in resources receive all typed behavior.

A newly installed CRD MUST be discoverable without rebuilding Ono.

## 33.2 CRD lifecycle

The provider SHOULD detect:

```text
CRD added
served version added/removed
storage version changed
schema changed
CRD deleted
```

through discovery/schema invalidation and relevant watches where active.

## 33.3 Custom resource schema

When a CRD publishes structural OpenAPI schema, the provider SHOULD use it to create typed field descriptions and validation-aware presentation.

## 33.4 Additional printer columns

CRD additional printer columns MAY inform default presentation, but they MUST remain presentation hints rather than the canonical resource schema.

## 33.5 Scale subresource

If a custom resource exposes the standard `scale` subresource, the provider MAY expose generic scalable-workload capability without knowing the CRD's domain.

The capability MUST be discovered rather than assumed.

## 33.6 Status subresource

If a CRD separates `status`, the provider SHOULD preserve desired/observed semantics and mutation boundaries.

## 33.7 Generic relationships

All custom resources can receive relationships from generic mechanisms where valid:

- ownerReferences;
- namespaced/cluster scope;
- explicit object references discoverable through future schema annotations;
- optional adapter rules;
- cross-system identity evidence adapters.

The provider MUST NOT scan every arbitrary string field and guess relationships by matching names.

## 33.8 Semantic adapter registry

Curated CRD knowledge SHOULD be implemented through provider-side adapters keyed by group/kind/version compatibility.

An adapter MAY contribute:

```text
semantic roles
relationship extractors
default views
prospective effects
verification rules
cross-system identity evidence
```

An adapter MUST NOT replace the underlying dynamically discovered object representation.

---

# 34. Aggregated API Servers

## 34.1 Normal discovery path

Resources served through the Kubernetes aggregation layer MUST appear through the same provider discovery model as other APIs.

## 34.2 Failure isolation

An unavailable aggregated API group MUST NOT make the entire Kubernetes provider unavailable if the core API server remains usable.

Coverage SHOULD report the failed group/version separately.

## 34.3 Latency and health

Aggregated APIs may have different performance and availability characteristics.

The provider SHOULD preserve per-request source group and latency diagnostics rather than attributing every failure generically to "the cluster".

## 34.4 Metrics API

If `metrics.k8s.io` is served, it MAY be consumed as an optional observation source.

Its presence MUST NOT be required for provider conformance and its values MUST remain observations with their own freshness/provenance.

---

# 35. Spatial Mapping

## 35.1 One Ono world, not a Kubernetes mode

Connecting Kubernetes adds places to Ono's existing world. It MUST NOT create an isolated grammar such as:

```text
k8s> get pods
k8s> describe service
```

as the native interaction model.

## 35.2 Cluster root

A provider instance SHOULD expose a root place analogous to:

```text
k8s://prod/
```

## 35.3 Namespace places

Namespaces SHOULD be directly enterable:

```text
k8s://prod/ns/production/
```

Exact URI grammar may be consolidated later, but URI identity MUST remain stable and machine-parseable.

## 35.4 Resource places

First-class resources SHOULD be enterable when meaningful:

```text
k8s://prod/ns/production/pod/checkout-7c9...
k8s://prod/cluster/node/worker-03
```

The place MUST bind the resource's lifetime identity when known, not only its mutable name.

## 35.5 `near`

`near` SHOULD prioritize operationally relevant graph neighbors rather than arbitrary objects in the same namespace.

For a Service, for example:

```text
selected Pods
EndpointSlices
Ingress/Gateway routes
related NetworkPolicies where evidence exists
```

## 35.6 `up`

`up` is a spatial/context operation, not an owner-reference shortcut.

A namespace may be the spatial parent of a Pod even though its Deployment is the semantic owner through a ReplicaSet.

## 35.7 `follow`

`follow` traverses named relationship types:

```text
follow owned-by
follow scheduled-on
follow selects
follow routes-to
follow bound-to
```

## 35.8 Ambiguous names

If multiple resource types share a name in a namespace, name-only entry MUST prompt/require disambiguation rather than choosing by an arbitrary type priority.

---

# 36. Semantic Roles

## 36.1 Provider-native first

Native Kubernetes types remain canonical. Semantic roles are overlays for cross-provider queries.

## 36.2 Initial role candidates

Kubernetes MAY map resources to small generic roles such as:

```text
workload
compute-node
network-endpoint
service-endpoint
configuration
secret
identity
storage
policy
```

Exact role definitions belong to the generic role registry as it matures.

## 36.3 No false equivalence

A Deployment is not an AWS Auto Scaling Group merely because both can produce compute capacity.

A semantic role MAY support broad discovery while native semantics remain inspectable.

---

# 37. Conditions and Desired/Observed State

## 37.1 Preserve native conditions

Resources exposing a `status.conditions` pattern SHOULD present conditions as structured values with fields such as:

```text
type
status
reason
message
observedGeneration where present
lastTransitionTime where present
```

## 37.2 Condition semantics are kind-specific

The provider MUST NOT assume that every resource uses condition types consistently.

Curated adapters MAY understand specific well-known conditions for core resources.

## 37.3 observedGeneration

Where a condition or status exposes observed generation, it SHOULD be used as evidence that a controller has observed a particular desired-state generation.

It MUST NOT by itself be labeled "healthy" or "successful."

## 37.4 Phase fields

Fields such as Pod phase MAY be surfaced as useful summaries, but default rendering SHOULD not hide richer conditions and container status when diagnosing failure.

## 37.5 Reconciliation state

Ono MAY derive explicit states such as:

```text
desired state changed; controller not yet observed
controller observed; convergence pending
converged by provider-specific rule
failed by provider-specific rule
unknown due to insufficient evidence
```

Every derived state MUST cite the fields/conditions on which it depends.

---

# 38. Kubernetes Events

## 38.1 Supplemental evidence only

Kubernetes Events are best-effort, limited-retention observations. The provider MUST NOT treat them as a durable audit log or complete causal history.

## 38.2 Event API

The provider SHOULD prefer the stable `events.k8s.io/v1` representation when served and may fall back to compatible core Event representations when necessary.

## 38.3 Regarding relationships

An Event SHOULD relate to the object it refers to when the involved/regarding object identity can be resolved.

The edge MUST preserve source identity and timestamp semantics.

## 38.4 Event aggregation

Repeated events may be aggregated by Kubernetes.

Ono MUST preserve count/series semantics where provided and MUST NOT fabricate individual occurrences that were not observed.

## 38.5 Reason and message

`reason` and human `note/message` are useful evidence but MUST NOT be used as stable machine semantics without a curated adapter because upstream warns that event reasons/messages can evolve.

## 38.6 Event gaps

Absence of an Event MUST never prove that an action or failure did not occur.

---

# 39. Temporal Integration

## 39.1 Sources of temporal evidence

The Kubernetes provider can contribute temporal observations from:

```text
watch events
resource snapshots
Kubernetes Events
metadata creation/deletion timestamps
condition transition timestamps
managedFields timestamps where useful
```

Each source has different coverage and semantics.

## 39.2 No retroactive history from current state

If Ono starts observing a cluster at 14:00, it MUST NOT claim a complete history of resource changes before 14:00 merely because objects contain creation timestamps or current status.

## 39.3 Watch history

A watch can provide ordered API change observations only for the period actually observed without unresolved gaps.

## 39.4 State snapshots

Periodic or user-triggered snapshots MAY support `diff` across observed states.

A difference between snapshots proves state difference, not the exact sequence of intermediate changes.

## 39.5 Audit logs

Kubernetes audit logs are outside the base provider because they are not universally accessible through the normal resource API.

A future audit-log observation source MAY enrich temporal evidence if explicitly configured and permissioned.

---

# 40. `why` and Causal Discipline

## 40.1 Evidence graph, not narrative invention

The provider MUST contribute evidence to Ono's inherited causal model rather than generating authoritative natural-language causes from heuristics.

## 40.2 Example: Pending Pod

For a pending Pod, evidence MAY include:

```text
Pod condition: PodScheduled=False
condition reason: Unschedulable
scheduler Event note
node selector constraints
PVC binding state
resource requests
```

Ono MAY summarize these facts, but a causal claim MUST be no stronger than the evidence.

## 40.3 Example: unhealthy Service

The graph MAY establish:

```text
Service selects Pods
EndpointSlices contain no ready endpoints
selected Pods are not Ready
Pod readiness failure follows container probe failures
```

This can support a strong operational explanation without claiming that a specific deployment change caused the failure unless temporal/evidence rules justify it.

## 40.4 Controller causality

Owner/controller relationships indicate management responsibility, not necessarily cause of every state change.

## 40.5 Unknown

`why` MUST be allowed to conclude:

```text
insufficient evidence
```

That outcome is preferable to a plausible invented explanation.

---

# 41. Live Views

## 41.1 Existing live-view model

The provider MUST use the inherited Ono live-view contract rather than creating a Kubernetes-specific TUI subsystem.

## 41.2 Live collection

A live view of Pods, Deployments or other resources SHOULD be backed by watch-capable resource streams where practical.

## 41.3 Relationship-live views

A live view MAY display a resource and changing neighbors, for example:

```text
Service checkout
  selected Pods: 4 -> 3
  ready endpoints: 4 -> 2
  EndpointSlices: 2
```

Changes MUST be driven by typed provider observations, not screen scraping.

## 41.4 Sync and gap indication

Live views MUST expose meaningful states such as:

```text
syncing
live
reconnecting
gap detected
stale
denied
```

A disconnected watch MUST not leave a frozen table that visually appears live.

---

# 42. Logs, Exec, Attach and Port Forward

These operations are operationally important but cross security and terminal/job-control boundaries. They require explicit design.

## 42.1 Logs

Pod/container logs MAY be exposed as a typed/byte stream capability.

The provider SHOULD support:

- container selection;
- previous container logs where upstream supports it;
- timestamps where requested;
- follow mode;
- cancellation;
- bounded tail/since parameters.

Logs are observations and MUST carry target/provenance metadata.

## 42.2 Log secrecy

Logs may contain secrets. They MUST follow normal shell stream/history policy and MUST NOT be silently persisted as provider cache or temporal history.

## 42.3 Exec

Remote exec into a container is NOT an ordinary resource mutation.

If supported, it MUST use a dedicated remote-execution capability integrated with Ono terminal/job-control and KUANG/11 security policy.

The provider MUST make target cluster, namespace, Pod and container explicit before execution.

## 42.4 Attach

Attach has similar terminal-stream semantics and SHOULD share the remote-session infrastructure rather than be implemented as an opaque provider callback.

## 42.5 Port forward

Port forwarding is a temporary transport/session capability, not a persistent Kubernetes resource.

If supported, Ono MUST represent its lifecycle as a job/session with clear local and remote endpoints.

## 42.6 No hidden `kubectl` subprocess

Native implementation SHOULD use Kubernetes API protocols/libraries. Invoking `kubectl logs`, `kubectl exec` or `kubectl port-forward` as hidden implementation detail is an anti-pattern unless explicitly justified as a temporary compatibility bridge.

---

# 43. Mutation Principles

## 43.1 Read-only usefulness first

The provider MUST be valuable and conformant at read/relationship/watch maturity before broad mutation is required.

## 43.2 Native API mutation

Mutations SHOULD use Kubernetes API operations directly through a supported client stack.

They MUST preserve API preconditions, field ownership and conflict semantics.

## 43.3 Bounded action surface

The provider SHOULD expose actions that map to understandable Kubernetes state transitions rather than every raw HTTP verb as a user-facing action.

Examples of candidate bounded actions:

```text
scale workload
restart rollout through an explicit supported mechanism
set image
apply bounded field change
delete resource
annotate / label
cordon / uncordon node
```

Exact action delivery is implementation-phased.

## 43.4 Generic raw mutation escape hatch

A low-level expert operation MAY allow structured patch/apply of arbitrary resources.

It MUST be explicitly low-level, preserve schema/field ownership, and integrate with the same planning and confirmation gates.

It MUST NOT become the default UX simply because it is easy to implement.

---

# 44. Server-Side Apply and Field Ownership

## 44.1 Preferred structured apply mechanism

Where the provider supports declarative field changes, server-side apply SHOULD be considered because Kubernetes tracks field ownership and conflicts.

## 44.2 fieldManager

Ono MUST use a stable, identifiable field manager name for server-side apply operations.

The field manager SHOULD distinguish Ono native changes from unrelated controllers/tools.

## 44.3 Conflicts

An apply conflict MUST be surfaced as a conflict with ownership evidence.

Ono MUST NOT automatically force ownership merely to make the action succeed.

## 44.4 Force

Force-conflict behavior, if exposed, MUST be a separate explicit high-risk choice in prospective-change output.

## 44.5 Dry-run

Kubernetes server-side dry-run SHOULD be used when available for mutation preview because it can execute admission/defaulting without persistence.

However:

> A successful Kubernetes dry-run is not a proof of post-apply convergence.

It predicts API acceptance semantics better than controller/runtime effects.

## 44.6 Admission effects

Dry-run results MAY reveal defaulted or mutated fields produced by admission. Ono SHOULD diff requested versus dry-run returned objects when useful.

---

# 45. Delete, Finalizers and Garbage Collection

## 45.1 Delete is asynchronous

A successful DELETE response does not necessarily mean the object and its effects are gone.

The provider MUST distinguish:

```text
deletion accepted
deletionTimestamp set
finalizers remaining
object absent
known dependents absent
external effects unknown
```

## 45.2 Propagation policy

Foreground, background and orphan deletion semantics MUST be preserved when exposed.

Prospective-change output SHOULD state the selected propagation policy.

## 45.3 Finalizers

If finalizers are present, the plan MUST state that deletion completion depends on their removal.

## 45.4 Owner dependents

Known ownership edges SHOULD inform impacted/dependent resource preview.

The provider MUST mark coverage limits: inability to list a dependent type means dependency impact may be incomplete.

## 45.5 Persistent storage

Deleting a PVC, PV, StatefulSet or namespace may trigger effects involving storage and cloud resources. The provider MUST show known reclaim/finalizer evidence and MUST NOT promise full rollback.

---

# 46. Prospective Change and Verification

## 46.1 Inherit v0.6 semantics

Every native Kubernetes mutation MUST map into the existing Ono proposed-state/change-plan model.

## 46.2 Plan content

A change plan SHOULD include:

```text
target resource identity
current resourceVersion / precondition context
requested field/action change
server dry-run result when available
admission/defaulting differences
known dependent resources
expected reconciliation signals
known destructive effects
permission preflight result
recovery possibilities and limitations
uncertainty / incomplete coverage
```

## 46.3 Verification is domain-specific

Verification rules MUST match action semantics.

Examples:

**Scale Deployment**

```text
API accepted replicas=N
Deployment generation advanced
controller observed generation
available/ready replicas satisfy chosen policy
```

**Change container image**

```text
Pod template changed
new ReplicaSet observed
rollout progresses
new Pods ready
old ReplicaSet scales down according to strategy
```

**Cordon Node**

```text
Node.spec.unschedulable == true
```

## 46.4 Timeouts

Reconciliation verification MUST have explicit timeouts/cancellation.

A timeout means:

```text
verification incomplete
```

not automatically:

```text
change failed
```

unless provider-specific evidence proves failure.

## 46.5 Recovery claims

A previous object spec MAY sometimes be reapplied, but that is not equivalent to full rollback.

The provider MUST state possible irreversibility such as:

- deleted ephemeral data;
- external side effects;
- new connections/requests;
- storage reclaim behavior;
- controller actions that occurred during the changed state;
- admission results that may differ on reapply.


# 47. Cross-System Identity Evidence

## 47.1 Export evidence, do not resolve foreign domains

The Kubernetes provider MUST export identity evidence that a generic cross-system resolver can consume.

It MUST NOT embed AWS, Azure, GCP or host inventory logic in Kubernetes-specific relationship code.

## 47.2 Node evidence

High-value Node evidence SHOULD include, where present:

```text
spec.providerID
status.addresses by address type
metadata.uid
metadata.name
well-known topology labels
kubelet/container runtime identifiers where available through allowed sources
```

`providerID` SHOULD be treated as stronger evidence than IP/name matching.

## 47.3 Pod/container evidence

Container status MAY expose runtime container IDs and image IDs.

These SHOULD be exportable as identity evidence for future local/container-runtime providers.

The provider MUST preserve the runtime scheme rather than stripping it into an ambiguous opaque string.

## 47.4 Load-balancer evidence

Service and Ingress load-balancer status addresses SHOULD be exportable for later resolution to cloud load-balancer resources.

An IP or hostname match alone remains resolver evidence, not a Kubernetes-verified foreign relationship.

## 47.5 Storage evidence

CSI volume handles and driver identities MAY be exported for later resolution to cloud/block-storage resources.

## 47.6 Image evidence

Container image references and resolved image IDs MAY be exported for future registry/image relationships.

Tag equality MUST not be confused with digest identity.

## 47.7 Evidence inspection

Cross-system evidence MUST be inspectable even before a foreign provider is connected.

Example:

```text
node worker-03
cross-system evidence:
  providerID: aws:///eu-central-1a/i-0123456789
  InternalIP: 10.42.0.17
  hostname: ip-10-42-0-17
```

---

# 48. Error Mapping and Partial Failure

## 48.1 Kubernetes Status objects

API failures returning Kubernetes `Status` objects SHOULD preserve structured fields such as:

```text
status
reason
message
code
details.name
details.group
details.kind
causes
retryAfterSeconds where present
```

## 48.2 Error taxonomy

The provider MUST map upstream errors into the generic provider taxonomy while retaining native detail.

At minimum distinguish:

```text
unauthenticated
authorization_denied
not_found
conflict
invalid
rate_limited
server_timeout
timeout
service_unavailable
api_not_served
watch_expired
transport_error
tls_error
credential_error
schema_error
partial_result
cancelled
```

## 48.3 404 ambiguity

A 404 can mean an object is absent or an endpoint/resource is not served.

The provider SHOULD use discovery/request context to preserve this distinction.

## 48.4 409 conflict

Conflicts MUST retain resourceVersion/field-manager context where relevant and MUST not be silently retried as destructive overwrite.

## 48.5 Invalid objects

Admission/validation errors SHOULD expose field causes in structured form suitable for Ono inspection.

## 48.6 Aggregated partial failure

If an all-resource view spans several GVRs and one API group is unavailable, successful resources MAY remain visible with explicit incomplete coverage.

---

# 49. API Priority, Fairness, Rate Limits and Retries

## 49.1 Respect the API server

Ono is an interactive shell, not a load generator.

The provider MUST bound concurrency and SHOULD use efficient list/watch patterns.

## 49.2 429 handling

Rate-limited responses MUST be represented as rate limiting, not generic network failure.

`Retry-After` or equivalent upstream retry guidance SHOULD be honored.

## 49.3 Retry classes

Safe idempotent reads MAY be retried with bounded exponential backoff and jitter.

Mutation retries MUST consider Kubernetes idempotency and preconditions. A timed-out mutation whose server outcome is unknown MUST NOT be blindly replayed if replay can duplicate side effects.

## 49.4 Watch backoff

Watch reconnect loops MUST be bounded and cancellable. Repeated failures SHOULD transition a live view to a visible degraded state.

## 49.5 Client-side throttling

The provider SHOULD expose configurable query concurrency/QPS/burst policy with conservative defaults aligned with interactive use.

---

# 50. Performance Requirements

## 50.1 Shell responsiveness

Connecting a large cluster MUST NOT freeze parser, prompt or unrelated local shell operations.

All remote work MUST be asynchronous/cancellable according to Ono host semantics.

## 50.2 Discovery cost

Discovery and OpenAPI loading SHOULD be cached and incrementally refreshed rather than downloaded before every query.

## 50.3 Lazy schema

The provider MAY load detailed schemas lazily by group/type to avoid making first connection depend on full OpenAPI processing.

## 50.4 Relationship indexes

Selector and owner-reference relationships MAY use indexes maintained over active caches.

Indexes MUST track cache sync/freshness. An incomplete index MUST not return an unqualified complete-looking graph.

## 50.5 Large CRDs

Resources with very large object payloads or very large populations SHOULD support field projection/lazy expansion where Ono's generic value model allows it.

## 50.6 Default output

Default views SHOULD prioritize operationally useful fields and avoid serializing entire objects merely to render a list.

---

# 51. Security and KUANG/11 Isolation

## 51.1 Minimum host capabilities

The provider should require only capabilities it actually uses, potentially including:

```text
network access to configured API server origins
read access to configured kubeconfig paths through host broker
credential broker access
conditional process execution for exec auth plugins
host time/cancellation
```

## 51.2 Network allow-list

Network capability SHOULD be constrained to the configured API server and explicitly required credential-plugin endpoints where architecture supports such restriction.

A Kubernetes provider MUST NOT receive unrestricted network access by default merely because clusters are remote.

## 51.3 File access

The provider SHOULD not receive arbitrary filesystem read capability.

Kubeconfig, certificate and referenced credential files SHOULD be opened through host-brokered paths/policies.

## 51.4 Process execution

Exec credential plugins are the primary justified subprocess use in the base provider.

Their invocation MUST be auditable as credential-plugin execution and MUST not turn into general shell command access.

## 51.5 Secret resource data

Even if the Kubernetes API authorizes reading Secret payloads, KUANG/11/host policy MAY impose additional reveal restrictions.

Provider authorization is necessary but not always sufficient for local presentation policy.

## 51.6 Audit

Provider diagnostics SHOULD record non-secret audit metadata for connection, permission failures, mutations and credential-plugin invocations according to Ono's inherited audit contract.

---

# 52. Presentation and Discoverability

## 52.1 Typed values precede Kubernetes-style tables

The provider MAY emulate familiar useful columns, but rendering MUST be derived from typed values.

## 52.2 Default Pod view

A default Pod list MAY emphasize:

```text
name
namespace
ready
status/phase
restarts
age
node
```

but all values MUST derive from structured fields and retain native detail for `inspect`.

## 52.3 Resource detail

A default resource detail SHOULD organize information by semantics rather than dump YAML first:

```text
Identity
Desired state
Observed state / conditions
Relationships
Events / recent observations
Permissions relevant to common actions
Cross-system evidence
Raw/native fields
```

## 52.4 YAML/JSON

Users MAY request native YAML/JSON projection for interoperability and debugging.

That is an output representation, not the provider's internal truth model.

## 52.5 Context prompt

When inside Kubernetes context, the prompt/context display SHOULD make at least provider instance and namespace visible enough to reduce wrong-cluster operations.

Production/high-risk labeling MAY be added by configuration but MUST not be inferred solely from context names.

---

# 53. Native Ono Interaction Examples

The exact grammar remains governed by existing Ono command specifications. These examples are semantic acceptance examples, not a new parser contract.

## 53.1 Enter a cluster

```text
> enter provider kubernetes:prod

k8s://prod/ >
```

## 53.2 Enter a namespace

```text
k8s://prod/ > enter namespace production

k8s://prod/ns/production >
```

## 53.3 Find workloads

```text
> find place --role workload
```

A result MAY contain Deployments, StatefulSets, DaemonSets, Jobs and compatible CRDs while preserving native type.

## 53.4 Service neighborhood

```text
> enter service checkout
> near
```

Expected semantic neighborhood:

```text
Service checkout
  represented-by -> EndpointSlice checkout-abc
  represented-by -> EndpointSlice checkout-def
  selects -> Pod checkout-7c9...
  selects -> Pod checkout-2fd...
  routed-from <- Ingress public
```

## 53.5 Follow to node

```text
> enter pod checkout-7c9...
> follow scheduled-on
```

## 53.6 Inspect relation evidence

```text
> explain relation selected-by
```

Output SHOULD show the exact selector and Pod label snapshot used to derive the edge.

## 53.7 Live troubleshooting

```text
> enter deployment checkout
> live near
```

The view MAY update ReplicaSets, Pods and readiness observations while exposing watch sync state.

## 53.8 Temporal comparison

```text
> diff now -10m
```

Only changes actually supported by observed snapshots/watch coverage may be claimed.

## 53.9 Safe change

```text
> plan scale 6
```

The plan SHOULD show current replicas, desired replicas, permission preflight, known autoscaler interaction where observable, and verification conditions before `apply`.

---

# 54. Autoscaling and Controller Interaction

## 54.1 Competing desired-state writers

Kubernetes objects are often modified by controllers, GitOps systems, autoscalers and humans.

Before mutation, Ono SHOULD expose known competing writers when evidence exists in:

- managedFields;
- owner relationships;
- HorizontalPodAutoscaler targets;
- curated GitOps annotations/adapters;
- admission/controller conventions.

## 54.2 HorizontalPodAutoscaler

When scaling a workload targeted by an HPA, the plan SHOULD warn that a direct replica change may be overwritten/reconciled by the autoscaler.

The provider MUST NOT claim durable effect merely because the Deployment accepted `spec.replicas`.

## 54.3 GitOps

The base provider cannot know every external reconciler.

Curated adapters MAY expose evidence that a resource is managed by a GitOps controller. Such evidence SHOULD generate a prospective-change warning rather than block mutation categorically.

---

# 55. Namespace Semantics and Bulk Operations

## 55.1 Namespace as operational boundary

Namespace context SHOULD constrain discovery by default for namespaced resources.

## 55.2 Namespace deletion

Deleting a Namespace is a high-impact destructive operation and MUST receive enhanced prospective analysis.

The plan SHOULD include:

- known contained resource counts by GVR;
- resource types that could not be listed;
- namespace finalizers;
- known PVC/PV implications;
- admission/authorization state;
- explicit statement that external side effects may outlive namespace deletion.

## 55.3 Bulk mutation

Any bulk mutation across multiple resources MUST enumerate/resolvably freeze targets before execution or explicitly define dynamic selection semantics.

A selector-based mutation MUST show whether the target set is evaluated at plan time, apply time or both.

## 55.4 Partial bulk failure

Bulk operations MUST return per-target outcomes and aggregate incomplete status. One successful target MUST not hide failures of others.

---

# 56. API Object Mutation Preconditions

## 56.1 Lost update prevention

Where practical, update/patch operations SHOULD use Kubernetes preconditions or resourceVersion-aware semantics to avoid overwriting unseen concurrent changes.

## 56.2 Plan staleness

A prospective plan built from resourceVersion X SHOULD be considered stale if the target has materially changed before apply.

The host/provider SHOULD require re-plan or explicit conflict handling rather than silently applying the old assumption.

## 56.3 UID precondition

Destructive operations SHOULD use UID preconditions where Kubernetes supports them so that a same-name recreated object is not accidentally deleted by a stale plan.

## 56.4 Generated objects

Mutating controller-generated children directly SHOULD be allowed only when the action is explicit and the provider can show the controlling owner relationship.

Ono SHOULD guide users toward the controlling resource when that better matches intent, without forbidding expert operations.

---

# 57. Provider Manifest Requirements

In addition to the generic external-provider manifest, the Kubernetes provider manifest SHOULD declare capabilities such as:

```yaml
provider:
  id: kubernetes
  domain: kubernetes

capabilities:
  discovery: true
  dynamic_schemas: true
  namespaced_scopes: true
  cluster_scopes: true
  watch: true
  relationships: true
  temporal_observations: true
  mutations: conditional
  remote_logs: conditional
  remote_exec: conditional
  port_forward: conditional

security:
  network: configured-origins
  filesystem: brokered-kubeconfig
  process_exec: exec-credential-only-by-default
```

Exact manifest schema follows the generic provider/extension contract.

## 57.1 Dynamic capability reporting

Runtime diagnostics MUST distinguish manifest-declared potential capability from session-effective capability.

Example:

```text
watch: supported by provider, available on resource
mutate deployment: supported by provider, denied for current user
exec auth: supported by provider, blocked by local KUANG policy
```

---

# 58. Implementation Architecture Guidance

This section is normative in layering, not exact Rust module naming.

## 58.1 Recommended layers

```text
Ono generic provider host
        |
Kubernetes provider adapter
        |
+-------+--------------------------+
|                                  |
Discovery/schema                API transport
|                                  |
Dynamic type registry           auth/TLS/retry
|
Relationship extractors
|
Curated kind adapters
|
Cross-system evidence export
```

## 58.2 Kubernetes client library

The implementation SHOULD use a mature Kubernetes API/client library where it preserves required semantics for discovery, authentication, watch and API operations.

The provider MUST NOT let a client library's static generated types prevent access to unknown CRDs or future fields.

## 58.3 Dynamic client path

A dynamic/unstructured API path is mandatory for arbitrary discovered resources.

Curated built-in adapters MAY use generated/static types internally for correctness and ergonomics, but the provider architecture MUST retain a dynamic fallback.

## 58.4 Adapter registry

Curated semantics SHOULD be registered by type capability rather than scattered `if kind == ...` branches across query code.

A conceptual adapter interface may provide:

```text
supports(gvk/schema)
relationships(resource, context)
default_view(resource)
semantic_roles(resource)
prospective_effects(action)
verification(action)
cross_system_evidence(resource)
```

## 58.5 Core-free Kubernetes domain

No Kubernetes SDK type SHOULD escape into generic Ono core interfaces. Conversion occurs at the provider boundary.

---

# 59. Deterministic Test Strategy

## 59.1 No production cluster requirement

All mandatory provider conformance tests MUST run without production credentials.

## 59.2 Fixture API transport

The generic deterministic provider test host SHOULD support scripted Kubernetes HTTP/discovery/watch fixtures.

Fixtures MUST cover:

- discovery responses;
- OpenAPI/schema documents;
- list pagination;
- watch streams;
- 410 expiry;
- RBAC denial;
- Status errors;
- CRD registration/removal;
- aggregated API failure;
- mutation dry-run/apply;
- concurrent conflict;
- finalizer deletion.

## 59.3 Local integration cluster

CI SHOULD additionally run integration tests against disposable local Kubernetes clusters such as kind or an equivalent project-approved mechanism.

These tests validate real API behavior not faithfully represented by fixtures.

## 59.4 Version matrix

Local integration SHOULD cover the provider's declared upstream support window at release qualification time.

## 59.5 No external cloud dependency

Kubernetes base-provider CI MUST NOT require AWS, Azure or GCP.

Cross-system resolver integration tests may use synthetic providerID/cloud fixtures.

---

# 60. Canonical Test Scenarios

## 60.1 Dynamic CRD appears

1. Connect provider.
2. Confirm CRD absent.
3. Install CRD fixture.
4. Refresh/detect discovery change.
5. Create custom resource.
6. Query it as typed dynamic resource.
7. Verify owner references and watch behavior.

## 60.2 Object recreated with same name

1. Observe Pod UID A.
2. Delete Pod.
3. Create Pod with same name UID B.
4. Verify distinct lifetime identity and temporal discontinuity.

## 60.3 Selector changes

1. Service selects Pods A/B.
2. Change label on B.
3. Watch update.
4. Verify `selects` edge disappears with evidence change.

## 60.4 Watch expiry

1. Establish known list/watch state.
2. Inject 410 Gone.
3. Verify gap state.
4. Relist.
5. Resume live state.
6. Verify temporal history does not claim gap-free continuity.

## 60.5 Permission denial

1. Allow get Pod A.
2. Deny list Pods.
3. Verify direct get can succeed while namespace inventory reports incomplete/denied coverage.

## 60.6 Finalizer deletion

1. Delete object with finalizer.
2. API accepts deletion.
3. Verify Ono reports terminating/pending finalizer rather than "deleted".
4. Remove finalizer.
5. Observe absence.

## 60.7 Server-side apply conflict

1. Fixture field owned by another manager.
2. Ono plans field change.
3. Dry-run/apply returns conflict.
4. Verify conflict owner evidence and no automatic force.

## 60.8 Cross-system node evidence

1. Node has providerID.
2. Kubernetes provider exports raw evidence.
3. Synthetic cloud resolver maps it.
4. Verify Kubernetes package itself does not depend on cloud SDK.

---

# 61. Conformance Levels for the Kubernetes Provider

These levels specialize the generic provider maturity model.

## 61.1 K0 - Connection and discovery

Required:

- kubeconfig/explicit connection;
- secure TLS defaults;
- provider instance isolation;
- dynamic API discovery;
- cluster/namespace scopes;
- provider health/identity diagnostics.

## 61.2 K1 - Dynamic read model

Required:

- arbitrary discovered readable resources;
- dynamic schema/unstructured fallback;
- UID identity;
- metadata projection;
- get/list/pagination;
- partial coverage and RBAC truth;
- CRD support.

## 61.3 K2 - Operational graph

Required:

- owner references;
- core curated workload relations;
- Service/EndpointSlice relations;
- scheduling relations;
- config/storage relations;
- spatial integration;
- relationship evidence inspection.

## 61.4 K3 - Live Kubernetes

Required:

- list/watch continuity;
- reconnect;
- 410 gap handling;
- live-view integration;
- cache sync/freshness state;
- Events as supplemental observations.

## 61.5 K4 - Bounded safe actions

Required for claimed actions:

- authorization preflight support;
- prospective plan;
- server dry-run where applicable;
- conflict/precondition handling;
- asynchronous verification;
- scoped recovery statement;
- deletion/finalizer semantics.

## 61.6 K5 - Temporal/cross-system enrichment

Required:

- explicit observation coverage;
- resource snapshot/watch temporal integration;
- causal evidence discipline;
- exported cross-system identity evidence;
- first verified external resolver path without provider-core coupling.

---

# 62. Acceptance Gates

The Kubernetes provider is not considered architecture-proven until these gates pass.

## 62.1 Gate A - Unknown CRD

A CRD invented after Ono is built can be installed, discovered, queried, entered and watched without recompiling Ono.

## 62.2 Gate B - No raw-JSON collapse

The unknown CRD exposes a typed dynamic structure where schema is available and preserves fields where schema is incomplete.

## 62.3 Gate C - UID lifetime

Delete/recreate with same name produces two resource lifetimes.

## 62.4 Gate D - Relationship evidence

Every curated relationship can reveal whether it came from:

```text
native field
ownerReference
selector
well-known convention
adapter derivation
inference
```

and the source fields used.

## 62.5 Gate E - Namespace truth

A denied namespace/list scope cannot render as empty/complete.

## 62.6 Gate F - Watch gap truth

410 expiry produces a visible gap and never a false continuous timeline.

## 62.7 Gate G - Desired/observed separation

A successful Deployment spec update cannot be rendered as successful rollout until verification evidence arrives.

## 62.8 Gate H - Finalizer truth

Deletion accepted with finalizers remains "terminating / deletion pending," not "deleted."

## 62.9 Gate I - Secret safety

Default list/detail/navigation paths cannot reveal Secret payload values.

## 62.10 Gate J - Context isolation

Two kubeconfig contexts can be queried concurrently without cache/credential/namespace crossover.

## 62.11 Gate K - Cross-system decoupling

Node providerID is exported without linking the Kubernetes provider package to any cloud provider SDK.

## 62.12 Gate L - Cancellation

Large list, watch, log-follow and verification operations terminate promptly under Ono cancellation semantics.

## 62.13 Gate M - No kubectl dependency

Core conformance works on a machine where `kubectl` is absent.

## 62.14 Gate N - Current support matrix

Release CI passes against the declared oldest and newest supported Kubernetes minor versions.

---

# 63. Anti-Patterns

## 63.1 `kubectl` wrapper

```text
run kubectl -o json
parse stdout
call that Kubernetes integration
```

is not an acceptable final architecture.

## 63.2 Built-ins only

Hard-coding Pods/Deployments/Services while treating CRDs as unsupported violates the reference-provider purpose.

## 63.3 YAML as internal data model

Serializing everything to YAML and reparsing it discards API/client semantics and is prohibited as the core data path.

## 63.4 Name-based ownership

A Pod named like a Deployment child is not ownership evidence.

## 63.5 Status-string flattening

Reducing conditions/container status/controller state to a single "Running/Healthy" string as canonical data is prohibited.

## 63.6 Event-as-audit-log

Using Kubernetes Events as complete historical truth is prohibited.

## 63.7 Silent all-namespaces

Falling back from a namespace query to all namespaces or vice versa without visible scope is prohibited.

## 63.8 Secret convenience

Automatically base64-decoding and printing Secret values in default `inspect` violates the security contract.

## 63.9 Mutation after stale plan

Applying a plan against a same-name recreated UID or materially changed target without conflict/re-plan handling violates prospective safety.

## 63.10 Hidden force apply

Automatically forcing server-side apply conflicts is prohibited.

## 63.11 Watch reconnect without gap semantics

Relisting after watch expiry and presenting the stream as continuous is prohibited.

---

# 64. Recommended Implementation Sequence

## Phase 1 - Connection foundation

Implement:

- provider package/instance;
- kubeconfig resolution;
- TLS/auth;
- effective connection diagnostics;
- discovery;
- basic scope/navigation root.

No mutations.

## Phase 2 - Dynamic resource model

Implement:

- GVK/GVR registry;
- OpenAPI schema loading;
- dynamic/unstructured value conversion;
- metadata projection;
- UID identity;
- get/list/pagination;
- CRD fixtures.

This phase proves that Kubernetes does not require a static core model.

## Phase 3 - Curated operational graph

Add semantic adapters for:

```text
Namespace
Deployment
ReplicaSet
StatefulSet
DaemonSet
Pod
Service
EndpointSlice
Node
ConfigMap
Secret metadata
PVC/PV/StorageClass
Ingress
Job/CronJob
ServiceAccount
```

Implement owner/selector/direct relationships and `near`/`follow` behavior.

## Phase 4 - Watch/live

Implement:

- list/watch;
- bookmarks where useful;
- streaming-list negotiation where available;
- reconnect;
- 410 recovery with explicit gap;
- live views;
- active relationship indexes.

## Phase 5 - Temporal evidence

Integrate:

- watch observations;
- Kubernetes Events;
- conditions;
- snapshot diff;
- coverage windows;
- evidence-aware `why` inputs.

Do not add broad mutations merely to accelerate roadmap appearance.

## Phase 6 - Cross-system anchors

Export:

- Node providerID/address evidence;
- container runtime IDs;
- load-balancer addresses;
- CSI handles;
- image digests.

Prove one resolver path with a synthetic or later AWS provider.

## Phase 7 - Bounded mutations

Start with a deliberately small action set whose verification can be specified well:

```text
scale Deployment/StatefulSet
cordon/uncordon Node
set image on curated workloads
label/annotate
bounded server-side apply
```

Add deletion only after finalizer/dependency/recovery presentation is solid.

## Phase 8 - Operational remote streams

Add logs/follow, then port-forward/exec only when Ono's remote-job/terminal security model is ready.

## Phase 9 - Ecosystem adapters

Add optional curated semantics for high-value CRDs based on real usage and external contributors.

---

# 65. Definition of Useful Kubernetes Provider v1 Capability

This section is not a release number. It defines the first product threshold at which the provider should be publicly described as useful rather than experimental.

A useful first capability SHOULD allow a user to:

1. connect to an ordinary kubeconfig context;
2. enter a namespace;
3. discover built-in and custom resources;
4. inspect typed desired and observed state;
5. move from Deployment -> ReplicaSet -> Pod -> Node;
6. move from Service -> EndpointSlice -> Pod;
7. inspect config/storage/identity relationships;
8. see current conditions and recent Events with provenance;
9. run a live watch-backed view with visible sync status;
10. distinguish empty, denied, stale and incomplete results;
11. export Node providerID for later cloud traversal;
12. do all of this without `kubectl` installed.

Mutation is valuable but not required for this threshold.

That ordering is intentional: Ono should first prove that it understands Kubernetes better as a system interface before it proves that it can send writes.

---

# 66. Maintainer and Contribution Boundaries

## 66.1 Domain ownership

The provider SHOULD be decomposable into contribution surfaces such as:

```text
discovery/schema
workload relationships
network relationships
storage relationships
RBAC/identity
watch/cache
Events/temporal
mutation/verification
CRD adapters
fixtures/version compatibility
```

## 66.2 Adapter contributions

A contributor adding support for one CRD ecosystem SHOULD not need commit access to Ono parser/core internals.

## 66.3 Fixture-first changes

Relationship or API behavior changes SHOULD include deterministic fixtures and acceptance examples.

## 66.4 Upstream expertise is valuable

Review policy SHOULD explicitly value Kubernetes domain expertise independently from Ono core expertise. This creates a realistic path for external maintainers to own parts of the provider.

---

# 67. CNCF-Relevant Design Qualities

This document does not define CNCF application readiness, but the Kubernetes provider SHOULD support the project's broader community goal through technical qualities.

## 67.1 Kubernetes-native, not Kubernetes-dependent shell core

Ono's core identity remains provider-independent while Kubernetes receives first-class treatment through public extension contracts.

## 67.2 Extensible API awareness

First-class CRD and aggregated API support demonstrates compatibility with the broader cloud-native ecosystem rather than only Kubernetes built-ins.

## 67.3 Contribution surface

Curated adapters and relationship modules create bounded areas external contributors can own.

## 67.4 Interoperability

The provider consumes Kubernetes APIs directly and preserves native identities, making it complementary to controllers, GitOps, observability and cloud providers rather than claiming to replace them.

## 67.5 Honest operational semantics

Explicit RBAC denial, watch gaps, reconciliation uncertainty and Event limitations are part of the product quality bar.

---

# 68. Open Questions Reserved for Later Specifications or ADRs

## 68.1 Canonical provider URI grammar

This document provides examples but does not freeze the global external-provider URI grammar before Kubernetes and AWS have both validated it.

## 68.2 Full cross-system confidence taxonomy

The later Cross-System Relationships Specification will define verified/strong/inferred/ambiguous/conflicting semantics canonically.

## 68.3 Durable background watchers

Long-running background cluster observation without an active Ono session must be justified by dogfooding before adding a persistent daemon requirement.

## 68.4 Audit-log ingestion

Kubernetes audit logs may materially improve temporal reasoning but require deployment-specific access and storage. They need a separate observation-source design.

## 68.5 Metrics integration

Metrics API, Prometheus and OpenTelemetry may enrich system reasoning, but should not be folded into the base provider until the boundary with Ono's non-monitoring goal is explicit.

## 68.6 Helm semantics

Helm release interpretation may be useful, but should be a separate adapter/spec rather than contaminating Kubernetes base semantics.

## 68.7 Generic reference annotations

Kubernetes has no universal schema annotation saying "this field references that GVK." A future Ono/CRD ecosystem convention could enable richer generic relationships, but it must not be invented prematurely.

---

# 69. Final Provider Thesis

The Kubernetes provider succeeds when the user stops thinking primarily in commands such as:

```text
kubectl get
kubectl describe
kubectl logs
kubectl get ... -o json | jq ...
```

and can instead operate on one coherent model:

```text
find
enter
inspect
near
follow
trace
past
diff
why
plan
apply
```

without losing Kubernetes-native truth.

The provider must make the cluster feel like a system with places, relationships, observations and consequences - not like a collection of REST endpoints wearing CLI flags.

The reference test is simple:

> Can Ono learn a cluster it has never seen before, preserve what Kubernetes actually says, show how its resources relate, expose uncertainty honestly, and let the operator move from understanding toward safe change without changing languages?

If yes, the generic KUANG/11 external-system architecture has passed its first real test.

---

# Appendix A. Initial Curated Resource Matrix

The following matrix is expressed as compact resource profiles to keep the contract readable on narrow document formats.

**Namespace**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: low; destructive namespace deletion only after enhanced safety semantics.

**Node**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: cordon/uncordon early.

**Pod**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: low; prefer mutations on controlling workload where they better match intent.

**Deployment**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: scale and image changes early.

**ReplicaSet**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: low; prefer controlling owner.

**StatefulSet**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: scale/image after Deployment behavior is proven.

**DaemonSet**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: image/rollout later.

**Service**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: later.

**EndpointSlice**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: normally controller-owned/read-only.

**Ingress**  
Dynamic read: MUST. Curated relations: SHOULD. Watch: MUST. Mutation priority: later.

**Job / CronJob**  
Dynamic read: MUST. Curated relations: SHOULD. Watch: MUST. Mutation priority: later.

**ConfigMap**  
Dynamic read: MUST. Curated relations: SHOULD. Watch: MUST. Mutation priority: bounded apply later.

**Secret**  
Metadata read: MUST; payload protected. Curated relations: SHOULD. Watch: guarded metadata/object observation. Mutation/reveal priority: guarded.

**ServiceAccount**  
Dynamic read: MUST. Curated relations: SHOULD. Watch: MUST. Mutation priority: low.

**PVC / PV**  
Dynamic read: MUST. Curated relations: MUST. Watch: MUST. Mutation priority: destructive operations later.

**StorageClass**  
Dynamic read: MUST. Curated relations: SHOULD. Watch: MUST. Mutation priority: low.

**NetworkPolicy / HPA**  
Dynamic read: MUST. Curated relations: SHOULD. Watch: MUST. Mutation priority: later.

**Role / ClusterRole / RoleBinding / ClusterRoleBinding**  
Dynamic read: MUST. Curated relations: SHOULD. Watch: MUST. Mutation priority: security-sensitive and later.

**Arbitrary CRD**  
Dynamic read: MUST. Generic relationships: MUST where structurally available. Watch: SHOULD when the served resource supports watch. Mutation priority: adapter-dependent.

---

# Appendix B. Canonical Relationship Vocabulary Candidates

These names are provider-facing candidates and SHOULD be reconciled with the project's global relationship registry before ABI freeze.

```text
owned-by
controls
scheduled-on
selects
selected-by
represented-by
endpoint-for
routes-to
routed-from
uses
references-config
references-secret
runs-as
mounts
bound-to
uses-storage-class
protected-by
binds
grants-to
uses-tls-secret
uses-image-pull-secret
has-address
provider-hosted-by (resolver output, not Kubernetes-native)
```

Every edge MUST retain provider-native evidence regardless of friendly vocabulary.

---

# Appendix C. Relationship Evidence Examples

## C.1 Owner edge

```text
edge:
  from: Pod uid=pod-uid
  relation: owned-by
  to: ReplicaSet uid=rs-uid
  evidence:
    class: provider-declared
    source: metadata.ownerReferences
    owner_uid: rs-uid
    controller: true
```

## C.2 Selector edge

```text
edge:
  from: Service uid=svc-uid
  relation: selects
  to: Pod uid=pod-uid
  evidence:
    class: derived
    source: Service.spec.selector + Pod.metadata.labels
    selector:
      app: checkout
    observed_resource_versions:
      service: "..."
      pod: "..."
```

## C.3 Node cross-system evidence

```text
identity_evidence:
  subject: Node uid=node-uid
  key: kubernetes.node.provider-id
  value: "aws:///eu-central-1a/i-0123456789"
  source: Node.spec.providerID
  observed_at: ...
  confidence: provider_fact
```

The later resolver decides what foreign resource this evidence matches.

---

# Appendix D. Coverage Examples

## D.1 Complete namespace Pod list

```text
coverage:
  scope: namespace/production
  type: core/v1 Pod
  completeness: complete
  source: list
  resourceVersion: "12345"
```

## D.2 RBAC denied list

```text
coverage:
  scope: namespace/secret-team
  type: core/v1 Pod
  completeness: denied
  reason: authorization_denied
```

## D.3 Partial multi-type view

```text
coverage:
  requested:
    - Deployments: complete
    - Pods: complete
    - custom.metrics.k8s.io: unavailable
  aggregate: partial
```

## D.4 Watch gap

```text
coverage:
  type: core/v1 Pod
  continuous_from: 14:00:00
  gap:
    start: after resourceVersion 18001
    reason: watch_expired_410
  resynced_at: 14:17:22
```

---

# Appendix E. Prospective Change Example - Scale Deployment

```text
TARGET
  Deployment production/checkout
  uid: 91a...
  observed resourceVersion: 72119

CURRENT
  spec.replicas: 3
  status.readyReplicas: 3
  status.availableReplicas: 3

PROPOSED
  spec.replicas: 6

AUTHORIZATION
  patch deployments: allowed (preflight)
  authoritative check occurs on apply

INTERACTIONS
  HPA target: none observed
  managed field owner for spec.replicas: deployment-controller / user-tool evidence shown

SERVER DRY-RUN
  accepted
  no admission change to replicas

EXPECTED RECONCILIATION
  Deployment generation advances
  Deployment controller observes generation
  ReplicaSet desired replicas increases
  Pods are created/scheduled
  ready replicas reaches policy threshold

RISKS / LIMITS
  scheduling capacity not guaranteed
  image pull/runtime readiness not guaranteed
  downstream service behavior not proven

RECOVERY
  previous desired replicas can be reapplied
  this does not undo requests handled or side effects produced by temporary extra replicas

VERIFY
  observedGeneration >= planned generation
  readyReplicas == 6
  availableReplicas == 6
  timeout: explicit host policy
```

---

# Appendix F. Prospective Change Example - Delete Namespace

```text
TARGET
  Namespace demo

KNOWN CONTENTS
  Pods: 18
  Deployments: 5
  Services: 7
  PVCs: 3
  CRD Foo: unknown (list denied)

FINALIZERS
  kubernetes
  example.io/cleanup

KNOWN EXTERNAL CONSEQUENCES
  2 PVCs bind PVs with Delete reclaim policy
  1 PVC bind PV with Retain reclaim policy

COVERAGE
  partial - custom Foo resources could not be enumerated

RECOVERY
  no general rollback claim
  recreating namespace/object manifests does not restore ephemeral state or guaranteed external resources

CONFIRMATION
  enhanced destructive confirmation required
```

---

# Appendix G. Upstream Behavior Notes Used by This Specification

The following Kubernetes behaviors are intentionally reflected in normative rules above:

1. Kubernetes publishes served API resources through Discovery and schemas through OpenAPI; clients should discover cluster capabilities rather than assume them.
2. Custom resources can appear and disappear dynamically through CRDs or aggregated API servers.
3. List/watch uses `resourceVersion` for change continuity; watches can expire and require relist after `410 Gone`.
4. Watch bookmarks are continuity markers, not resource changes.
5. Streaming initial events are an optional negotiated optimization and cannot be the only supported list/watch path for a broad compatibility window.
6. Owner references encode ownership under namespace/cluster-scope constraints; selectors are a different relationship mechanism.
7. Kubernetes Events have limited retention and best-effort semantics and are not a stable audit trail.
8. SelfSubjectAccessReview can ask whether the current user can perform a specific action; rules summaries can be incomplete and must not replace authoritative authorization.
9. kubeconfig exec credential plugins return structured `ExecCredential` data and may have explicit stdin interaction requirements.
10. Kubernetes maintains only a moving set of current release branches, so Ono compatibility must be tested continuously rather than frozen to the version current when this document was written.

These notes are informative summaries. Upstream Kubernetes documentation and API behavior remain the authority for Kubernetes semantics.

