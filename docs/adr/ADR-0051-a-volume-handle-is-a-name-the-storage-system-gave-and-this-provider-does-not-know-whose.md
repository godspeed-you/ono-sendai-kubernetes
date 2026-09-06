# ADR-0051: A volume handle is a name the storage system gave, and this provider does not know whose

- Status: accepted
- Date: 2026-09-06
- Spec refs: §21.4, §28.3, §28.5, §47.1, §47.2, §47.5, §47.7; ADR-0022
- Decided by: agent (autonomous)

## Context

§47 asks this provider to export cross-system identity evidence for a later generic resolver, and
names five families. Four were implemented: §47.2's Node evidence, §47.3's containers, §47.4's
load-balancer addresses, §47.6's images. §47.5's was missing:

> CSI volume handles and driver identities MAY be exported for later resolution to
> cloud/block-storage resources.

It is a `MAY`, and it is the cheapest of the five to get wrong, because a volume handle is the one
piece of Kubernetes data most likely to tempt a reader into interpreting it. `vol-0abc123def456789`
looks like something a provider could helpfully classify.

§47.1 is the rule against exactly that:

> The Kubernetes provider MUST export identity evidence that a generic cross-system resolver can
> consume. It MUST NOT embed AWS, Azure, GCP or host inventory logic in Kubernetes-specific
> relationship code.

## Decision

**Three items, no interpretation, and no in-tree volume sources.**

`Evidence::of_storage` reads a PersistentVolume's `spec.csi.volumeHandle` as `distinguishing`,
`spec.csi.driver` as `correlating` and `spec.csi.fsType` as `placement`, each citing the pointer it
came from.

Three decisions inside that:

1. **The driver and the handle are two items, not one composite key.** Joining them into
   `<driver>/<handle>` would be a decision about which system's namespace the handle lives in —
   made here, by the Kubernetes provider, in a format the resolver would then have to take apart.
   That is §47.1's prohibition in miniature. The driver is `correlating` rather than
   `distinguishing` for the same reason a zone is not an identity: every volume on a cluster may
   name the same driver. It is the namespace a handle has to be read in, and a resolver holding a
   handle and no driver does not know whose names it is holding.

2. **In-tree volume sources are not read.** A cluster inside §5.1's support window may still serve
   volumes provisioned through the older per-vendor `spec` fields, each carrying the same fact in
   its own spelling. Reading them under the CSI keys would mean this file holding a table of which
   vendor field belongs to which storage system — precisely the foreign-domain knowledge §47.1
   forbids, and precisely what the driver name exists to make unnecessary. A volume with no
   `spec.csi` reports §21.4's *absent*: it was read, and it states no CSI source. That is a fact
   about the volume and a different answer from "nobody looked".

3. **`fsType` is exported even though it identifies nothing.** It is `placement`, and its only use
   is to *reject* a match a resolver would otherwise make on a handle collision. Evidence that can
   only ever say no is still evidence, and leaving it out would make the resolver's job strictly
   harder for no gain in honesty.

`PersistentVolume` joins the `k8s-evidence` subject table, so §47.7's requirement that this
evidence be inspectable before any foreign provider exists holds for storage as it does for the
other four.

## Consequences

`get k8s-evidence --kind PersistentVolume --name pvc-9f3` answers with the handle, the driver and
the filesystem, each with its strength and its source pointer, and with no claim about what the
handle refers to.

The module's existing guard —
`should_name_no_cloud_vendor_anywhere_in_the_module` — caught the first draft of this change,
which named three cloud vendors in its doc comments as illustrations. The guard was right to: a
reader cannot tell an illustration from a rule, and a file whose comments enumerate clouds is one
edit away from a `match` that does. The prose now describes the shape of the problem without
naming anyone's product, and the vendor-specific strings live only in the fixtures, where being
realistic is the whole point.
