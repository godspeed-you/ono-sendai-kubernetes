//! What this package declares before any of its code runs: the targets it answers for, and the
//! schemas their records carry (spec §31.23, §31.68).
//!
//! The table below is the single place the two halves of a declaration come from. A package
//! states what it contributes twice — once in `package/contributions/*.yaml`, so the host can
//! register a placeholder without starting anything, and once across the handshake, when the
//! instance loads. Deriving both from one table is what stops them disagreeing about what the
//! package contributes; `tests/contributions.rs` holds them to it.
//!
//! Each entry also carries **what it reads** — [`Reads`]. For a curated noun that is a group and
//! a kind. Deliberately not a GVR: which REST collection serves a kind, and at which version, is
//! discovery's answer and never a compile-time assumption (§4 invariants 1–2, §5.2, §13.1). A
//! group and a kind are GVK identity, which is stable across the versions a server happens to
//! serve, so naming them here decides nothing discovery is entitled to decide.
//!
//! For `k8s-resource` it is [`Reads::Discovered`]: the kind is named by the *query* and resolved
//! against the cluster's own discovery, so a CRD invented after this table was written is
//! reachable without recompiling anything (§15.1, §33.1, Gate A). A document written before the
//! package runs cannot name a kind invented after it, so the noun names the *shape* of the
//! question instead of the answer — ADR-0010.

use ono_kuang_sdk::protocol::{
    Answer, CommandContribution, ParameterContribution, SchemaContribution,
    SchemaFieldContribution, TargetContribution,
};

/// One argument a contribution declares, in the vocabulary a core command declares its own
/// (`ADR-0587 (core)`).
///
/// Declaring an argument is not the same as accepting it: every word here already reached a
/// handler before there was anywhere to declare it, and a word this table does not name still
/// does. What a declaration buys is the four things the host can only do when it knows the
/// argument exists — a help line, a completion candidate, a *type* the written word is coerced
/// to, and a default the host supplies when the user says nothing.
///
/// The fourth is why the mutating commands declare theirs. `dry_run` decides whether a cluster
/// changes, and until now its safe value was a fallback each handler had to remember
/// (`unwrap_or(true)`); declared, it is the shell's guarantee, applied before this package's code
/// runs. The handlers keep their fallbacks anyway, because a package that is correct only when
/// the host is doing its job is a package with a latent write in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameter {
    /// The name, without the `--` an option is written with, and spelled exactly as the handler
    /// reads it out of the argument map.
    pub name: &'static str,
    /// The registry type the written word is coerced to, e.g. `string`, `int`, `bool`, `map`.
    pub declared_type: &'static str,
    /// One line, shown by `help` and beside a completion candidate.
    pub doc: &'static str,
    /// The value the host supplies when the argument is absent, as the text the registry
    /// vocabulary coerces. `None` means the argument simply does not arrive, which is a
    /// different thing from arriving as zero, empty or false.
    pub default: Option<&'static str>,
    /// Whether the argument may be written more than once, accumulating.
    pub repeatable: bool,
}

impl Parameter {
    /// A declared argument with no default: absent means absent.
    const fn new(name: &'static str, declared_type: &'static str, doc: &'static str) -> Self {
        Self {
            name,
            declared_type,
            doc,
            default: None,
            repeatable: false,
        }
    }

    /// A declared argument that may be written more than once, accumulating into a list.
    const fn repeatable(
        name: &'static str,
        declared_type: &'static str,
        doc: &'static str,
    ) -> Self {
        Self {
            name,
            declared_type,
            doc,
            default: None,
            repeatable: true,
        }
    }

    /// A declared argument the host fills in when nothing is written.
    const fn defaulting(
        name: &'static str,
        declared_type: &'static str,
        doc: &'static str,
        default: &'static str,
    ) -> Self {
        Self {
            name,
            declared_type,
            doc,
            default: Some(default),
            repeatable: false,
        }
    }

    /// The parameter as the handshake and the on-disk document carry it.
    #[must_use]
    pub fn contribution(&self) -> ParameterContribution {
        ParameterContribution {
            name: self.name.to_owned(),
            declared_type: self.declared_type.to_owned(),
            doc: self.doc.to_owned(),
            repeatable: self.repeatable,
            // Nothing here is written without its value: a flag that may stand alone would make
            // `--dry_run` mean the opposite of `--dry_run false` by omission.
            optional_value: false,
            default: self
                .default
                .map(|text| serde_json::Value::String(text.to_owned())),
        }
    }
}

/// Which cluster the invocation is about (§7.1, §7.3, §7.4).
///
/// Every word this package contributes takes these four, because every one of them has to reach
/// an API server before it can answer anything. No endpoint is ever defaulted: naming neither a
/// `context` nor a `host` is refused rather than guessed, and the only thing that stands in for
/// them is what a *previous* invocation in this process named (ADR-0027).
pub(crate) const CLUSTER: &[Parameter] = &[
    Parameter::new(
        "context",
        "string",
        "A kubeconfig context: its server, default namespace, trust anchors and credential.",
    ),
    Parameter::new(
        "kubeconfig",
        "string",
        "Which kubeconfig file to read the context from. An absolute path; default `~/.kube/config`.",
    ),
    Parameter::new(
        "host",
        "string",
        "An explicit API server host instead of a context (specification section 7.3).",
    ),
    Parameter::new(
        "port",
        "int",
        "The API server port, where `host` names one and the default 443 is wrong.",
    ),
];

/// Which namespace, for a read that has one (§7.5, §9.2, §9.4).
pub(crate) const SCOPE: &[Parameter] = &[
    Parameter::new(
        "namespace",
        "string",
        "One namespace, beating the context's default (specification section 7.5).",
    ),
    Parameter::new(
        "all_namespaces",
        "bool",
        "Every namespace the caller can see. Deliberate rather than implied: there is no silent \
         fan-out (specification section 9.4).",
    ),
];

/// Which resource, for the nouns that take the kind from the query rather than from the table.
///
/// This is ADR-0010's floor written as four arguments: a CRD invented after this package was
/// built has no word of its own, so the question names the shape of the answer instead. `group`
/// is a `string` and not filtered for emptiness anywhere, because `--group ''` names the core
/// group and omitting it searches every group (§13.3).
const RESOURCE: &[Parameter] = &[
    Parameter::new(
        "kind",
        "string",
        "The Kubernetes kind, e.g. `Widget`, resolved against the cluster's own discovery.",
    ),
    Parameter::new(
        "group",
        "string",
        "The API group, e.g. `example.io`. Written empty it names the core group; omitted it \
         searches every group the server lists.",
    ),
    Parameter::new(
        "version",
        "string",
        "One served version instead of the group's preferred one (specification section 13.4).",
    ),
    Parameter::new(
        "resource",
        "string",
        "The REST collection name, e.g. `widgets`, where the kind is ambiguous or unknown.",
    ),
];

/// One object rather than a collection (§17.1).
const NAMED: Parameter = Parameter::new(
    "name",
    "string",
    "One object, read at its own endpoint rather than filtered out of the collection. A \
     different request with different permissions (specification section 17.1).",
);

/// Which of §47's four subjects a query means, for `k8s-evidence`.
///
/// Declared with a default rather than left absent, because the answer differs per kind and a
/// silent choice would be this package deciding which object an operator meant. `Node` is the
/// default because §47.2's evidence is the oldest and the one §60.8's scenario names.
const EVIDENCE_KIND: Parameter = Parameter::defaulting(
    "kind",
    "string",
    "Whose evidence: `Node`, `Pod`, `Service` or `Ingress`. Each states a different kind of \
     cross-system fact, and a kind with no rule is refused by name rather than answered empty \
     (specification section 47).",
    "Node",
);

/// A page budget for a listing (§18.4).
/// Server-side filtering, pushed to the API server exactly as written (§17.3 to §17.5).
///
/// Two parameters rather than one, because the API server treats them differently and so must a
/// caller: every resource supports label selection, while field selector support "varies by
/// resource type and server implementation" (§17.5) — so a rejected field selector is refused with
/// the field named, and never turned into an empty collection.
///
/// The syntax is Kubernetes' own, undocumented here on purpose. §17.4 requires that "Kubernetes
/// label selector semantics MUST remain Kubernetes semantics", and the way to keep a translation
/// from changing meaning is to have no translation: what the operator writes goes on the wire.
const SELECTORS: &[Parameter] = &[
    Parameter::new(
        "selector",
        "string",
        "A Kubernetes label selector, e.g. `app=api,tier!=cache` or `env in (staging, prod)`. Pushed \
         to the API server verbatim, so the semantics are Kubernetes' own (specification section \
         17.4).",
    ),
    Parameter::new(
        "field_selector",
        "string",
        "A Kubernetes field selector, e.g. `status.phase=Running`. Support varies by resource and by \
         server; one this server will not index is refused by name rather than answered with an \
         empty collection (specification section 17.5).",
    ),
];

const MAX_PAGES: Parameter = Parameter::new(
    "max_pages",
    "int",
    "How many pages of a listing to read before stopping. The stop is coverage, never a \
     silently short answer (specification section 18.4).",
);

/// What one invocation may spend against the API server (§49.5, §50.1).
///
/// §49.5 asks the provider to "expose configurable query concurrency/QPS/burst policy with
/// conservative defaults aligned with interactive use". These three are that policy, and they are
/// three rather than six on purpose — see `query::budget_of` for why concurrency and the
/// transferred-byte bound stay where they are. The defaults are `Budget::interactive`'s, so a
/// query that names none of them is still bounded on every dimension.
///
/// Different in kind from `max_pages` beside them, and the difference is §18.4's: a page budget
/// is a *decision* to stop consuming, which is not incompleteness, while passing one of these is
/// the provider stopping short — a gap, stated as one.
const BUDGET: &[Parameter] = &[
    Parameter::new(
        "max_requests",
        "int",
        "How many requests this query may send to the API server before it stops and says so. \
         Default 64, which is what an interactive question costs (specification section 49.5).",
    ),
    Parameter::new(
        "max_scopes",
        "int",
        "How many distinct scopes — namespaces, API group-versions — the query may reach into. \
         Checked against the estimated breadth before the first request rather than halfway \
         through (specification section 17.6). Default 32.",
    ),
    Parameter::new(
        "budget_ms",
        "int",
        "How long the query may take before it stops with what it has. Default 10000: an \
         interactive answer is one somebody is waiting for (specification section 50.1).",
    ),
];

/// One field of a contributed schema, as the table spells it.
///
/// `required` is the only flag because ADR-0012 §8 makes the two mutually exclusive: a field is
/// required or it is nullable, and a table with both would be able to say something the contract
/// refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// The field name, as the record carries it.
    pub name: &'static str,
    /// The registry type name, e.g. `string`, `int`, `list<string>`, `map`, `timestamp`.
    pub field_type: &'static str,
    /// Whether the field is always known. Everything else is nullable, and null means unknown.
    pub required: bool,
}

impl Field {
    /// A field that is always known.
    const fn required(name: &'static str, field_type: &'static str) -> Self {
        Self {
            name,
            field_type,
            required: true,
        }
    }

    /// A field that may be absent, in which case it is null and never a default.
    const fn nullable(name: &'static str, field_type: &'static str) -> Self {
        Self {
            name,
            field_type,
            required: false,
        }
    }
}

/// What a target reads, which is either one named kind or whatever the query names.
///
/// An enum rather than an optional group and kind, so that the two cases cannot be confused by a
/// caller who forgets to check: a curated noun always has a kind and the dynamic noun never has
/// one, and there is no third state in which a table entry is half-specified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reads {
    /// One kind, named in this table (§15.2's curated tier).
    Kind {
        /// The API group the kind lives in; empty for the core group (§13.3).
        group: &'static str,
        /// The kind, as `apiVersion`/`kind` spells it. Half of a GVK, never a GVR (§13.1).
        kind: &'static str,
    },
    /// Whatever kind the query names, resolved against the cluster's discovery (§15.1, §33.1).
    ///
    /// The one route by which a resource this package has never heard of is readable. It carries
    /// no group and no kind because it has none until a query supplies them, and a default here
    /// would be this package choosing a kind on the operator's behalf.
    Discovered,
    /// No Kubernetes object at all: the provider instance itself (§8.6, §10, §61.1).
    ///
    /// The diagnostic reads `/version`, the discovery documents, the `kube-system` namespace and
    /// a `SelfSubjectReview` — none of which is a collection of objects, and all of which are
    /// facts about the session rather than about anything in the cluster. A group and a kind here
    /// would name a collection nobody lists.
    Instance,
    /// The relationships of one object, rather than the object (§23 to §32, Gate D).
    ///
    /// A relationship has no `metadata.uid` and is not fetched from a collection: it is derived
    /// from one object the query names, plus — for the derived classes — whatever second reading
    /// the rule needs. So this variant names no kind either. Which object the edges start at is
    /// the *query's* answer, resolved against discovery exactly as [`Self::Discovered`] resolves
    /// one, which is what makes a CRD's owner references reachable without recompiling anything
    /// (§33.1). ADR-0014.
    Relations,
    /// What changed in one collection while this provider was watching it (§19, Gate F).
    ///
    /// Not a collection either, and for a reason worth stating: a listing answers "what is
    /// there", a watch answers "what happened", and the second question has an answer the first
    /// cannot carry — the periods nobody observed. Which collection is watched is the *query's*
    /// answer, resolved against discovery exactly as [`Self::Discovered`] resolves one, so a CRD
    /// invented after this table was written is watchable without recompiling anything.
    Changes,
    /// The Events regarding one object, rather than the object (§38).
    ///
    /// Not a collection of the query's kind either: the query names the object an Event is
    /// *about*, and the Events themselves are read from whichever of §38.2's two representations
    /// the cluster serves. Which object is the query's answer, resolved against discovery exactly
    /// as [`Self::Discovered`] resolves one, so a custom resource's Events are reachable without
    /// recompiling anything.
    Events,
    /// What one object states about the systems around Kubernetes, as evidence (§47).
    ///
    /// Four kinds state such a thing and each states a different one: a Node names the machine
    /// underneath it (§47.2), a Pod names the containers and images a runtime holds for it
    /// (§47.3), and a Service or an Ingress names the load-balancer addresses something outside
    /// answers on (§47.4). Which of them a query means is the *query's* answer, through a `kind`
    /// option that defaults to `Node`.
    ///
    /// It is deliberately not [`Self::Discovered`]'s resolution over every group. There is no
    /// generic evidence rule: every rule is a set of pointers into one kind's own fields, so a
    /// kind resolved through discovery would be read and then refused — a promise the answer
    /// cannot keep. The four are named here, and a fifth is refused by name before a cluster is
    /// reached. It stays a variant of its own because the records are not the object.
    Evidence,
    /// One container's log, as lines (§42.1).
    ///
    /// A subresource rather than a collection: `pods/log` is reached through one Pod's own REST
    /// endpoint, it is served only where discovery says the subresource is served, and its answer
    /// is bytes rather than objects.
    Logs,
    /// What was observed about one object, when, and by whose clock (§39).
    ///
    /// Not a collection: a timeline is assembled from one object's metadata, its conditions, its
    /// field managers and the Events regarding it, over the window this provider was looking in.
    Timeline,
    /// What may be said about the state one object is in, and the rung above which it may not
    /// climb (§40).
    Why,
    /// The structured observations one object's controllers wrote about it (§37.1).
    Conditions,
    /// What a change *would* do, described before anybody is asked to agree to it (§46).
    ///
    /// Not a collection, and not the object: a plan is a value about a change that has not
    /// happened. It is a target rather than a command because building one is read-only — one
    /// `GET` of the object the change is aimed at, and this provider's own rules — and because
    /// §46.1 puts understanding a change before making it. Which object is the query's answer,
    /// resolved against discovery exactly as [`Self::Discovered`] resolves one, so a change to a
    /// custom resource is as plannable as a change to a Deployment (§33.1).
    Plan,
}

impl Reads {
    /// The API group, where the table names one.
    #[must_use]
    pub const fn group(self) -> Option<&'static str> {
        match self {
            Self::Kind { group, .. } => Some(group),
            Self::Discovered
            | Self::Instance
            | Self::Relations
            | Self::Changes
            | Self::Events
            | Self::Evidence
            | Self::Logs
            | Self::Timeline
            | Self::Why
            | Self::Conditions
            | Self::Plan => None,
        }
    }

    /// The kind, where the table names one.
    #[must_use]
    pub const fn kind(self) -> Option<&'static str> {
        match self {
            Self::Kind { kind, .. } => Some(kind),
            // Not `Evidence`: four kinds state cross-system evidence and the query says which
            // (§47.2 to §47.4), so this table names none of them.
            Self::Evidence
            | Self::Discovered
            | Self::Instance
            | Self::Relations
            | Self::Changes
            | Self::Events
            | Self::Logs
            | Self::Timeline
            | Self::Why
            | Self::Conditions
            | Self::Plan => None,
        }
    }
}

/// One noun this package answers for, with everything needed to declare it and to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// The target word, as `get k8s-pod` spells it.
    pub name: &'static str,
    /// The schema id the target's records carry.
    pub schema: &'static str,
    /// The schema's display name.
    pub schema_name: &'static str,
    /// One line: what an object of this schema is.
    pub schema_summary: &'static str,
    /// One line, for `help` and completion.
    pub summary: &'static str,
    /// What makes two observations the same object, in prose.
    pub identity_doc: &'static str,
    /// Which resource the target reads, and whether the table or the query names it.
    pub reads: Reads,
    /// The schema's fields, in declaration order.
    pub fields: &'static [Field],
}

impl Target {
    /// The schema as the handshake carries it.
    #[must_use]
    pub fn schema_contribution(&self) -> SchemaContribution {
        SchemaContribution {
            id: self.schema.to_owned(),
            name: self.schema_name.to_owned(),
            summary: self.schema_summary.to_owned(),
            identity: self
                .identity_fields()
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
            fields: self
                .fields
                .iter()
                .map(|field| SchemaFieldContribution {
                    name: field.name.to_owned(),
                    field_type: field.field_type.to_owned(),
                    required: field.required,
                    nullable: !field.required,
                })
                .collect(),
        }
    }

    /// What makes two records of this target's schema the same thing.
    ///
    /// [`IDENTITY`] for everything that projects a Kubernetes object, without exception. An edge
    /// is the one thing here that is not an object: it has no `metadata.uid`, so it is keyed on
    /// `uid`, `relation`, `target` and `evidence_path` — the object it starts at, the word, the
    /// far end, and the field that decided. See ADR-0014 for why all four are needed.
    #[must_use]
    pub const fn identity_fields(&self) -> &'static [&'static str] {
        match self.reads {
            Reads::Relations => EDGE_IDENTITY,
            Reads::Changes => CHANGE_IDENTITY,
            Reads::Evidence => EVIDENCE_IDENTITY,
            Reads::Logs => LOG_IDENTITY,
            Reads::Timeline => OBSERVATION_IDENTITY,
            Reads::Why => FINDING_IDENTITY,
            Reads::Conditions => CONDITION_IDENTITY,
            Reads::Plan => PLAN_IDENTITY,
            // An Event *is* a Kubernetes object with a `metadata.uid` of its own, so it is keyed
            // the way every other object here is. What it is about is a field of it.
            Reads::Kind { .. } | Reads::Discovered | Reads::Instance | Reads::Events => {
                OBJECT_IDENTITY
            }
        }
    }

    /// The target as the handshake carries it.
    #[must_use]
    pub fn target_contribution(&self) -> TargetContribution {
        TargetContribution {
            name: self.name.to_owned(),
            schema: self.schema.to_owned(),
            summary: self.summary.to_owned(),
            identity_doc: self.identity_doc.to_owned(),
            options: self.options().iter().map(Parameter::contribution).collect(),
            answer: self.answer(),
        }
    }

    /// Whether this target's answer ends by itself (`ADR-0588 (core)`).
    ///
    /// **Two words do not**, and the host has to know before it reads the first record: a package
    /// that has not emitted yet and one that never will look the same from outside, and what is
    /// being decided is whether to collect the answer at all. A collected watch never returns to
    /// the prompt.
    ///
    /// - `k8s-change` is a watch. §41 gives it no natural end — the operator ends it — and there
    ///   is no bounded reading of it to fall back on.
    /// - `k8s-log` is bounded *unless* `follow` is written, and the declaration is a property of
    ///   the target rather than of the invocation, so it declares the worst case. That is the
    ///   right direction to be wrong in: an unbounded answer that ends is a stream that ended,
    ///   while a bounded declaration over a followed log is a shell that does not come back. What
    ///   it costs is that a bare `get k8s-log` whose output goes somewhere that is not a terminal
    ///   and not a serializer is refused rather than tabulated — the shell's own rule for a live
    ///   stream, with a message naming the two ways out. ADR-0035.
    #[must_use]
    pub const fn answer(&self) -> Answer {
        match self.reads {
            Reads::Changes | Reads::Logs => Answer::Unbounded,
            Reads::Instance
            | Reads::Kind { .. }
            | Reads::Discovered
            | Reads::Relations
            | Reads::Events
            | Reads::Evidence
            | Reads::Timeline
            | Reads::Why
            | Reads::Conditions
            | Reads::Plan => Answer::Bounded,
        }
    }

    /// The arguments this target takes, decided by what it reads.
    ///
    /// Every word takes the four cluster arguments, because none of them can answer without
    /// reaching an API server. What is added beyond that is exactly what the handler reads out of
    /// the argument map, so a declared option no code consumes cannot exist:
    /// `tests/contributions.rs`
    /// holds this table, the on-disk document and the handshake to each other, and the handlers
    /// are the third reader of the same names.
    #[must_use]
    pub fn options(&self) -> Vec<Parameter> {
        let mut options: Vec<Parameter> = CLUSTER.to_vec();
        match self.reads {
            // Which cluster, and nothing else. The diagnostic is about the instance rather than
            // about a collection in it (§10.1, §34.3).
            Reads::Instance => {}
            // A curated noun already knows its kind; what a query adds is which scope and which
            // object (§9.2, §17.1, §18.4).
            Reads::Kind { .. } => {
                options.extend_from_slice(SCOPE);
                options.push(NAMED);
                options.extend_from_slice(SELECTORS);
                options.push(MAX_PAGES);
                options.extend_from_slice(BUDGET);
            }
            // The floor of ADR-0010: the kind comes from the query.
            Reads::Discovered => {
                options.extend_from_slice(SCOPE);
                options.extend_from_slice(RESOURCE);
                options.push(NAMED);
                options.extend_from_slice(SELECTORS);
                options.push(MAX_PAGES);
                options.extend_from_slice(BUDGET);
            }
            Reads::Relations => {
                options.extend_from_slice(SCOPE);
                options.extend_from_slice(RESOURCE);
                options.push(NAMED);
                options.push(MAX_PAGES);
                options.extend_from_slice(BUDGET);
                options.push(Parameter::new(
                    "relation",
                    "string",
                    "One relationship word, e.g. `owned-by` or `selects`, instead of every edge \
                     this object states.",
                ));
            }
            Reads::Changes => {
                options.extend_from_slice(SCOPE);
                options.extend_from_slice(RESOURCE);
                options.push(MAX_PAGES);
                options.extend_from_slice(BUDGET);
                options.push(Parameter::new(
                    "max_changes",
                    "int",
                    "Stop after this many changes. Absent is unbounded, which is what a watch \
                     is: the operator ends it.",
                ));
                options.push(Parameter::new(
                    "reacquire",
                    "bool",
                    "After a continuity gap, list the collection again to resume from a known \
                     version. Default true; the gap record is emitted either way \
                     (specification section 19.4).",
                ));
                options.push(Parameter::defaulting(
                    "stale_after_ms",
                    "int",
                    "How long without a live observation before the view calls itself stale \
                     (specification section 41.4). A threshold this source declares, not a rule \
                     the shell applies to everything.",
                    "30000",
                ));
            }
            Reads::Events => {
                options.extend_from_slice(SCOPE);
                options.extend_from_slice(RESOURCE);
                options.push(NAMED);
                options.push(MAX_PAGES);
                options.extend_from_slice(BUDGET);
            }
            // §47.2's Node is cluster-scoped; §47.3's Pod and §47.4's Service and Ingress are
            // not, so a namespace is nameable — and `all_namespaces` is not, because this is a
            // question about one object (§17.1).
            Reads::Evidence => {
                options.push(SCOPE[0]);
                options.push(NAMED);
                options.push(EVIDENCE_KIND);
            }
            Reads::Logs => {
                options.push(SCOPE[0]);
                options.push(NAMED);
                options.extend_from_slice(LOG_OPTIONS);
            }
            Reads::Timeline | Reads::Conditions => {
                options.extend_from_slice(SCOPE);
                options.extend_from_slice(RESOURCE);
                options.push(NAMED);
            }
            Reads::Why => {
                options.extend_from_slice(SCOPE);
                options.extend_from_slice(RESOURCE);
                options.push(NAMED);
                options.push(Parameter::new(
                    "within_ms",
                    "int",
                    "How close in time two observations must be before they are considered \
                     together. Never a claim that one caused the other \
                     (specification section 40).",
                ));
            }
            Reads::Plan => {
                options.extend_from_slice(SCOPE);
                options.extend_from_slice(RESOURCE);
                options.push(NAMED);
                options.extend_from_slice(PLAN_OPTIONS);
            }
        }
        options
    }
}

/// What a log read may narrow, and the one option that unbounds it (§42.1).
///
/// `follow` is last because it is not a narrowing: every other option here cuts the answer
/// shorter and adds an entry to the record's `bounds`, and this one keeps the body open instead.
/// It is refused together with `previous` — the API server accepts that pair and answers it by
/// closing the body at once, which a caller watching for more lines reads as a container it has
/// just seen stop (ADR-0030).
const LOG_OPTIONS: &[Parameter] = &[
    Parameter::new(
        "container",
        "string",
        "Which container's log, where the Pod has more than one.",
    ),
    Parameter::new(
        "previous",
        "bool",
        "The previous instance of the container, where one is retained.",
    ),
    Parameter::new(
        "timestamps",
        "bool",
        "Ask the API server to prefix each line with the time it wrote it.",
    ),
    Parameter::new(
        "tail_lines",
        "int",
        "Read only the last N lines, which is a bound on the read and is reported as one.",
    ),
    Parameter::new(
        "since_seconds",
        "int",
        "Read only what was written in the last N seconds.",
    ),
    Parameter::new(
        "limit_bytes",
        "int",
        "Stop after N bytes. The stop is coverage, never a silently short log.",
    ),
    Parameter::new(
        "follow",
        "bool",
        "Keep the body open and answer with each line as the container writes it, until the \
         query is cancelled. Refused with `previous`: a run that has already ended cannot \
         produce another line.",
    ),
];

/// What a plan and a bounded write name about the change itself (§43.3, §44, §45.2).
const PLAN_OPTIONS: &[Parameter] = &[
    Parameter::new(
        "action",
        "string",
        "`apply` for a bounded field change or `delete` for the object. Default `apply` \
         (specification section 43.3).",
    ),
    Parameter::new(
        "set",
        "record",
        "A mapping from a JSON pointer to the value the field should hold, e.g. \
         `{\"/spec/replicas\": 2}`.",
    ),
    Parameter::repeatable(
        "unset",
        "list<string>",
        "A pointer whose field the apply gives up rather than sets. Write it more than once for \
         more than one (specification section 44.1).",
    ),
    Parameter::new(
        "propagation",
        "string",
        "`Foreground`, `Background` or `Orphan` for a deletion's dependents \
         (specification section 45.2).",
    ),
];

/// The identity field of every Kubernetes schema, without exception.
///
/// `metadata.uid` is what the API server guarantees about one object's life; a name is a label a
/// human reuses (§16.1, §4 invariants 4–5). A schema keyed on the name would let a recreated Pod
/// inherit the history of the one it replaced, which is precisely the discontinuity §16.3 exists
/// to make visible.
pub const IDENTITY: &str = "uid";

/// [`IDENTITY`] as a schema's identity list.
const OBJECT_IDENTITY: &[&str] = &[IDENTITY];

/// What makes two edges the same edge (§23, §24.1, ADR-0014).
///
/// Four components, and each one is there because dropping it merges edges that are not the same
/// relationship:
///
/// - `uid` — the object the edge starts at, by the identity every other schema here uses. Two
///   edges of one Pod share it, which is exactly why it is not the whole key;
/// - `relation` — `owned-by` and `controlled-by` are the same fact read at two strengths (§24.3)
///   and a key without the word would collapse them;
/// - `target` — the far end's address, which is what distinguishes one owner reference from the
///   next. An address rather than a UID, because §24.1 keeps an edge whose target nobody read;
/// - `evidence_path` — a Pod that names one ConfigMap from two containers has two edges, and the
///   pointer is the only thing that differs. Null for the classes that rest on no single field,
///   where the three components above already separate them.
const EDGE_IDENTITY: &[&str] = &["uid", "relation", "target", "evidence_path"];

/// The metadata every Kubernetes object carries, projected the same way for every kind (§14).
///
/// Repeated per schema rather than shared through composition because `SchemaContribution` has no
/// notion of a mixin: the wire shape is a flat field list, and a reader of one schema should see
/// all of it in one place.
///
/// **All twelve of §14.1's fields, and the last four were the ones that reached nobody.**
/// `object.rs` has projected `annotations`, `finalizers`, `ownerReferences` and `managedFields`
/// since it was written; no schema declared them, so §14.1's "MUST NOT pretend the data is
/// absent" was breached at the boundary rather than in the library. Four things decided their
/// shape:
///
/// - `annotations` is a **map**, beside `labels`, because §14.5 requires both to stay structured.
///   Flattening either into text loses the one thing an operator does with them, which is to read
///   one key;
/// - `finalizers` is a list beside `terminating`, because §14.6 is one question asked twice: a
///   deletion was accepted, and something is holding it. Gate H's premise is that a user can see
///   the second half, and until now only the first half was reachable;
/// - `owner_references` is a `list<map>` rather than a list of names, because §14.6 keeps the
///   `controller` and `blockOwnerDeletion` flags meaningful and a name on its own answers
///   neither. It is *also* reachable as `k8s-relation` edges — the same fact as a relationship
///   with its evidence, where this is the same fact as metadata of the object (ADR-0013);
/// - `field_managers` is §14.7's **summary** rather than `managedFields` itself. The full record
///   is large, is rarely what anyone wants, and the specification asks for a summary by default;
///   the structure stays reachable through `k8s-resource`'s projection of the whole object.
const fn common(namespaced: bool) -> &'static [Field] {
    if namespaced {
        NAMESPACED_METADATA
    } else {
        CLUSTER_METADATA
    }
}

const CLUSTER_METADATA: &[Field] = &[
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::nullable("resource_version", "string"),
    Field::nullable("created", "timestamp"),
    Field::nullable("labels", "map"),
    Field::nullable("annotations", "map"),
    Field::required("terminating", "bool"),
    Field::nullable("finalizers", "list<string>"),
    Field::nullable("owner_references", "list<map>"),
    Field::nullable("field_managers", "list<string>"),
];

const NAMESPACED_METADATA: &[Field] = &[
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("namespace", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::nullable("resource_version", "string"),
    Field::nullable("created", "timestamp"),
    Field::nullable("labels", "map"),
    Field::nullable("annotations", "map"),
    Field::required("terminating", "bool"),
    Field::nullable("finalizers", "list<string>"),
    Field::nullable("owner_references", "list<map>"),
    Field::nullable("field_managers", "list<string>"),
];

/// Concatenates the shared metadata with a kind's own fields, at compile time.
///
/// A `const fn` rather than a macro so that the field order a schema declares — and therefore the
/// order a record stores its fields in — is visible in the table itself.
const fn with_metadata<const N: usize>(namespaced: bool, own: &'static [Field]) -> [Field; N] {
    let shared = common(namespaced);
    let mut fields = [Field::required("", ""); N];
    let mut at = 0;
    while at < shared.len() {
        fields[at] = shared[at];
        at += 1;
    }
    let mut own_at = 0;
    while own_at < own.len() {
        fields[at] = own[own_at];
        at += 1;
        own_at += 1;
    }
    fields
}

const NAMESPACE_FIELDS: [Field; 13] = with_metadata(false, &[Field::nullable("phase", "string")]);

const NODE_FIELDS: [Field; 16] = with_metadata(
    false,
    &[
        Field::nullable("ready", "string"),
        Field::nullable("unschedulable", "bool"),
        Field::nullable("kubelet_version", "string"),
        Field::nullable("internal_ip", "string"),
    ],
);

const POD_FIELDS: [Field; 18] = with_metadata(
    true,
    &[
        Field::nullable("phase", "string"),
        Field::nullable("node", "string"),
        Field::nullable("pod_ip", "string"),
        Field::nullable("containers", "list<string>"),
        Field::nullable("restarts", "int"),
    ],
);

const DEPLOYMENT_FIELDS: [Field; 20] = with_metadata(
    true,
    &[
        Field::nullable("desired_replicas", "int"),
        Field::nullable("ready_replicas", "int"),
        Field::nullable("updated_replicas", "int"),
        Field::nullable("available_replicas", "int"),
        Field::nullable("generation", "int"),
        Field::nullable("observed_generation", "int"),
        RECONCILIATION,
    ],
);

/// Where an object stands between what was asked of it and what has been observed (§37.5).
///
/// One field rather than three, and a map rather than a word, because §37.5 requires a derived
/// state to arrive with the rule that derived it and the fields that rule read. A bare string
/// would be a verdict nobody can check, and §37.3 is explicit that a matching
/// `observedGeneration` is *not* a claim of health — which is why `verified_convergence` is a
/// separate key from `state` and is true for exactly one of the five states.
///
/// Required rather than nullable: `condition::reconciliation` answers for every object, and its
/// answer for one with no evidence is "unknown due to insufficient evidence", which is a
/// statement rather than a gap.
const RECONCILIATION: Field = Field::required("reconciliation", "map");

const REPLICASET_FIELDS: [Field; 21] = with_metadata(
    true,
    &[
        Field::nullable("desired_replicas", "int"),
        Field::nullable("current_replicas", "int"),
        Field::nullable("ready_replicas", "int"),
        Field::nullable("available_replicas", "int"),
        Field::nullable("generation", "int"),
        Field::nullable("observed_generation", "int"),
        Field::nullable("controller", "string"),
        Field::nullable("controller_kind", "string"),
    ],
);

const STATEFULSET_FIELDS: [Field; 23] = with_metadata(
    true,
    &[
        Field::nullable("desired_replicas", "int"),
        Field::nullable("current_replicas", "int"),
        Field::nullable("ready_replicas", "int"),
        Field::nullable("updated_replicas", "int"),
        Field::nullable("available_replicas", "int"),
        Field::nullable("service_name", "string"),
        Field::nullable("current_revision", "string"),
        Field::nullable("update_revision", "string"),
        Field::nullable("claim_templates", "list<string>"),
        RECONCILIATION,
    ],
);

const DAEMONSET_FIELDS: [Field; 22] = with_metadata(
    true,
    &[
        Field::nullable("desired_scheduled", "int"),
        Field::nullable("current_scheduled", "int"),
        Field::nullable("ready_scheduled", "int"),
        Field::nullable("updated_scheduled", "int"),
        Field::nullable("available_scheduled", "int"),
        Field::nullable("misscheduled", "int"),
        Field::nullable("generation", "int"),
        Field::nullable("observed_generation", "int"),
        RECONCILIATION,
    ],
);

const SERVICE_FIELDS: [Field; 20] = with_metadata(
    true,
    &[
        Field::nullable("service_type", "string"),
        Field::nullable("cluster_ip", "string"),
        Field::nullable("external_ips", "list<string>"),
        Field::nullable("external_name", "string"),
        Field::nullable("load_balancer", "list<string>"),
        Field::nullable("ports", "map"),
        Field::nullable("selector", "map"),
    ],
);

const ENDPOINTSLICE_FIELDS: [Field; 20] = with_metadata(
    true,
    &[
        Field::nullable("address_type", "string"),
        Field::nullable("service_name", "string"),
        Field::nullable("endpoint_count", "int"),
        Field::nullable("ready_endpoints", "int"),
        Field::nullable("addresses", "list<string>"),
        Field::nullable("targets", "list<string>"),
        Field::nullable("ports", "map"),
    ],
);

const INGRESS_FIELDS: [Field; 18] = with_metadata(
    true,
    &[
        Field::nullable("ingress_class", "string"),
        Field::nullable("hosts", "list<string>"),
        Field::nullable("services", "list<string>"),
        Field::nullable("tls_secrets", "list<string>"),
        Field::nullable("load_balancer", "list<string>"),
    ],
);

const JOB_FIELDS: [Field; 25] = with_metadata(
    true,
    &[
        Field::nullable("completions", "int"),
        Field::nullable("parallelism", "int"),
        Field::nullable("active", "int"),
        Field::nullable("succeeded", "int"),
        Field::nullable("failed", "int"),
        Field::nullable("start_time", "timestamp"),
        Field::nullable("completion_time", "timestamp"),
        Field::nullable("complete", "string"),
        Field::nullable("failure_reason", "string"),
        Field::nullable("controller", "string"),
        Field::nullable("controller_kind", "string"),
        RECONCILIATION,
    ],
);

const CRONJOB_FIELDS: [Field; 19] = with_metadata(
    true,
    &[
        Field::nullable("schedule", "string"),
        Field::nullable("suspend", "bool"),
        Field::nullable("concurrency_policy", "string"),
        Field::nullable("last_schedule_time", "timestamp"),
        Field::nullable("last_successful_time", "timestamp"),
        Field::nullable("active_jobs", "list<string>"),
    ],
);

const CONFIGMAP_FIELDS: [Field; 16] = with_metadata(
    true,
    &[
        Field::nullable("keys", "list<string>"),
        Field::nullable("binary_keys", "list<string>"),
        Field::nullable("immutable", "bool"),
    ],
);

const SECRET_FIELDS: [Field; 15] = with_metadata(
    true,
    &[
        Field::nullable("secret_type", "string"),
        Field::nullable("keys", "list<string>"),
    ],
);

const SERVICEACCOUNT_FIELDS: [Field; 16] = with_metadata(
    true,
    &[
        Field::nullable("secrets", "list<string>"),
        Field::nullable("image_pull_secrets", "list<string>"),
        Field::nullable("automount_token", "bool"),
    ],
);

const PERSISTENTVOLUMECLAIM_FIELDS: [Field; 20] = with_metadata(
    true,
    &[
        Field::nullable("phase", "string"),
        Field::nullable("volume_name", "string"),
        Field::nullable("storage_class", "string"),
        Field::nullable("volume_mode", "string"),
        Field::nullable("access_modes", "list<string>"),
        Field::nullable("requested_storage", "string"),
        Field::nullable("bound_capacity", "string"),
    ],
);

const PERSISTENTVOLUME_FIELDS: [Field; 20] = with_metadata(
    false,
    &[
        Field::nullable("phase", "string"),
        Field::nullable("capacity", "string"),
        Field::nullable("storage_class", "string"),
        Field::nullable("volume_mode", "string"),
        Field::nullable("access_modes", "list<string>"),
        Field::nullable("reclaim_policy", "string"),
        Field::nullable("claim", "string"),
        Field::nullable("csi_driver", "string"),
    ],
);

const STORAGECLASS_FIELDS: [Field; 18] = with_metadata(
    false,
    &[
        Field::nullable("provisioner", "string"),
        Field::nullable("reclaim_policy", "string"),
        Field::nullable("volume_binding_mode", "string"),
        Field::nullable("allow_volume_expansion", "bool"),
        Field::nullable("is_default", "bool"),
        Field::nullable("parameters", "map"),
    ],
);

const NETWORKPOLICY_FIELDS: [Field; 16] = with_metadata(
    true,
    &[
        Field::nullable("pod_selector", "map"),
        Field::nullable("policy_types", "list<string>"),
        Field::nullable("rules", "map"),
    ],
);

/// The one schema every dynamically discovered resource's records carry.
///
/// **Why one schema and not one per kind.** A record may only claim a schema the package
/// contributed at load, and the contributions are fixed before the package has spoken to any
/// cluster — so there is no moment at which a schema named after a CRD could be declared. The
/// host enforces this twice over: a record whose schema id is not in the handshake's registry
/// does not decode at all, and one that decodes but does not match the target's declared schema
/// is a `runtime.schema_violation`. A dynamic record therefore carries
/// `io.github.godspeed-you.kubernetes.resource/1` whatever kind it holds, and says which
/// Kubernetes type it *is* in its fields rather than in its schema id (§13.2). ADR-0010.
///
/// The fields after the shared metadata are three claims:
///
/// - **what this is** — `api_group`, `resource_name`, `scope`, which is §13.2's canonical host
///   type, so that identity survives the flattening of every kind onto one schema;
/// - **how well it is known** — `schema_source` and `precision`, because a projection that does
///   not say where its typing came from invites the reader to trust all of it equally (§12.3);
/// - **what it holds** — `spec`, `status` and `other`, kept apart because desired and observed
///   state are different claims (§4 invariant 8, §33.6), plus `untyped`, the pointers of the
///   fields no schema described. Those fields are *in* `spec`, `status` and `other` all the
///   same: §12.5 preserves them, and `untyped` says which they are rather than hiding them.
const RESOURCE_FIELDS: [Field; 22] = with_metadata(
    true,
    &[
        Field::required("api_group", "string"),
        Field::required("resource_name", "string"),
        Field::required("scope", "enum<namespaced|cluster>"),
        Field::required("schema_source", "enum<openapi-v3|crd-structural|absent>"),
        Field::required("precision", "enum<structural|loose|unknown>"),
        Field::nullable("spec", "map"),
        Field::nullable("status", "map"),
        Field::nullable("other", "map"),
        Field::required("untyped", "list<string>"),
    ],
);

/// One relationship, with the evidence that decided it (§23 to §32, Gate D, ADR-0014).
///
/// **A record per edge, rather than a list of edges on the object's record.** An edge is a value
/// a pipeline filters, sorts and groups; folded into a Pod's record it would be one opaque list
/// field, and every one of the nineteen schemas would grow it. It would also inherit the object's
/// identity, so a Pod's six relationships would be one thing six times.
///
/// Four groups of fields, and the boundaries between them are the point:
///
/// - **where it starts** — §14's metadata of the source object, spelled exactly as every other
///   schema here spells it, plus `source` as the place address of §35.4. The record is a fact
///   *about* that object, which is why `uid` means here what it means everywhere else;
/// - **what it is** — `relation`, the word `follow` takes (§35.7). One vocabulary: a curated
///   routing edge and an owner reference are the same kind of thing with different evidence
///   behind them;
/// - **where it points** — the far end, as an address and in parts. `target_resolved` is false
///   for an edge whose target nobody read, which §24.1 requires to stay an edge; `target_uid` is
///   then whatever the reference itself carried, and null where it carried none. `target_roles`
///   is §36.2's overlay, beside the native kind rather than instead of it (§36.1);
/// - **why it exists** — `evidence_class` is Gate D's six-way choice, `evidence` is what was read
///   and what it held, `evidence_path` is the pointer where the class cites one, and `asserted`
///   is §23.3's distinction: the API server states an owner reference and a `nodeName`, and it is
///   *this provider* that evaluates a selector against labels. `supporting` carries what
///   qualifies the edge without deciding it — the host, path and port §27.1 requires to stay
///   attached, the adapter that read a custom resource (§33.8).
///
/// Everything but `evidence_path` and the two nullable target parts is required, because an edge
/// that could not say one of them would not be checkable, and Gate D is the requirement that it
/// is.
const RELATION_FIELDS: &[Field] = &[
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("namespace", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::required("source", "string"),
    Field::required("relation", "string"),
    Field::required("target", "string"),
    Field::required("target_kind", "string"),
    Field::required("target_name", "string"),
    Field::nullable("target_namespace", "string"),
    Field::nullable("target_uid", "string"),
    Field::required("target_resolved", "bool"),
    Field::required("target_roles", "list<string>"),
    Field::required(
        "evidence_class",
        "enum<native-field|owner-reference|selector|convention|adapter-derivation|inference>",
    ),
    Field::required("evidence", "string"),
    Field::nullable("evidence_path", "string"),
    Field::required("asserted", "bool"),
    Field::required("supporting", "list<string>"),
    Field::required("observed_resource_versions", "map"),
];

/// What makes two observations the same observed change (§19.3, §39.3).
///
/// A change has no `metadata.uid` of its own — the UID on the record is the *object's*, and one
/// object changing three times is three observations. Five components, and each is there because
/// dropping it merges observations that are not the same one:
///
/// - `resource` — two collections may both hold an object of one UID at one version only if one
///   of them is an aggregated view of the other, and this provider watches neither on the other's
///   behalf;
/// - `segment` — the unbroken period this observation belongs to. §19.4 forbids stitching pre-gap
///   and post-gap observation into one history, and a key without the segment would let a
///   re-listed object collapse onto the one observed before the break;
/// - `change` — an object listed at acquisition and the same object modified a moment later are
///   two facts, and the word is what separates them;
/// - `uid` — which object. Null for a gap, which is about a period rather than about an object;
/// - `resource_version` — which version of it. Null for a gap, and for a `DELETED` whose final
///   object the server sent without one.
const CHANGE_IDENTITY: &[&str] = &["resource", "segment", "change", "uid", "resource_version"];

/// What makes two exported facts about a machine the same fact (§47, ADR-0016).
///
/// Three components, and the third is the one that is easy to leave out. A Node commonly reports
/// an internal address, a public address and a hostname, and all three are published under
/// [`key::ADDRESS`](ono_provider_kubernetes::evidence::key::ADDRESS) — so a key without the
/// pointer they were read from would merge three separate pieces of evidence into one. The
/// pointer is null for a key that could not be read at all, where the key alone separates them.
const EVIDENCE_IDENTITY: &[&str] = &["uid", "key", "source"];

/// What makes two log lines the same line (§42.1).
///
/// The Pod's lifetime identity rather than its name, because a Pod deleted and recreated under
/// one name is two containers and their outputs are not one log (§4 invariants 4–5). The run is
/// in the key because `previous` reaches a different container from the one running now, and the
/// ordinal is in it because a log line is not unique in its own text — a process that prints one
/// message twice printed it twice.
const LOG_IDENTITY: &[&str] = &["uid", "container", "instance", "line"];

/// What makes two temporal observations the same observation (§39.1, §39.2).
///
/// The clock is part of the key and not a decoration: the same instant written by the API server
/// and by a reporting controller are two observations of two machines' idea of the time, and a
/// key without the clock would merge them into the single history §39.2 forbids. `stamp` is the
/// raw string the clock wrote, never a parsed instant, for the same reason.
const OBSERVATION_IDENTITY: &[&str] = &["uid", "source", "clock", "stamp", "detail"];

/// What makes two findings the same finding (§40).
///
/// The claim is in the key because the same two facts may support a weak claim and a stronger
/// one, and collapsing them would let a reader see only one rung of the ladder.
const FINDING_IDENTITY: &[&str] = &["uid", "claim", "support"];

/// What makes two conditions the same condition (§37.1).
///
/// The `type` within one object's lifetime, which is the uniqueness the API's own convention
/// gives conditions. Not the status: a condition that flipped is the same condition.
const CONDITION_IDENTITY: &[&str] = &["uid", "condition_type"];

/// What makes two prospective changes, or two attempts at one, the same thing (§46, §56).
///
/// Four components, and the argument for the second is the interesting one. A plan is about one
/// object *lifetime* (`uid`, §16.3), aimed at one point in that lifetime's continuity
/// (`resource_version`, §56.1), doing one thing (`action`) to a named set of fields (`changes`).
/// Two records agreeing on all four describe the same change, and a mutation record is keyed the
/// same way because a `resourceVersion` precondition is *consumed* by the write that satisfies
/// it: an accepted apply moves the object on, so a second attempt asserting the same token is
/// refused rather than being a second write of the same key. Dropping any component merges
/// things that are not the same — two field sets against one object, an apply with a delete, or
/// a plan built before a concurrent write with one built after it.
const PLAN_IDENTITY: &[&str] = &["uid", "resource_version", "action", "changes"];

/// One Kubernetes Event, and everything §38 says it is not (§38, Gate F's neighbour).
///
/// **An aggregated Event is one record.** `recorded_count` carries the number the server
/// recorded and `aggregate` says that the record stands for more than one occurrence — and there
/// is no field, and no route through this package, by which 47 aggregated failures become 47
/// records. Kubernetes aggregates precisely so that the individual occurrences need not be
/// stored, so 46 of them were never observed and manufacturing them would produce records a
/// reader could not tell from observed ones (§38.4).
///
/// **Nothing here is a history.** `event_time`, `first_seen`, `last_seen` and
/// `series_last_observed` are strings rather than timestamps, and `clock` names the machine that
/// wrote `event_time` beside it. A timestamp field would be sortable, and a set of Events sorted
/// by time reads as a sequence of what happened while being an artefact of three unrelated
/// accidents: the reporters' clocks, unordered delivery, and retention that has already discarded
/// part of it (§38.1, §39.2).
///
/// **`reason` is evidence, not machine semantics.** It is carried so a reader sees it and never
/// so anything branches on it: upstream warns that reasons evolve, and a consumer switching on
/// one is an unversioned dependency that stops matching without failing (§38.5).
///
/// The shared metadata is §14's, spelled as every other schema here spells it: an Event *is* a
/// Kubernetes object, with a `metadata.uid` of its own, and the object it regards is a field of
/// it rather than its identity (ADR-0013).
const EVENT_FIELDS: [Field; 34] = with_metadata(
    true,
    &[
        // --- which of §38.2's two representations this was read from ---
        Field::required("representation", "enum<events.k8s.io|core>"),
        // --- what the reporter said ---
        Field::required("level", "string"),
        Field::nullable("reason", "string"),
        Field::nullable("note", "string"),
        Field::nullable("action", "string"),
        // --- what it is about (§38.3) ---
        Field::nullable("regarding", "string"),
        Field::nullable("regarding_kind", "string"),
        Field::nullable("regarding_name", "string"),
        Field::nullable("regarding_namespace", "string"),
        Field::nullable("regarding_uid", "string"),
        Field::nullable("related", "string"),
        // --- who said it (§38.3) ---
        Field::nullable("reporting_controller", "string"),
        Field::nullable("reporting_instance", "string"),
        // --- when, and on whose clock (§39.1) ---
        Field::nullable("event_time", "string"),
        Field::required("clock", "string"),
        // --- how often, as a count and never as a list (§38.4) ---
        Field::required("aggregate", "bool"),
        Field::nullable("recorded_count", "int"),
        Field::nullable("series_count", "int"),
        Field::nullable("series_last_observed", "string"),
        Field::nullable("first_seen", "string"),
        Field::nullable("last_seen", "string"),
    ],
);

/// One fact a Node states about the machine underneath it, exported rather than resolved (§47).
///
/// **Nothing here presents a match.** There is no target, no link, no foreign identifier and no
/// resolution: this provider has read Kubernetes and nothing else, so the strongest honest claim
/// it can make is "here is what the API server stated, here is where it stated it, and here is
/// how far that value narrows anything down" (§47.1, ADR-0016). Which foreign resource a value
/// matches is a finding of a resolver that has read both sides, and this schema deliberately has
/// nowhere to put one.
///
/// **Distinguishing evidence stays distinguishable from correlating evidence.** `strength` is
/// §47.2's ranking as a field rather than something a consumer rebuilds from key names — which
/// would be the vendor knowledge §47.1 keeps out of here in a different disguise. A private
/// address repeats between clusters and a public one outlives the machine that held it, so
/// `lookup_key` is false for every address however exact the value looks.
///
/// **A key that could not be read is a record too.** `observed` is false for it, `value` and
/// `source` are null, and `outcome` names one of §21.4's eight states — so a Node whose spec
/// carries no provider identifier reads differently from one whose spec nobody projected.
const EVIDENCE_FIELDS: &[Field] = &[
    // --- whose evidence this is, bound to a lifetime rather than to a name (§4 invariants 4–5) ---
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::required("subject", "string"),
    // --- what kind of fact, and what it held ---
    Field::required("key", "string"),
    Field::nullable("qualifier", "string"),
    Field::nullable("value", "string"),
    // --- where it was read, and how far it goes ---
    Field::nullable("source", "string"),
    // Null for a key that was not read: strength is how far a *value* narrows the subject down,
    // and there is no value. Never defaulted to the weakest, which would be a claim about a
    // machine nobody looked at.
    Field::nullable("strength", "enum<distinguishing|correlating|placement>"),
    Field::nullable(
        "evidence_class",
        "enum<native-field|owner-reference|selector|convention|adapter-derivation|inference>",
    ),
    Field::nullable("evidence", "string"),
    Field::nullable("asserted", "bool"),
    Field::nullable("lookup_key", "bool"),
    // --- §28.4's whole permitted decomposition of a URI-shaped identifier, and no more ---
    Field::nullable("uri_scheme", "string"),
    Field::nullable("uri_path", "string"),
    // --- or a key that was not read, which is not a machine with nothing to say ---
    Field::required("observed", "bool"),
    Field::nullable("outcome", "string"),
];

/// One line of a container's log, and everything that is not in it (§42.1, §42.2).
///
/// **`bounds` is never empty, on any record.** The container runtime rotated and truncated this
/// log before anybody asked, so even an unbounded request carries `the container runtime rotated
/// and truncated this log before it was read`, and a `tailLines`, `sinceSeconds` or `limitBytes`
/// adds its own entry. A record without it would imply completeness by omission, which is the one
/// thing §42.1 will not have: a log is not the container's output.
///
/// **A line is bytes.** `text` is null where the bytes are not UTF-8 and `not_utf8_after` says
/// how far decoding got, because substituting U+FFFD hands a reader something that looks like the
/// container's output and is not it. `bytes` is the length either way.
///
/// **`stamp` is a string beside its `clock`.** The prefix the API server writes comes from the
/// container runtime on the node, and parsing it into an instant would make it sortable against
/// this provider's own observations — the cross-clock timeline §39.2 forbids.
///
/// `may_contain_secrets` is true on every record and is not a scan of the content: whether a log
/// carries a credential is not decidable from the log, and a field that sometimes answered false
/// would be a filter that is wrong exactly when it matters (§42.2).
const LOG_FIELDS: &[Field] = &[
    // --- what was read, bound to the Pod's lifetime and never to its name ---
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("namespace", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::nullable("container", "string"),
    Field::required("instance", "enum<current|previous>"),
    // --- the line ---
    Field::required("line", "int"),
    Field::nullable("text", "string"),
    Field::required("bytes", "int"),
    Field::nullable("not_utf8_after", "int"),
    Field::nullable("stamp", "string"),
    Field::required("clock", "string"),
    Field::required("terminated", "bool"),
    // --- and what this is not ---
    Field::required("bounds", "list<string>"),
    Field::required("ending", "string"),
    Field::required("may_contain_secrets", "bool"),
];

/// One thing known to have a time attached, with the clock that wrote it (§39).
///
/// **`stamp` is the string the clock wrote.** Not a timestamp: a timestamp field is one a shell
/// sorts, and five of Kubernetes' timestamps are written by five machines. Sorting them produces
/// something that reads as a history of the cluster and is a picture of the skew between those
/// machines (§39.2). `clock` travels beside it, and two records whose clocks differ are not in
/// any order at all.
///
/// **`basis` is the distinction the whole section exists for.** `observed` means this provider
/// saw the change while it was watching; `reported` means a timestamp was read off state. A Pod
/// created at 08:00 and first read at 14:00 is a *reported* object-metadata observation, and
/// filing it as six hours of history is precisely what §39.2 forbids.
///
/// **Every record carries the window and the gaps.** `window_opened` and `window_latest` are this
/// provider's own clock, which is the only clock it owns, and `gaps` names each stretch that
/// could not be observed. A record that carried observations without them would let a reader take
/// a sequence for a complete one — and `not_observed` is the other kind of hole, a scope that was
/// never readable, because a continuous window over a denied namespace is not a complete answer.
const TIMELINE_FIELDS: &[Field] = &[
    // --- what the observation is about ---
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("namespace", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    // --- what kind of observation it is (§39.1, §39.2) ---
    Field::required("basis", "enum<observed|reported>"),
    Field::required(
        "source",
        "enum<watch-event|resource-snapshot|event-record|object-metadata|condition-transition|managed-field>",
    ),
    Field::required("clock", "string"),
    Field::required("stamp", "string"),
    Field::required("placeable", "bool"),
    Field::required("detail", "string"),
    // --- the period it belongs to, and the holes in that period (§39.3) ---
    Field::required("window_opened", "timestamp"),
    Field::required("window_latest", "timestamp"),
    Field::required("continuous", "bool"),
    Field::required("gaps", "list<string>"),
    Field::required("not_observed", "list<string>"),
];

/// One thing this provider is prepared to say about why an object is as it is (§40).
///
/// **There is no field for a cause, and that is the schema's content.** The strongest thing a
/// record here carries is a `claim`, there are five of them, and none says that one thing brought
/// about another. `claim_means` travels with it because a token on its own is read as strongly as
/// its reader needs it to be — `CORRELATED_WITH` arrives with "one clock saw both, close
/// together; proximity is not a causal link" attached to it.
///
/// **`strongest_claim` is on every record rather than on a summary somebody may not read.** It is
/// the maximum of the ladder and never a sum: three weak findings do not add up to a strong one.
/// `insufficient_evidence` is §40.5's required conclusion, which the specification calls
/// preferable to a plausible invented explanation.
///
/// **A refusal is a record.** A finding that established nothing keeps its `not_proven` reason —
/// different clocks, an unreadable timestamp, a window that was too narrow, no path, nothing
/// asserted — because an answer with the empty findings dropped looks like one where nobody
/// looked (§4 invariant 13).
const WHY_FIELDS: &[Field] = &[
    // --- what the answer is about ---
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("namespace", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    // --- the rung, verbatim, and where it stops ---
    Field::required(
        "claim",
        "enum<CAUSALITY_NOT_PROVEN|CORRELATED_WITH|PRECEDED_BY|DEPENDENCY_PATH_EXISTS|ASSERTED_BY_KUBERNETES>",
    ),
    Field::required("claim_means", "string"),
    // --- what was read to say it ---
    Field::required("support_class", "enum<sequence|path|assertion|nothing>"),
    Field::required("support", "string"),
    Field::nullable("not_proven", "string"),
    Field::nullable("clock", "string"),
    Field::nullable("apart_ms", "int"),
    Field::nullable(
        "evidence_class",
        "enum<native-field|owner-reference|selector|convention|adapter-derivation|inference>",
    ),
    Field::nullable("evidence_path", "string"),
    // --- the ceiling of the whole answer, and what the search could not reach ---
    Field::required(
        "strongest_claim",
        "enum<CAUSALITY_NOT_PROVEN|CORRELATED_WITH|PRECEDED_BY|DEPENDENCY_PATH_EXISTS|ASSERTED_BY_KUBERNETES>",
    ),
    Field::required("insufficient_evidence", "bool"),
    Field::required("not_observed", "list<string>"),
];

/// One structured observation a controller wrote about an object (§37.1).
///
/// **`status` is the string the API carries.** `True`, `False` and `Unknown` are three states and
/// a boolean has two, and a controller may write a fourth word this provider has never seen —
/// which §37.2 requires to survive rather than be coerced into `false`.
///
/// **`observedGeneration` is never on its own a claim of health.** `observed_generation` and
/// `generation` are two plain numbers here, and the only derived state is the `reconciliation`
/// map — which arrives with the rule that produced it and the fields that rule read (§37.5), and
/// whose `verified_convergence` key is true for exactly one of five states and never for
/// `generation-observed-only` (§37.3). There is deliberately no `healthy`, no `ready` and no
/// green word anywhere on this record.
///
/// `last_transition_time` is a string beside `clock`, and the clock is `unattributed`:
/// `status.conditions` does not say which controller wrote an entry, so two conditions on one
/// object may be two machines' idea of the time and must not be ordered against each other.
const CONDITION_FIELDS: &[Field] = &[
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("namespace", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::required("condition_type", "string"),
    Field::required("status", "string"),
    Field::nullable("reason", "string"),
    Field::nullable("message", "string"),
    Field::nullable("observed_generation", "int"),
    Field::nullable("generation", "int"),
    Field::nullable("last_transition_time", "string"),
    Field::required("clock", "string"),
    RECONCILIATION,
];

/// One observed change, and the continuity it belongs to (§19, §39.3, §41.4, Gate F).
///
/// **A record per observation, and a record for the periods with no observations in them.** The
/// hard requirement of §19 is not that changes are delivered; it is that a *gap* in the
/// observation is impossible to miss. §4 invariant 14 and §19.4 say pre-gap and post-gap events
/// are never stitched into a continuous history, and a stream of change records with nothing to
/// mark the break would be exactly that stitching — the reader would see an ordered sequence and
/// have no way to know that a period of it was never observed.
///
/// So three fields carry the continuity, and they are required rather than optional because a
/// record that could omit them would let a consumer forget to ask:
///
/// - `segment` counts the unbroken periods. Everything before a `410` is segment 1 and everything
///   after it is segment 2, so `group by segment` is the honest reading and `sort by time` is not
///   available as an accident;
/// - `continuous` is false from the first gap onward — the one-bit form of the same fact, for the
///   reader who filters rather than groups;
/// - `sync_state` is §41.4's word for what a live view may honestly show right now: syncing,
///   live, reconnecting, gap detected, denied. `live` is the only one of the five that entitles
///   anybody to read an absence as an absence (§20.3).
///
/// `change` has five members and `gap` is one of them. A gap could have been a second schema; it
/// is not, because a consumer that has to join two streams to notice a break is a consumer that
/// will forget to, and because a gap *is* an observation — of a period, rather than of an object.
/// Its object fields are null for the same reason: null is unknown, and what happened in that
/// period is precisely what is unknown.
///
/// The object fields are §14's, spelled as every other schema here spells them (ADR-0013). They
/// are all nullable, which the object schemas' are not: this record may be about no object at
/// all.
const CHANGE_FIELDS: &[Field] = &[
    // --- what happened, and to what ---
    Field::required("change", "enum<listed|added|modified|deleted|gap|notice>"),
    Field::required("resource", "string"),
    Field::required("scope", "string"),
    // --- which observation period, and whether anything was missed reaching it ---
    Field::required("segment", "int"),
    Field::required("continuous", "bool"),
    Field::required("sync_state", "string"),
    // §41.4's six words, which are `sync_state`'s five and one more. `sync_state` is about the
    // *connection* — what `watch.rs` can know without a clock — and `view_state` is about what a
    // reader is looking at: a stream that is `live` and has told nobody anything for longer than
    // the window is `stale`, and a table that kept rendering it would be the frozen one §41.4
    // forbids. The two are separate fields because they answer different questions and can
    // honestly disagree.
    Field::required(
        "view_state",
        "enum<syncing|live|reconnecting|gap detected|stale|denied>",
    ),
    // How many objects the view is holding, and how many it is not (§18.5, §50.4). A bound that
    // is not reported is a truncation presented as a complete picture.
    Field::required("withheld", "int"),
    // --- the object it happened to, where there was one ---
    Field::nullable("uid", "string"),
    Field::nullable("name", "string"),
    Field::nullable("namespace", "string"),
    Field::nullable("api_version", "string"),
    Field::nullable("kind", "string"),
    Field::nullable("resource_version", "string"),
    Field::nullable("created", "timestamp"),
    Field::nullable("labels", "map"),
    Field::nullable("terminating", "bool"),
    Field::nullable("finalizers", "list<string>"),
    // --- what was not observed, for the one class that is about a period ---
    Field::nullable(
        "gap_reason",
        "enum<watch_expired_410|watch_denied|restarted_without_checkpoint|change_log_trimmed>",
    ),
    Field::nullable("gap_detail", "string"),
];

/// What `k8s-cluster` answers: which cluster this is, whether it answers, and who the provider is
/// to it (§8.5, §8.6, §10, §34.3, §61.1).
///
/// The shared metadata of every other schema is deliberately absent. There is no
/// `metadata.uid` here because there is no Kubernetes object: the identity is the *provider
/// instance* of §10.1 — `kubernetes:<context>` — which is what stays stable across reconnects and
/// what two instances pointed at one cluster differ in. Keying this record on the cluster
/// fingerprint instead would merge exactly the two instances §10.3 says MUST NOT be merged.
///
/// Four groups of fields, and the boundaries between them are the point:
///
/// - **which cluster** — `server`, `kube_system_uid`, `server_key_fingerprint` are §10.2's
///   signals one by one, and `fingerprint` plus `fingerprint_signals` are what they compose to.
///   A signal that was not obtained is `null` and names its reason in `unknowns`, so a fingerprint
///   built from one signal is visibly weaker than one built from three;
/// - **whether it answers** — `reachable`, `server_version`, `tls`, and the per-request `probes`
///   and `latency_ms` §34.3 asks for, so that a slow aggregated API is not reported as "the
///   cluster";
/// - **who the provider is to it** — `credential_identity` and `effective_identity` are two
///   fields rather than one, because §8.5 requires them to be impossible to confuse the day
///   impersonation exists. `impersonating` says whether they can differ;
/// - **what it could not determine** — `unknowns`, each entry naming a subject and one of §21.4's
///   eight outcomes, so a field the cluster refused reads differently from one it does not have;
/// - **what it can do here** — `capabilities`, one entry per capability, each a two-part
///   statement of what the provider supports and what *this* session found (§57.1). The two
///   halves are never derived from one another: a capability this build refuses reads
///   differently from one the cluster does not serve, from one the operator did not grant, and
///   from one nobody has asked about.
const CLUSTER_FIELDS: &[Field] = &[
    Field::required("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("server", "string"),
    Field::required("reachable", "bool"),
    Field::nullable("server_version", "string"),
    Field::required("tls", "string"),
    Field::nullable("fingerprint", "string"),
    Field::required("fingerprint_signals", "list<string>"),
    Field::nullable("kube_system_uid", "string"),
    Field::nullable("server_key_fingerprint", "string"),
    Field::nullable("credential_identity", "string"),
    Field::nullable("effective_identity", "string"),
    Field::nullable("effective_uid", "string"),
    Field::nullable("effective_groups", "list<string>"),
    Field::required("impersonating", "bool"),
    Field::nullable("impersonated_user", "string"),
    Field::required("unknowns", "list<string>"),
    Field::required("probes", "map"),
    Field::required("latency_ms", "map"),
    Field::required("capabilities", "map"),
    Field::nullable("discovery", "map"),
];

/// The targets this package answers for.
///
/// **All nineteen of §15.2's Tier 1 set, in the order §15.2 lists them**, plus the dynamic noun
/// and the instance diagnostic. Every word `package/contributions/targets.yaml` declares is now
/// a word this package answers — which is what ADR-0005 asked for and deferred: a declared
/// schema is a promise, so a schema arrives with the handler that keeps it, and there is no
/// longer a placeholder naming a schema nothing emits.
///
/// The order is §15.2's rather than alphabetical, because the list is a walk through workload
/// troubleshooting — scope, machine, workload, controllers, routing, batch, configuration,
/// identity, storage, policy — and the reader who wants a kind reaches it by remembering what it
/// is near.
///
/// Each schema's fields are the ones an operator troubleshoots with, not every field the API
/// carries (§15.5). Where a kind has a meaningful desired-versus-observed distinction — the four
/// workload controllers and Job — the record carries a `reconciliation` map derived by
/// `condition::reconciliation`, so the state arrives with the rule that produced it and the
/// fields that rule read (§37.5) and never as a status word this package invented.
///
/// `k8s-resource` is the floor beneath all of them (§15.1): it reads whatever the cluster serves
/// and this package never heard of, so a curated noun is a *better* answer for a kind rather
/// than the only answer for it. A curated noun that is deleted from this table costs its user a
/// more verbose spelling and nothing else.
pub static TARGETS: &[Target] = &[
    Target {
        name: "k8s-namespace",
        schema: "io.github.godspeed-you.kubernetes.namespace/1",
        schema_name: "KubernetesNamespace",
        schema_summary: "A namespace, the primary scope dimension of a cluster.",
        summary: "Namespaces, the primary scope dimension of a cluster.",
        identity_doc: "Two observations are the same namespace when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "",
            kind: "Namespace",
        },
        fields: &NAMESPACE_FIELDS,
    },
    Target {
        name: "k8s-node",
        schema: "io.github.godspeed-you.kubernetes.node/1",
        schema_name: "KubernetesNode",
        schema_summary: "A node, and what the kubelet on it reports about itself.",
        summary: "Nodes, and the cloud instances underneath them.",
        identity_doc: "Two observations are the same node when their `metadata.uid` matches; a \
                       name reused after deletion is a new node.",
        reads: Reads::Kind {
            group: "",
            kind: "Node",
        },
        fields: &NODE_FIELDS,
    },
    Target {
        name: "k8s-pod",
        schema: "io.github.godspeed-you.kubernetes.pod/1",
        schema_name: "KubernetesPod",
        schema_summary: "A pod, the workload that actually runs.",
        summary: "Pods, the workload that actually runs.",
        identity_doc: "Two observations are the same pod when their `metadata.uid` matches. A \
                       recreated pod with the same name is a different pod.",
        reads: Reads::Kind {
            group: "",
            kind: "Pod",
        },
        fields: &POD_FIELDS,
    },
    Target {
        name: "k8s-deployment",
        schema: "io.github.godspeed-you.kubernetes.deployment/1",
        schema_name: "KubernetesDeployment",
        schema_summary: "A deployment, with what was asked of it beside what has been observed.",
        summary: "Deployments, and the ReplicaSets they control.",
        identity_doc: "Two observations are the same deployment when their `metadata.uid` \
                       matches.",
        reads: Reads::Kind {
            group: "apps",
            kind: "Deployment",
        },
        fields: &DEPLOYMENT_FIELDS,
    },
    Target {
        name: "k8s-replicaset",
        schema: "io.github.godspeed-you.kubernetes.replicaset/1",
        schema_name: "KubernetesReplicaSet",
        schema_summary: "A ReplicaSet, and the controller above it.",
        summary: "ReplicaSets, which sit between a Deployment and its Pods.",
        identity_doc: "Two observations are the same ReplicaSet when their `metadata.uid` \
                       matches.",
        reads: Reads::Kind {
            group: "apps",
            kind: "ReplicaSet",
        },
        fields: &REPLICASET_FIELDS,
    },
    Target {
        name: "k8s-statefulset",
        schema: "io.github.godspeed-you.kubernetes.statefulset/1",
        schema_name: "KubernetesStatefulSet",
        schema_summary: "A StatefulSet, its rollout revisions and the claims its templates ask \
                         for.",
        summary: "StatefulSets, and the claims their templates materialise.",
        identity_doc: "Two observations are the same StatefulSet when their `metadata.uid` \
                       matches.",
        reads: Reads::Kind {
            group: "apps",
            kind: "StatefulSet",
        },
        fields: &STATEFULSET_FIELDS,
    },
    Target {
        name: "k8s-daemonset",
        schema: "io.github.godspeed-you.kubernetes.daemonset/1",
        schema_name: "KubernetesDaemonSet",
        schema_summary: "A DaemonSet, counted per node rather than per replica.",
        summary: "DaemonSets, and their rollout across nodes.",
        identity_doc: "Two observations are the same DaemonSet when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "apps",
            kind: "DaemonSet",
        },
        fields: &DAEMONSET_FIELDS,
    },
    Target {
        name: "k8s-service",
        schema: "io.github.godspeed-you.kubernetes.service/1",
        schema_name: "KubernetesService",
        schema_summary: "A service: how it is addressed, on which ports, and what it selects.",
        summary: "Services, and the Pods their selectors reach.",
        identity_doc: "Two observations are the same service when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "",
            kind: "Service",
        },
        fields: &SERVICE_FIELDS,
    },
    Target {
        name: "k8s-endpointslice",
        schema: "io.github.godspeed-you.kubernetes.endpointslice/1",
        schema_name: "KubernetesEndpointSlice",
        schema_summary: "An EndpointSlice: which addresses answer for a service, and which of \
                         them are ready.",
        summary: "EndpointSlices, the endpoints a Service is represented by.",
        identity_doc: "Two observations are the same slice when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "discovery.k8s.io",
            kind: "EndpointSlice",
        },
        fields: &ENDPOINTSLICE_FIELDS,
    },
    Target {
        name: "k8s-ingress",
        schema: "io.github.godspeed-you.kubernetes.ingress/1",
        schema_name: "KubernetesIngress",
        schema_summary: "An ingress: which hosts it answers for, which services it routes to, \
                         and which secrets terminate its TLS.",
        summary: "Ingresses, and the Services they route to.",
        identity_doc: "Two observations are the same ingress when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "networking.k8s.io",
            kind: "Ingress",
        },
        fields: &INGRESS_FIELDS,
    },
    Target {
        name: "k8s-job",
        schema: "io.github.godspeed-you.kubernetes.job/1",
        schema_name: "KubernetesJob",
        schema_summary: "A job, with what it was asked to complete beside what it has.",
        summary: "Jobs, and the Pods they own.",
        identity_doc: "Two observations are the same job when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "batch",
            kind: "Job",
        },
        fields: &JOB_FIELDS,
    },
    Target {
        name: "k8s-cronjob",
        schema: "io.github.godspeed-you.kubernetes.cronjob/1",
        schema_name: "KubernetesCronJob",
        schema_summary: "A CronJob: its schedule, whether it is suspended, and what it has \
                         running now.",
        summary: "CronJobs, and the Jobs they create.",
        identity_doc: "Two observations are the same CronJob when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "batch",
            kind: "CronJob",
        },
        fields: &CRONJOB_FIELDS,
    },
    Target {
        name: "k8s-configmap",
        schema: "io.github.godspeed-you.kubernetes.configmap/1",
        schema_name: "KubernetesConfigMap",
        schema_summary: "A ConfigMap's keys and whether it may still change.",
        summary: "ConfigMaps, and what consumes them.",
        identity_doc: "Two observations are the same ConfigMap when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "",
            kind: "ConfigMap",
        },
        fields: &CONFIGMAP_FIELDS,
    },
    Target {
        name: "k8s-secret",
        schema: "io.github.godspeed-you.kubernetes.secret/1",
        schema_name: "KubernetesSecret",
        schema_summary: "A secret's metadata — which keys exist, never what they hold (§22).",
        summary: "Secret metadata — which keys exist and what mounts them, never the values \
                  (specification section 22).",
        identity_doc: "Two observations are the same secret when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "",
            kind: "Secret",
        },
        fields: &SECRET_FIELDS,
    },
    Target {
        name: "k8s-serviceaccount",
        schema: "io.github.godspeed-you.kubernetes.serviceaccount/1",
        schema_name: "KubernetesServiceAccount",
        schema_summary: "A ServiceAccount, and the secrets it carries — never their contents.",
        summary: "ServiceAccounts, the identity a workload runs as.",
        identity_doc: "Two observations are the same account when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "",
            kind: "ServiceAccount",
        },
        fields: &SERVICEACCOUNT_FIELDS,
    },
    Target {
        name: "k8s-persistentvolumeclaim",
        schema: "io.github.godspeed-you.kubernetes.persistentvolumeclaim/1",
        schema_name: "KubernetesPersistentVolumeClaim",
        schema_summary: "A claim: what it asked for, and which volume — if any — it is bound to.",
        summary: "PersistentVolumeClaims, and the volumes they bind.",
        identity_doc: "Two observations are the same claim when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "",
            kind: "PersistentVolumeClaim",
        },
        fields: &PERSISTENTVOLUMECLAIM_FIELDS,
    },
    Target {
        name: "k8s-persistentvolume",
        schema: "io.github.godspeed-you.kubernetes.persistentvolume/1",
        schema_name: "KubernetesPersistentVolume",
        schema_summary: "A volume, what happens to the storage when it is released, and which \
                         claim holds it.",
        summary: "PersistentVolumes, and the storage behind them.",
        identity_doc: "Two observations are the same volume when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "",
            kind: "PersistentVolume",
        },
        fields: &PERSISTENTVOLUME_FIELDS,
    },
    Target {
        name: "k8s-storageclass",
        schema: "io.github.godspeed-you.kubernetes.storageclass/1",
        schema_name: "KubernetesStorageClass",
        schema_summary: "A storage class: what provisions it, when it binds, and what happens on \
                         release.",
        summary: "StorageClasses, and what they provision.",
        identity_doc: "Two observations are the same class when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "storage.k8s.io",
            kind: "StorageClass",
        },
        fields: &STORAGECLASS_FIELDS,
    },
    Target {
        name: "k8s-networkpolicy",
        schema: "io.github.godspeed-you.kubernetes.networkpolicy/1",
        schema_name: "KubernetesNetworkPolicy",
        schema_summary: "A network policy's intent, in the structure the API states it — never \
                         reduced to a verdict about reachability (§31.2, §31.3).",
        summary: "NetworkPolicies, and the Pods their selectors govern.",
        identity_doc: "Two observations are the same policy when their `metadata.uid` matches.",
        reads: Reads::Kind {
            group: "networking.k8s.io",
            kind: "NetworkPolicy",
        },
        fields: &NETWORKPOLICY_FIELDS,
    },
    Target {
        name: "k8s-resource",
        schema: "io.github.godspeed-you.kubernetes.resource/1",
        schema_name: "KubernetesResource",
        schema_summary: "Any resource the cluster serves, typed by the schema the cluster \
                         publishes for it.",
        summary: "Any resource this cluster serves, named by `kind` and `group` \
                  (specification section 15.1).",
        identity_doc: "Two observations are the same object when their `metadata.uid` matches, \
                       whatever kind they are.",
        reads: Reads::Discovered,
        fields: &RESOURCE_FIELDS,
    },
    Target {
        name: "k8s-relation",
        schema: "io.github.godspeed-you.kubernetes.relation/1",
        schema_name: "KubernetesRelation",
        schema_summary: "One relationship between two Kubernetes objects, and the evidence it \
                         rests on.",
        summary: "What one object is related to, with the evidence class and the fields that \
                  decided each edge (specification sections 23 to 32).",
        identity_doc: "Two observations are the same edge when the object they start at, the \
                       relationship word, the far end's address and the field that decided all \
                       match. An edge has no `metadata.uid` of its own.",
        reads: Reads::Relations,
        fields: RELATION_FIELDS,
    },
    Target {
        name: "k8s-change",
        schema: "io.github.godspeed-you.kubernetes.change/1",
        schema_name: "KubernetesChange",
        schema_summary: "One observed change in a watched collection, or one period that was \
                         not observed at all.",
        summary: "What changed in a collection while this provider was watching it, and every \
                  period it could not observe (specification section 19).",
        identity_doc: "Two observations are the same change when the collection, the observation \
                       period, the word, the object's UID and its resourceVersion all match. A \
                       change has no `metadata.uid` of its own; the UID on the record is the \
                       object's.",
        reads: Reads::Changes,
        fields: CHANGE_FIELDS,
    },
    Target {
        name: "k8s-event",
        schema: "io.github.godspeed-you.kubernetes.event/1",
        schema_name: "KubernetesEvent",
        schema_summary: "One Kubernetes Event: what a component reported, about what, and how \
                         many times the server recorded it.",
        summary: "The Events a cluster reported about an object — best-effort, briefly retained, \
                  and never a history (specification section 38).",
        identity_doc: "Two observations are the same Event when their `metadata.uid` matches. An \
                       Event is an object of its own; what it regards is a field of it. An \
                       aggregated Event is one Event however many occurrences it counts.",
        reads: Reads::Events,
        fields: &EVENT_FIELDS,
    },
    Target {
        name: "k8s-evidence",
        schema: "io.github.godspeed-you.kubernetes.evidence/1",
        schema_name: "KubernetesIdentityEvidence",
        schema_summary: "One value an object states about a system outside Kubernetes, with \
                         where it was read and how far it goes — never a link to that system.",
        summary: "What a Node, a Pod, a Service or an Ingress states about the machine, the \
                  container runtime or the load balancer behind it, as inspectable evidence for \
                  a resolver that has read the other system (specification section 47).",
        identity_doc: "Two observations are the same evidence when the object's `metadata.uid`, \
                       the published key and the field pointer all match. A Node rebuilt under \
                       the same name is a different machine, and a Pod restarted under the same \
                       name runs different containers.",
        reads: Reads::Evidence,
        fields: EVIDENCE_FIELDS,
    },
    Target {
        name: "k8s-log",
        schema: "io.github.godspeed-you.kubernetes.log/1",
        schema_name: "KubernetesLogLine",
        schema_summary: "One line of a container's log, with everything that kept the read short \
                         of what the container wrote.",
        summary: "A container's log, as lines that state their bounds — never the container's \
                  complete output (specification section 42.1).",
        identity_doc: "Two observations are the same line when the Pod's `metadata.uid`, the \
                       container, the run and the ordinal within the read all match. A line has \
                       no identity of its own; a process that printed one message twice printed \
                       it twice.",
        reads: Reads::Logs,
        fields: LOG_FIELDS,
    },
    Target {
        name: "k8s-timeline",
        schema: "io.github.godspeed-you.kubernetes.timeline/1",
        schema_name: "KubernetesObservation",
        schema_summary: "One thing known to have a time attached, the clock that wrote it, and \
                         the window this provider was observing in.",
        summary: "What is known to have happened to an object, with the clock behind every time \
                  and the periods nobody observed (specification section 39).",
        identity_doc: "Two observations are the same observation when the object, the source, \
                       the clock, the raw timestamp and what was observed all match. Two \
                       observations on two clocks are never in an order.",
        reads: Reads::Timeline,
        fields: TIMELINE_FIELDS,
    },
    Target {
        name: "k8s-why",
        schema: "io.github.godspeed-you.kubernetes.why/1",
        schema_name: "KubernetesFinding",
        schema_summary: "One thing this provider is prepared to say about the state an object is \
                         in, and the rung above which it will not climb.",
        summary: "What can be said about the state an object is in — correlation, order, a \
                  dependency path or something Kubernetes asserts, and never a cause \
                  (specification section 40).",
        identity_doc: "Two observations are the same finding when the object, the claim and what \
                       the claim rests on all match. A finding has no `metadata.uid` of its own.",
        reads: Reads::Why,
        fields: WHY_FIELDS,
    },
    Target {
        name: "k8s-condition",
        schema: "io.github.godspeed-you.kubernetes.condition/1",
        schema_name: "KubernetesCondition",
        schema_summary: "One condition a controller wrote about an object, kept structured \
                         rather than reduced to a status word.",
        summary: "The conditions an object's controllers wrote about it, each with the \
                  generation it was written about (specification section 37).",
        identity_doc: "Two observations are the same condition when the object's `metadata.uid` \
                       and the condition `type` match. A condition that flipped is the same \
                       condition.",
        reads: Reads::Conditions,
        fields: CONDITION_FIELDS,
    },
    Target {
        name: "k8s-cluster",
        schema: "io.github.godspeed-you.kubernetes.cluster/1",
        schema_name: "KubernetesCluster",
        schema_summary: "One provider instance: which cluster it reaches, whether it answers, \
                         and who it is to it.",
        summary: "Which cluster this is, whether it can be reached, and who you are to it.",
        identity_doc: "Two observations are the same provider instance when their `uid` — \
                       `kubernetes:<context>` — matches. Two instances that reach one cluster \
                       share a fingerprint and are never one instance (specification section \
                       10.3).",
        reads: Reads::Instance,
        fields: CLUSTER_FIELDS,
    },
    Target {
        name: "k8s-plan",
        schema: "io.github.godspeed-you.kubernetes.plan/1",
        schema_name: "KubernetesChangePlan",
        schema_summary: "A change described before it is made: its target, its preconditions, \
                         its effects and what could be verified afterwards.",
        summary: "What a change would do, before anything is changed (specification section 46).",
        identity_doc: "Two records describe the same prospective change when the object \
                       lifetime, the `resourceVersion` the plan is aimed at, the action and the \
                       fields it touches all match. A plan has no `metadata.uid` of its own; the \
                       uid on the record is the target object's.",
        reads: Reads::Plan,
        fields: &PLAN_FIELDS,
    },
];

/// The target of that name, where this package answers for one.
#[must_use]
pub fn target(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|target| target.name == name)
}

// --- what a change says about itself, and what an attempt at one came back with -------------------

/// The target every plan and every mutation record names, in the words every other schema here
/// uses (ADR-0013).
///
/// Not the object's metadata projection: a plan is not the object, and a reader who saw
/// `terminating` or `labels` on one would be reading facts that belong to a record of the object
/// itself. What is here is exactly what identifies the change's target and what guards it —
/// which is §16.1's identity plus §56's two preconditions.
const CHANGE_TARGET: &[Field] = &[
    Field::nullable("uid", "string"),
    Field::required("name", "string"),
    Field::nullable("namespace", "string"),
    Field::required("api_version", "string"),
    Field::required("kind", "string"),
    Field::nullable("resource_version", "string"),
    Field::required("action", "string"),
    Field::required("changes", "list<string>"),
    Field::required("preconditions", "map"),
];

/// A change described before it is made (§46.2), and the two things §46.2's list does not name.
///
/// **`prediction` is required and it is not decoration.** §21.4 of the generic provider contract
/// makes a provider label where a prediction came from — a provider-native dry run, static
/// provider metadata, Ono's own impact analysis or a heuristic — and a plan built from one read
/// and this package's rules is the second of those. A plan that did not say so would be
/// indistinguishable from a server dry run's answer, which is a much stronger claim.
///
/// **`reversibility` is the weakest of the effects and never a boolean.** §46.5 separates
/// reapplying a previous spec from getting back what the change consumed, so every entry of
/// `effects` carries its own answer and `recovery` states in two lists what reapplying would and
/// would not restore. A `reversible: bool` here is exactly the claim §46.5 forbids.
///
/// **`verification` is a plan field rather than a verification field.** "How would we know this
/// worked" is answered before the change (§46.3), and one of the answers is that this provider
/// has no rule — which is a visible value here rather than silent optimism.
///
/// **`competing_writers` carries its coverage and `contained` is nullable.** §54.1 asks for known
/// competing desired-state writers from five sources, and a list with no coverage beside it reads
/// as complete — an empty list from a group that would not answer is not an absence of
/// autoscalers (§21.4). `contained` is §55.2's inventory of what a Namespace holds, and it is
/// null rather than empty for every change that is not a Namespace deletion, because a count of
/// zero for a question nobody asked is the one number this schema must not be able to print.
const PLAN_FIELDS: [Field; 26] = with_target(&[
    Field::required("precondition_guarded", "bool"),
    Field::nullable("propagation", "string"),
    Field::required("effects", "list<map>"),
    Field::required("reversibility", "string"),
    Field::required("recovery", "map"),
    Field::required("dependents", "list<map>"),
    Field::required("dependent_coverage", "string"),
    Field::required("preflight", "string"),
    Field::required("verification", "string"),
    Field::nullable("verification_stage", "string"),
    Field::required("competing_writers", "list<map>"),
    Field::required("competing_writer_coverage", "string"),
    Field::nullable("contained", "list<map>"),
    Field::nullable("contained_coverage", "string"),
    Field::required("caveats", "list<string>"),
    Field::required("prediction", "string"),
    Field::required("statement", "string"),
]);

/// What one attempt at a change came back with — and, deliberately, no field that could carry
/// the sentence Gate G forbids.
///
/// **There is no `succeeded` and no `rolled_out`.** `acceptance` says what the API server did
/// with the request and `stage` says how far up §20.4's ladder that reaches, which for a write
/// is one rung and for a dry run is none at all (§44.5, §4 invariant 18). Everything above that
/// rung is `verdict`'s, and `verdict` has four values because §46.4 insists on the fourth: a
/// verification that did not become decisive is not a failure and not a success.
///
/// **`deletion_state` is a state and not a boolean.** §45.1 lists six distinctions a boolean
/// collapses, and Gate H turns on the one in the middle: an accepted delete with a finalizer on
/// the object is *terminating*. `finalizers` is beside it because §45.3 requires what deletion
/// is waiting for to be visible.
///
/// **`forced` never appears without `forced_because`.** §44.4 makes forcing a separate explicit
/// choice, so the record keeps the sentence somebody wrote rather than a flag somebody flipped.
const MUTATION_FIELDS: [Field; 34] = with_target(&[
    Field::required("acceptance", "string"),
    Field::required("dry_run", "bool"),
    Field::nullable("prediction", "string"),
    Field::required("code", "int"),
    Field::nullable("stage", "string"),
    Field::required("field_manager", "string"),
    Field::required("forced", "bool"),
    Field::nullable("forced_because", "string"),
    Field::nullable("conflict_fields", "list<string>"),
    Field::nullable("conflict_managers", "list<string>"),
    Field::nullable("resolution", "string"),
    Field::nullable("admission_differences", "list<string>"),
    Field::nullable("deletion_state", "string"),
    Field::nullable("finalizers", "list<string>"),
    Field::nullable("propagation", "string"),
    Field::required("verification", "string"),
    Field::nullable("verdict", "string"),
    Field::nullable("verification_detail", "string"),
    Field::nullable("reconciliation", "map"),
    Field::required("caveats", "list<string>"),
    Field::required("competing_writers", "list<map>"),
    Field::required("competing_writer_coverage", "string"),
    Field::nullable("contained", "list<map>"),
    Field::nullable("contained_coverage", "string"),
    Field::required("statement", "string"),
]);

/// Concatenates [`CHANGE_TARGET`] with a schema's own fields, at compile time.
///
/// The same shape as [`with_metadata`], and for the same reason: the field order a schema
/// declares is the order a record stores its fields in, so it is visible in the table rather
/// than assembled by a macro.
const fn with_target<const N: usize>(own: &'static [Field]) -> [Field; N] {
    let mut fields = [Field::required("", ""); N];
    let mut at = 0;
    while at < CHANGE_TARGET.len() {
        fields[at] = CHANGE_TARGET[at];
        at += 1;
    }
    let mut own_at = 0;
    while own_at < own.len() {
        fields[at] = own[own_at];
        at += 1;
        own_at += 1;
    }
    fields
}

/// One schema this package contributes that no target answers for.
///
/// Every other schema here belongs to a noun somebody can `get`. A mutation's answer belongs to
/// a *command*: it is what one attempt produced, and there is no collection of attempts to
/// enumerate. So the schema is declared on its own and the commands name it as their output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaDef {
    /// The schema id, as records of it carry it.
    pub id: &'static str,
    /// The schema's display name.
    pub name: &'static str,
    /// One line: what a record of this schema is.
    pub summary: &'static str,
    /// What makes two records of it the same thing.
    pub identity: &'static [&'static str],
    /// The fields, in declaration order.
    pub fields: &'static [Field],
}

impl SchemaDef {
    /// The schema as the handshake carries it.
    #[must_use]
    pub fn contribution(&self) -> SchemaContribution {
        SchemaContribution {
            id: self.id.to_owned(),
            name: self.name.to_owned(),
            summary: self.summary.to_owned(),
            identity: self
                .identity
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
            fields: self
                .fields
                .iter()
                .map(|field| SchemaFieldContribution {
                    name: field.name.to_owned(),
                    field_type: field.field_type.to_owned(),
                    required: field.required,
                    nullable: !field.required,
                })
                .collect(),
        }
    }
}

/// The schemas that belong to a command rather than to a target.
pub static COMMAND_SCHEMAS: &[SchemaDef] = &[SchemaDef {
    id: "io.github.godspeed-you.kubernetes.mutation/1",
    name: "KubernetesMutation",
    summary: "What one attempt at a change asked for, what the API server did with it, and the \
              one rung of the ladder that establishes.",
    identity: PLAN_IDENTITY,
    fields: &MUTATION_FIELDS,
}];

/// What a contributed command changes, which decides which handler answers it.
///
/// Two members, because §43.3's candidate actions all reduce to two shapes: a bounded field
/// change and a deletion. A third member would be a third kind of write, and this package has
/// none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writes {
    /// A bounded set of field changes, applied with field ownership tracked (§43.3, §44.1).
    Fields,
    /// The object, with the propagation policy the invocation chose (§45.2).
    Object,
}

/// One command this package contributes: a word that changes a cluster.
///
/// A command rather than a target, and the difference is not cosmetic. A `TargetContribution`
/// carries a name, a schema, a summary and an identity note, and that is all it can carry — it
/// has nowhere to declare a risk and nowhere to declare a capability, because everything a
/// target answers is a read. A `CommandContribution` carries both, and the host checks the
/// capability at every invocation before this package's code is reached at all. That is why a
/// mutation is a command here: not because `get` would be inconvenient, but because `get` cannot
/// say what a write has to say about itself (§31.22, §31.75).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command {
    /// The kebab name after `<package.id>.command.`.
    pub name: &'static str,
    /// An existing verb from core's `docs/contracts/verbs.yaml` — never one invented here.
    pub verb: &'static str,
    /// The noun the verb acts on, which is a target this package already contributes.
    pub target: &'static str,
    /// One line, for `help` and completion.
    pub summary: &'static str,
    /// The schema of the records the command emits.
    pub schema: &'static str,
    /// The risk level, from `risk_levels` in core's `docs/contracts/capabilities.yaml` (§31.75).
    pub risk: &'static str,
    /// The KUANG/11 capabilities the command needs, checked by the host at each invocation.
    pub capabilities: &'static [&'static str],
    /// What the command changes.
    pub writes: Writes,
    /// The arguments that belong to this command alone, beyond the ones every write takes.
    pub extra: &'static [Parameter],
    /// Documented examples.
    pub examples: &'static [&'static str],
}

impl Command {
    /// The full contributed id, `<package.id>.command.<kebab-name>` (§31.5).
    #[must_use]
    pub fn id(&self) -> String {
        format!("{}.command.{}", crate::PACKAGE, self.name)
    }

    /// The command as the handshake carries it.
    #[must_use]
    pub fn contribution(&self) -> CommandContribution {
        CommandContribution {
            id: self.id(),
            verb: self.verb.to_owned(),
            target: self.target.to_owned(),
            summary: self.summary.to_owned(),
            // A mutation is aimed at one object this package resolves for itself (§21.3 of the
            // generic contract), so nothing flows into it.
            input: None,
            output: format!("stream<{}>", self.schema),
            capabilities: self
                .capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
            argument_mode: "words".to_owned(),
            // A change is aimed at one object this package resolves for itself, and every word
            // that says which object is named rather than positional — `--name`, `--kind`,
            // `--context`. There is nothing left for a bare word to bind to.
            selectors: Vec::new(),
            options: self.options().iter().map(Parameter::contribution).collect(),
            risk: Some(self.risk.to_owned()),
            examples: self
                .examples
                .iter()
                .map(|example| (*example).to_owned())
                .collect(),
        }
    }

    /// The arguments this command takes.
    ///
    /// Which cluster, which namespace, which resource, which object — the same words `get
    /// k8s-resource` reads, because it is the same object read by one verb and written by
    /// another — and then `dry_run`, which is the one that decides whether a cluster changes.
    ///
    /// **`dry_run` declares its default rather than relying on the handler's.** The handler still
    /// falls back to `true` when the argument is absent, and that fallback is not redundant: a
    /// package whose safe behaviour depends on the host having applied a default is a package
    /// with a latent write in it. What the declaration adds is that the safe value is now visible
    /// in `help`, offered by completion, and applied before this package's code runs (§44.5,
    /// `ADR-0587 (core)`).
    #[must_use]
    pub fn options(&self) -> Vec<Parameter> {
        let mut options: Vec<Parameter> = CLUSTER.to_vec();
        // A write is aimed at one object in one namespace. `all_namespaces` is deliberately not
        // here: §55.3 keeps bulk mutation out of this action surface, and an option that fanned a
        // change across every namespace the caller can see is exactly the shape it forbids.
        options.push(SCOPE[0]);
        options.extend_from_slice(RESOURCE);
        options.push(NAMED);
        options.push(Parameter::defaulting(
            "dry_run",
            "bool",
            "Ask the API server what it would do without doing it. Default true: the shortest \
             sentence a user can write predicts (specification section 44.5).",
            "true",
        ));
        options.extend_from_slice(self.extra);
        options
    }
}

/// What `set k8s-resource` names beyond the object (§44.1, §44.2, §44.4).
const APPLY_OPTIONS: &[Parameter] = &[
    // --- section 43.3's curated transitions, in the order that section lists them ---
    Parameter::new(
        "replicas",
        "int",
        "Scale: how many replicas the workload should ask for. The curated form of \
         `/spec/replicas` (specification section 43.3).",
    ),
    Parameter::repeatable(
        "image",
        "list<string>",
        "Set image: `<container>=<image>`, naming the container rather than its position in the \
         list. Write it more than once for more than one container (specification section 43.3).",
    ),
    Parameter::new(
        "restart_rollout",
        "bool",
        "Restart the rollout by marking the pod template as changed, which is what makes a \
         controller roll its pods. Nothing is deleted (specification section 43.3).",
    ),
    Parameter::new(
        "schedulable",
        "bool",
        "Cordon or uncordon a Node: `false` stops the scheduler placing new pods on it, `true` \
         lets it again. Pods already running are neither stopped nor moved (specification \
         section 43.3).",
    ),
    Parameter::repeatable(
        "label",
        "list<string>",
        "Label: `<key>=<value>`, or `<key>=` to remove the label. Write it more than once for \
         more than one (specification sections 43.3, 14.5).",
    ),
    Parameter::repeatable(
        "annotation",
        "list<string>",
        "Annotate: `<key>=<value>`, or `<key>=` to remove the annotation. Write it more than \
         once for more than one (specification sections 43.3, 14.5).",
    ),
    // --- section 43.4's escape hatch, and it says so ---
    Parameter::new(
        "set",
        "record",
        "LOW-LEVEL EXPERT PATH (specification section 43.4): a mapping from a raw JSON pointer \
         to the value the field should hold, e.g. `{\"/spec/replicas\": 2}`. It names fields \
         against a schema you are expected to know and no curated action vouches for what they \
         mean together. Prefer `--replicas`, `--image`, `--restart_rollout`, `--schedulable`, \
         `--label` or `--annotation`, which each carry their own effects and verification rule.",
    ),
    Parameter::repeatable(
        "unset",
        "list<string>",
        "LOW-LEVEL EXPERT PATH (specification section 43.4): a pointer whose field this apply \
         gives up rather than sets. Write it more than once for more than one (specification \
         section 44.1).",
    ),
    Parameter::defaulting(
        "field_manager",
        "string",
        "The name field ownership is recorded under (specification section 44.2).",
        "ono-sendai",
    ),
    Parameter::new(
        "force_because",
        "string",
        "The reason ownership is taken from a conflicting manager. There is deliberately no \
         `force` flag: forcing is a sentence somebody wrote (specification section 44.4).",
    ),
];

/// What `remove k8s-resource` names beyond the object (§45.2).
const DELETE_OPTIONS: &[Parameter] = &[Parameter::defaulting(
    "propagation",
    "string",
    "`Foreground` keeps the object until its dependents are gone, `Background` removes it now \
     and collects them afterwards, `Orphan` leaves them behind owned by nothing.",
    "Background",
)];

/// The two words that change a cluster, and nothing else.
///
/// **The verbs are core's.** §31.22 asks a package to reuse an existing verb wherever the
/// semantics allow, and both do: `set` is "modify properties or configuration" and `remove` is
/// "delete a resource or a membership", which is exactly §43.3's bounded field change and
/// exactly its deletion. Neither needed a verb of its own, and a `k8s-apply` would have been a
/// Kubernetes mini-shell growing its first word (§4 invariant 22, §35.1).
///
/// **The noun is the one `get k8s-resource` already reads.** One word for a kind, read by one
/// verb and written by another, is the whole point of a verb-noun shell: nothing here is
/// reachable that `get` could not already show.
///
/// **`network.connect` is the capability, and it is the only honest one available.** Everything
/// these commands do to a cluster travels as bytes through the host's network broker, and the
/// broker's scope — the host and the port of the API server — is the operator's decision about
/// which cluster this package may reach at all (§27.2 of the generic contract, §51.2). The
/// capability model has no family for "change state in the external system a provider fronts":
/// `service.mutate` is scoped to service-manager units and `remote.mutate` to Ono links, and
/// claiming either would put a scope on an operator's grant that nothing checks — which §31.16
/// forbids in as many words. See ADR-0024.
pub static COMMANDS: &[Command] = &[
    Command {
        name: "set-k8s-resource",
        verb: "set",
        target: "k8s-resource",
        summary: "Change one Kubernetes object through a curated action — `--replicas` to \
                  scale, `--image` to set an image, `--restart_rollout`, `--schedulable` to \
                  cordon or uncordon a Node, `--label`, `--annotation` — or through the \
                  low-level `--set`/`--unset` JSON-pointer escape hatch. A server dry run unless \
                  `dry_run false` is given (specification sections 43.3, 43.4, 44).",
        schema: "io.github.godspeed-you.kubernetes.mutation/1",
        risk: "mutate",
        capabilities: &["network.connect"],
        writes: Writes::Fields,
        extra: APPLY_OPTIONS,
        examples: &[
            "set k8s-resource --context prod --kind Deployment --name api --replicas 2",
            "set k8s-resource --context prod --kind Deployment --name api --replicas 2 \
             --dry_run false",
            "set k8s-resource --context prod --kind Deployment --name api --image \
             web=registry.example/web:1.4.0",
            "set k8s-resource --context prod --kind Deployment --name api --restart_rollout true",
            "set k8s-resource --context prod --kind Node --name node-7 --schedulable false",
            "set k8s-resource --context prod --kind Deployment --name api --label tier=edge",
            "set k8s-resource --context prod --kind Deployment --name api --set \
             '{\"/spec/minReadySeconds\": 10}'",
        ],
    },
    Command {
        name: "remove-k8s-resource",
        verb: "remove",
        target: "k8s-resource",
        summary: "Delete one Kubernetes object, as a server dry run unless `dry_run false` is \
                  given (specification section 45).",
        schema: "io.github.godspeed-you.kubernetes.mutation/1",
        // `destructive` rather than `mutate`: §45.1 and §45.5 are a list of the ways a deletion
        // reaches things this provider cannot get back, and `risk_levels` in core's
        // `capabilities.yaml` defines `destructive` as exactly "may cause irreversible loss".
        risk: "destructive",
        capabilities: &["network.connect"],
        writes: Writes::Object,
        extra: DELETE_OPTIONS,
        examples: &[
            "remove k8s-resource --context prod --kind ConfigMap --name stale",
            "remove k8s-resource --context prod --kind ConfigMap --name stale --dry_run false",
        ],
    },
];

/// The command of that kebab name, where this package contributes one.
#[must_use]
pub fn command(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|command| command.name == name)
}
