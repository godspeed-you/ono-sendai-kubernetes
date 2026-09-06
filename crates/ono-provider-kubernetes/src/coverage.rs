//! What a query observed, and what it did not.
//!
//! Specification §18, §21 and §4 invariant 13. This is where the project's truth-first claim is
//! either kept or quietly lost, because eight different situations end with no objects coming
//! back and only one of them means "there are none".
//!
//! ```text
//! absent            the object is not there
//! type not served   the cluster has no such API
//! namespace absent  the namespace is not there
//! read denied       RBAC refused a get
//! list denied       RBAC refused a list
//! disconnected      the provider could not reach the server
//! request failed    the request errored
//! not queried       nobody asked
//! ```
//!
//! Collapsing those into an empty collection is how a permission boundary gets read as "there is
//! nothing there" — wrong in the direction that costs an operator the most, because it looks like
//! information rather than like a failure.
//!
//! §34.2 adds a ninth beside §21.4's eight, and a scope dimension to record it against:
//!
//! ```text
//! unavailable       an API group's own server did not answer
//! ```
//!
//! An aggregated API group is served by a second API server behind the aggregation layer, and
//! that server can be down while the core one answers perfectly. §34.2 requires exactly two
//! things of that case — that it must not make the whole provider unavailable, and that "coverage
//! SHOULD report the failed group/version separately" — so the group-version is a [`Scope`] of its
//! own (§9.3) and the word is its own outcome rather than a generic `request failed` (§34.3).

use std::fmt;

/// Why a scope produced no objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    /// The object or objects are genuinely not there.
    Absent,
    /// The cluster serves no such API (§11.5).
    TypeNotServed,
    /// The namespace does not exist.
    NamespaceAbsent,
    /// Authorization refused a read (§21.4).
    ReadDenied,
    /// Authorization refused an enumeration (§21.4).
    ListDenied,
    /// The provider could not reach the API server.
    Disconnected,
    /// The request reached the server and failed.
    RequestFailed,
    /// An API group's own server did not answer while the core API server did (§34.2, §48.6).
    ///
    /// Distinct from [`Self::Disconnected`], which is the whole provider losing the cluster, and
    /// from [`Self::RequestFailed`], which is one request erroring against a server that is
    /// there. This is one group-version's worth of the API surface going dark — the aggregation
    /// layer's characteristic failure, and the one §34.2 forbids escalating to the provider.
    Unavailable,
    /// Nobody asked. Never to be read as absence (§21.5).
    NotQueried,
}

impl Outcome {
    /// The word this outcome is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::TypeNotServed => "not served",
            Self::NamespaceAbsent => "namespace absent",
            Self::ReadDenied => "read denied",
            Self::ListDenied => "list denied",
            Self::Disconnected => "disconnected",
            Self::RequestFailed => "request failed",
            Self::Unavailable => "unavailable",
            Self::NotQueried => "not queried",
        }
    }

    /// Whether this outcome means the absence is a fact about the cluster rather than about the
    /// query.
    ///
    /// Only [`Self::Absent`] does. Everything else is a statement about what could not be seen.
    #[must_use]
    pub fn is_evidence_of_absence(self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// What a query was asked about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scope {
    namespace: Option<String>,
    all_namespaces: bool,
    group_version: Option<String>,
}

impl Scope {
    /// One namespace.
    #[must_use]
    pub fn in_namespace(name: impl Into<String>) -> Self {
        Self {
            namespace: Some(name.into()),
            all_namespaces: false,
            group_version: None,
        }
    }

    /// Every namespace the caller can see.
    #[must_use]
    pub fn all_namespaces() -> Self {
        Self {
            namespace: None,
            all_namespaces: true,
            group_version: None,
        }
    }

    /// Cluster scope, for resources that have no namespace (§9.2).
    #[must_use]
    pub fn cluster() -> Self {
        Self {
            namespace: None,
            all_namespaces: false,
            group_version: None,
        }
    }

    /// One API group-version, as `group/version` or the bare version of the core group (§9.3).
    ///
    /// The dimension §34.2's second sentence asks a gap to be recorded against: a group-version
    /// that did not answer is a hole in the *type space* a query searched, which is a different
    /// claim from a namespace nobody could list. Spelled as discovery spells it, so that the row
    /// an operator reads names the `APIService` they have to go and look at.
    #[must_use]
    pub fn in_group_version(group_version: impl Into<String>) -> Self {
        Self {
            namespace: None,
            all_namespaces: false,
            group_version: Some(group_version.into()),
        }
    }

    /// The namespace this scope names, if any.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The API group-version this scope names, if any.
    #[must_use]
    pub fn group_version(&self) -> Option<&str> {
        self.group_version.as_deref()
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.namespace, &self.group_version, self.all_namespaces) {
            (Some(name), _, _) => write!(f, "namespace/{name}"),
            (None, Some(group_version), _) => f.write_str(group_version),
            (None, None, true) => f.write_str("all-namespaces"),
            (None, None, false) => f.write_str("cluster"),
        }
    }
}

/// One scope that did not answer, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    scope: Scope,
    outcome: Outcome,
}

impl Gap {
    /// Records a scope that did not answer.
    #[must_use]
    pub fn new(scope: Scope, outcome: Outcome) -> Self {
        Self { scope, outcome }
    }

    /// What was asked about.
    #[must_use]
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Why it did not answer.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// One line naming the scope and what happened.
    ///
    /// A gap nobody can read is a gap nobody acts on: "incomplete" alone does not tell an
    /// operator whether to ask for access, install a CRD or retry.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}: {}", self.scope, self.outcome.as_str())
    }
}

/// What one query observed, and what it could not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    requested: Scope,
    observed: Vec<Scope>,
    gaps: Vec<Gap>,
    more: bool,
}

impl Coverage {
    /// A query that observed everything it asked about.
    #[must_use]
    pub fn complete(requested: Scope) -> Self {
        Self {
            requested,
            observed: Vec::new(),
            gaps: Vec::new(),
            more: false,
        }
    }

    /// What the query asked about.
    #[must_use]
    pub fn requested(&self) -> &Scope {
        &self.requested
    }

    /// Notes a scope that answered.
    pub fn observed(&mut self, scope: Scope) {
        if !self.observed.contains(&scope) {
            self.observed.push(scope);
        }
    }

    /// Notes a scope that did not.
    pub fn record(&mut self, gap: Gap) {
        self.gaps.push(gap);
    }

    /// Notes that the source holds more than was consumed (§18.4).
    ///
    /// Not a gap: stopping early is the pipeline's decision, and a decision is not a hole.
    pub fn more_available(&mut self) {
        self.more = true;
    }

    /// The scopes that answered.
    #[must_use]
    pub fn observed_scopes(&self) -> &[Scope] {
        &self.observed
    }

    /// The scopes that did not.
    #[must_use]
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    /// Whether everything asked about was observed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Whether more values exist upstream than were consumed.
    #[must_use]
    pub fn may_have_more(&self) -> bool {
        self.more
    }

    /// Whether a result of `count` objects is empty *and* known to be missing something.
    ///
    /// Gate E in one question. A renderer that shows an empty table must be able to ask it, so
    /// that "nothing here" and "nothing I was allowed to see" do not print the same.
    #[must_use]
    pub fn is_empty_but_incomplete(&self, count: usize) -> bool {
        count == 0 && !self.is_complete()
    }

    /// Every gap, in words.
    #[must_use]
    pub fn describe(&self) -> String {
        self.gaps
            .iter()
            .map(Gap::describe)
            .collect::<Vec<_>>()
            .join("; ")
    }
}
