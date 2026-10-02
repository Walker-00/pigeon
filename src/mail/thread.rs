use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use crate::store::model::Envelope;

#[derive(Debug, Clone)]
pub struct ThreadNode {
    pub index: usize,
    pub depth: u16,
    pub children: Vec<ThreadNode>,
}

#[derive(Debug, Clone)]
pub struct Thread {
    pub id: String,
    pub root: usize,
    pub members: Vec<usize>,
    pub newest: DateTime<Utc>,
    pub oldest: DateTime<Utc>,
    pub unread: usize,
    pub flagged: bool,
    pub has_attachments: bool,
    pub participants: Vec<String>,
    pub subject: String,
    pub tree: Vec<(usize, u16)>,
}

/// Message threading modelled on Jamie Zawinski's algorithm: link on
/// References/In-Reply-To first, then fall back to normalised-subject grouping
/// for the many clients that drop those headers when replying.
pub fn build(envelopes: &[Envelope], subject_fallback: bool) -> Vec<Thread> {
    let mut by_id: HashMap<&str, usize> = HashMap::new();
    for (i, e) in envelopes.iter().enumerate() {
        if let Some(id) = &e.message_id {
            by_id.entry(id.as_str()).or_insert(i);
        }
    }

    let mut parent: Vec<Option<usize>> = vec![None; envelopes.len()];
    for (i, e) in envelopes.iter().enumerate() {
        let candidates = e
            .references
            .iter()
            .rev()
            .chain(e.in_reply_to.iter())
            .filter_map(|r| by_id.get(r.as_str()).copied())
            .filter(|&p| p != i);
        if let Some(p) = candidates.into_iter().next() {
            parent[i] = Some(p);
        }
    }

    break_cycles(&mut parent);

    let mut union = DisjointSet::new(envelopes.len());
    for (i, p) in parent.iter().enumerate() {
        if let Some(p) = p {
            union.union(i, *p);
        }
    }

    if subject_fallback {
        let mut by_subject: HashMap<String, usize> = HashMap::new();
        for (i, e) in envelopes.iter().enumerate() {
            let s = e.base_subject().to_lowercase();
            if s.is_empty() {
                continue;
            }
            match by_subject.get(&s) {
                Some(&first) => union.union(i, first),
                None => {
                    by_subject.insert(s, i);
                }
            }
        }
    }

    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..envelopes.len() {
        groups.entry(union.find(i)).or_default().push(i);
    }

    let mut threads: Vec<Thread> = groups
        .into_values()
        .map(|members| assemble(envelopes, &parent, members))
        .collect();

    threads.sort_by(|a, b| b.newest.cmp(&a.newest));
    threads
}

fn assemble(envelopes: &[Envelope], parent: &[Option<usize>], mut members: Vec<usize>) -> Thread {
    members.sort_by_key(|&i| envelopes[i].date);

    let set: HashSet<usize> = members.iter().copied().collect();
    let roots: Vec<usize> = members
        .iter()
        .copied()
        .filter(|&i| parent[i].is_none_or(|p| !set.contains(&p)))
        .collect();
    let root = roots.first().copied().unwrap_or(members[0]);

    let mut kids: HashMap<usize, Vec<usize>> = HashMap::new();
    for &i in &members {
        if let Some(p) = parent[i]
            && set.contains(&p)
        {
            kids.entry(p).or_default().push(i);
        }
    }
    for v in kids.values_mut() {
        v.sort_by_key(|&i| envelopes[i].date);
    }

    let mut tree = Vec::with_capacity(members.len());
    let mut stack: Vec<(usize, u16)> = roots.iter().rev().map(|&r| (r, 0u16)).collect();
    let mut seen = HashSet::new();
    while let Some((i, d)) = stack.pop() {
        if !seen.insert(i) {
            continue;
        }
        tree.push((i, d));
        if let Some(cs) = kids.get(&i) {
            for &c in cs.iter().rev() {
                stack.push((c, d.saturating_add(1)));
            }
        }
    }
    for &i in &members {
        if seen.insert(i) {
            tree.push((i, 0));
        }
    }

    let newest = members.iter().map(|&i| envelopes[i].date).max().unwrap_or_default();
    let oldest = members.iter().map(|&i| envelopes[i].date).min().unwrap_or_default();

    let mut participants = Vec::new();
    let mut seen_p = HashSet::new();
    for &i in &members {
        for a in &envelopes[i].from {
            let name = a.display().to_string();
            if seen_p.insert(name.clone()) {
                participants.push(name);
            }
        }
    }

    Thread {
        id: envelopes[root]
            .message_id
            .clone()
            .unwrap_or_else(|| format!("{}:{}", envelopes[root].folder, envelopes[root].uid)),
        root,
        unread: members.iter().filter(|&&i| envelopes[i].is_unread()).count(),
        flagged: members
            .iter()
            .any(|&i| envelopes[i].flags.contains(crate::store::model::Flags::FLAGGED)),
        has_attachments: members.iter().any(|&i| !envelopes[i].attachments.is_empty()),
        subject: envelopes[root].subject_or_placeholder().to_string(),
        participants,
        newest,
        oldest,
        members,
        tree,
    }
}

fn break_cycles(parent: &mut [Option<usize>]) {
    for start in 0..parent.len() {
        let mut slow = start;
        let mut fast = start;
        loop {
            let Some(f1) = parent[fast] else { break };
            let Some(f2) = parent[f1] else { break };
            fast = f2;
            slow = parent[slow].unwrap();
            if slow == fast {
                parent[start] = None;
                break;
            }
        }
    }
}

struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl DisjointSet {
    fn new(n: usize) -> Self {
        Self { parent: (0..n).collect(), rank: vec![0; n] }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb {
            return;
        }
        match self.rank[ra].cmp(&self.rank[rb]) {
            std::cmp::Ordering::Less => self.parent[ra] = rb,
            std::cmp::Ordering::Greater => self.parent[rb] = ra,
            std::cmp::Ordering::Equal => {
                self.parent[rb] = ra;
                self.rank[ra] += 1;
            }
        }
    }
}
