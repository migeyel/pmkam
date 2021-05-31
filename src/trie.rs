use std::{collections::VecDeque, fmt::Display};

#[derive(Debug)]
pub enum TermWarning<'a> {
    InvalidChar { term: &'a str, at: usize, ch: char },
    TooLong { term: &'a str, at: usize },
    Duplicate { term: &'a str, at: usize, orig: &'a str, orig_at: usize },
}

impl Display for TermWarning<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidChar { term, at, ch } => write!(
                f, "invalid char '{}' on term {} ({})",
                ch, at + 1, term,
            ),
            Self::TooLong { term, at } => write!(
                f, "term {} ({}) is too long",
                at + 1, term,
            ),
            Self::Duplicate {term, at, orig, orig_at} => write!(
                f, "term {} ({}) is already covered by term {} ({})",
                at + 1, term, orig_at + 1, orig,
            ),
        }
    }
}

#[derive(Debug, Clone)]
enum TrieNodeOpt {
    Nil,
    Leaf,
    Branch(TrieNode),
}

fn validate_term(term: &'_ str, at: usize) -> Result<(), TermWarning<'_>> {
    if term.len() > 9 {
        return Err(TermWarning::TooLong { term, at });
    }

    for ch in term.chars() {
        match ch {
            '0'..='9' => {}
            'a'..='z' => {}
            _ => {
                return Err(TermWarning::InvalidChar { term, at, ch });
            }
        }
    }

    Ok(())
}

fn validate_terms<'a>(
    terms: &[&'a str],
) -> (Vec<&'a str>, Vec<TermWarning<'a>>) {
    let mut terms = terms.iter().enumerate().collect::<Vec<_>>();
    terms.sort_unstable_by_key(|a| a.1.len());

    let mut prev_valid = "\0";
    let mut prev_valid_i = 0;
    let mut warnings = Vec::new();
    let mut valid_terms = Vec::with_capacity(terms.len());
    for (at, term) in terms.into_iter() {
        if term.is_empty() { continue }
        if let Err(w) = validate_term(term, at) {
            warnings.push(w);
            continue;
        }
        if term.starts_with(prev_valid) {
            warnings.push(TermWarning::Duplicate {
                term,
                at,
                orig: prev_valid,
                orig_at: prev_valid_i,
            });
            continue;
        }

        valid_terms.push(*term);
        prev_valid = term;
        prev_valid_i = at;
    }

    (valid_terms, warnings)
}

#[derive(Debug, Clone)]
pub struct TrieNode(Vec<TrieNodeOpt>);

impl TrieNode {
    fn new() -> Self {
        Self(vec![TrieNodeOpt::Nil; 36])
    }

    fn insert(&mut self, path: &[usize]) {
        assert_ne!(path.len(), 0, "validation failed to remove empty terms");
        let child_opt = &mut self.0[path[0]];
        match child_opt {
            TrieNodeOpt::Nil => {
                if path.len() == 1 {
                    *child_opt = TrieNodeOpt::Leaf;
                } else {
                    let mut child_node = Self::new();
                    child_node.insert(&path[1..]);
                    *child_opt = TrieNodeOpt::Branch(child_node);
                }
            },
            TrieNodeOpt::Leaf => panic!("validation failed to deduplicate"),
            TrieNodeOpt::Branch(child_node) => {
                assert_ne!(path.len(), 1, "validation failed to deduplicate");
                child_node.insert(&path[1..]);
            },
        }
    }

    pub fn from_terms<'a>(terms: &[&'a str]) -> (Self, Vec<TermWarning<'a>>) {
        let mut trie = Self::new();
        let (valid_terms, warnings) = validate_terms(terms);
        for term in valid_terms {
            let mut path = Vec::with_capacity(term.len());
            for ch in term.chars() {
                path.push(match ch {
                    '0'..='9' => ch as usize - '0' as usize,
                    'a'..='z' => ch as usize - 'a' as usize + 10,
                    _ => unreachable!(),
                })
            }
            trie.insert(&path);
        }

        (trie, warnings)
    }

    pub fn encode(self) -> Vec<u32> {
        let mut result = vec![0; 36];
        let mut queue = VecDeque::new();
        queue.push_back((0, self));

        loop {
            let node = queue.pop_front();
            match node {
                Some((index, Self(children))) => {
                    for (i, child_opt) in children.into_iter().enumerate() {
                        match child_opt {
                            TrieNodeOpt::Nil => {}
                            TrieNodeOpt::Leaf => {
                                result[index + i] = 1;
                            }
                            TrieNodeOpt::Branch(child_node) => {
                                let child_index = result.len();
                                let idiff = child_index - index;
                                result[index + i] = idiff as u32 / 36 + 1;
                                result.extend_from_slice(&[0; 36]);
                                queue.push_back((child_index, child_node));
                            }
                        }
                    }
                }
                None => break,
            }
        }

        result
    }
}
