use std::{collections::VecDeque, fmt::Display, fs};
use anyhow::anyhow;

/// A warning about how a term has been ignored.
#[derive(Debug)]
pub enum TermWarning {
    InvalidChar { term: String, at: usize, ch: char },
    TooLong { term: String, at: usize },
    Duplicate { term: String, at: usize, orig: String, orig_at: usize },
    TooManyKs { example: String },
}

impl Display for TermWarning {
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
            Self::TooManyKs { example } => write!(
                f, "all your terms start with 'k'. Do you not know that \
                putting '{}' means searching for k{}, or do you just really \
                like the letter k?",
                example, example
            )
        }
    }
}

#[derive(Debug, Clone)]
enum TrieNodeOpt {
    Nil,
    Leaf,
    Branch(TrieNode),
}

/// Checks that a term is not too long and contains only valid chars.
fn validate_term(term: String, at: usize) -> Result<(), TermWarning> {
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

/// Filters a list of terms such that:
/// - No term is empty.
/// - No term is too long.
/// - No term contains invalid chars.
/// - No term is a prefix of another term.
///
/// Returns a list of [TermWarning]s for the terms that has been filtered out.
fn validate_terms(terms: Vec<String>) -> (Vec<String>, Vec<TermWarning>) {
    let mut warnings = Vec::new();
    if terms.iter().all(|t| t.starts_with("k")) && terms.len() >= 5 {
        warnings.push(TermWarning::TooManyKs { example: terms[0].clone() })
    }

    let mut at_terms = terms.iter().enumerate().collect::<Vec<_>>();
    at_terms.sort_unstable_by_key(|a| a.1);

    let mut prev_valid = "\0";
    let mut prev_valid_i = 0;
    let mut valid_terms = Vec::with_capacity(at_terms.len());
    for (at, term) in at_terms.into_iter() {
        if term.is_empty() { continue }
        if let Err(w) = validate_term(term.clone(), at) {
            warnings.push(w);
            continue;
        }

        if term.starts_with(prev_valid) {
            warnings.push(TermWarning::Duplicate {
                term: term.clone(),
                at,
                orig: prev_valid.to_string(),
                orig_at: prev_valid_i,
            });
            continue;
        }

        valid_terms.push(term.clone());
        prev_valid = term;
        prev_valid_i = at;
    }

    (valid_terms, warnings)
}

/// A node of a 36-ary trie.
#[derive(Debug, Clone)]
pub struct TrieNode(Vec<TrieNodeOpt>);

impl TrieNode {
    fn new() -> Self {
        Self(vec![TrieNodeOpt::Nil; 36])
    }

    /// Inserts a child following branches down the given path.
    ///
    /// Panics on:
    /// - An empty path.
    /// - If the path is a prefix of an already existing path.
    fn insert(&mut self, path: &[usize]) {
        if path.is_empty() {
            unreachable!("validation failed to remove empty terms");
        }

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

            TrieNodeOpt::Leaf => {
                unreachable!("validation failed to deduplicate");
            }

            TrieNodeOpt::Branch(child_node) => {
                if path.len() == 1 {
                    unreachable!("validation failed to deduplicate");
                }
                child_node.insert(&path[1..]);
            },
        }
    }

    /// Given a list of terms, validates them and transforms them into a trie
    /// following the address -> path byte form on the cl kernel.
    ///
    /// Returns a list of [TermWarning]s for terms that failed validation.
    pub fn from_terms(terms: Vec<String>) -> (Self, Vec<TermWarning>) {
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

    /// Given a file path with terms as lines, validates and generates a trie.
    pub fn from_file(path: &str) -> anyhow::Result<(Self, Vec<TermWarning>)> {
        let terms = fs::read_to_string(path)
            .map_err(|e| anyhow!("Could not open {}: {}", path, e))?
            .lines()
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>();
        Ok(Self::from_terms(terms))
    }

    /// Encodes a trie into a u32 vector.
    ///
    /// Each node is represented by 36 integers, one for each branch:
    /// - `0` means the branch is empty.
    /// - `1` means the branch leads to a leaf.
    /// - `x > 1` means the branch leads to the `x - 1`th node after them.
    ///
    /// Encoding is performed breadth-first using a queue.
    pub fn encode(self) -> Vec<u32> {
        let mut result = vec![0; 36];
        let mut queue = VecDeque::new();
        queue.push_back((0, self));

        loop {
            let node = queue.pop_front();
            match node {
                Some((index, TrieNode(children))) => {
                    for (i, child_opt) in children.into_iter().enumerate() {
                        match child_opt {
                            TrieNodeOpt::Nil => {}
                            TrieNodeOpt::Leaf => {
                                result[index + i] = 1;
                            }
                            TrieNodeOpt::Branch(child_node) => {
                                let child_index = result.len();
                                let diff = (child_index - index) / 36;
                                result[index + i] = diff as u32 + 1;
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
