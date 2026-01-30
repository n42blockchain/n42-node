//! VecTree - Merkle tree-based vector storage.
//!
//! This implementation provides efficient O(log n) updates to validator storage
//! with only affected path nodes being updated.

use std::{collections::HashMap, marker::PhantomData};
use std::collections::HashSet;

use tree_hash::Hash256;

use crate::merkle_db::{error::Error, utils::{tree_height, zero_tree_root}, Value};

use typenum::Unsigned;

use sha2::{Digest, Sha256};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Tree<T: Value> {
    Leaf(T),
    Node {
        left: Hash256,
        right: Hash256,
    },
    Zero(usize),
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct VecTree<T: Value, N: Unsigned> {
    root: Hash256,
    kv: HashMap<Hash256, Tree<T>>,
    vec_len: u64,
    height: usize, // The fixed height of the tree based on capacity N
    /// For collision types (where T::default() hashes to zero_tree_root(0)),
    /// stores the default value to return when reading uninitialized positions.
    /// None for non-collision types.
    default_for_collision: Option<T>,
    _phantom: PhantomData<N>,
}

impl<T: Value, N: Unsigned> VecTree<T, N> {
    pub fn try_new(vec_len: u64) -> Result<Self, Error> {
        if vec_len as usize > N::to_usize() {
            return Err(Error::VecLenTooLarge {
                vec_len,
                limit: N::to_u64(),
            });
        }

        let height = tree_height(N::to_usize());
        let root = zero_tree_root(height);

        let kv = HashMap::from([(root, Tree::Zero(height))]);

        // SSZ Collision Handling: Store default separately for collision types
        let default_val = T::default();
        let default_for_collision = if default_val.tree_hash_root() == zero_tree_root(0) {
            Some(default_val)
        } else {
            None
        };

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            default_for_collision,
            _phantom: PhantomData,
        })
    }

    /// Creates a new VecTree from an existing Vec, building the Merkle tree.
    pub fn from_vec(elements: Vec<T>) -> Result<Self, Error> {
        let vec_len = elements.len() as u64;

        // 1. Capacity Guard
        if vec_len > N::to_u64() {
            return Err(Error::VecLenTooLarge {
                vec_len,
                limit: N::to_u64(),
            });
        }

        let height = tree_height(N::to_usize());
        let mut kv = HashMap::new();

        // 2. Recursive Builder
        fn build_recursive<T: Value>(
            elements: &[T],
            height: usize,
            kv: &mut HashMap<Hash256, Tree<T>>,
        ) -> Hash256 {
            // CASE A: The current branch is empty (Padding/Sparse)
            if elements.is_empty() {
                let root = zero_tree_root(height);

                if height == 0 {
                    // Leaf level - store Zero node for empty positions
                    kv.insert(root, Tree::Zero(0));
                } else {
                    // Internal nodes that are empty are stored as Zero subtrees
                    kv.insert(root, Tree::Zero(height));
                }
                return root;
            }

            // CASE B: The branch has data and we've reached a Leaf
            if height == 0 {
                // Elements slice is non-empty (CASE A would have handled empty), extract the value
                let leaf_val = elements[0].clone();
                let root = leaf_val.tree_hash_root();
                kv.insert(root, Tree::Leaf(leaf_val));
                return root;
            }

            // CASE C: Internal Node with data (Split and Hash)
            let capacity_at_height = 1usize << (height - 1);
            let (left_slice, right_slice) = if elements.len() <= capacity_at_height {
                (elements, &[][..])
            } else {
                elements.split_at(capacity_at_height)
            };

            let left = build_recursive(left_slice, height - 1, kv);
            let right = build_recursive(right_slice, height - 1, kv);

            // Compute parent hash: SHA256(left || right)
            let mut hasher = Sha256::new();
            hasher.update(left.as_slice());
            hasher.update(right.as_slice());
            let root = Hash256::from_slice(&hasher.finalize());

            kv.insert(root, Tree::Node { left, right });
            root
        }

        let root = build_recursive(&elements, height, &mut kv);

        // SSZ Collision Handling: Store default separately for collision types
        let default_val = T::default();
        let default_for_collision = if default_val.tree_hash_root() == zero_tree_root(0) {
            Some(default_val)
        } else {
            None
        };

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            default_for_collision,
            _phantom: PhantomData,
        })
    }

    /// Convenience wrapper for `diff_restore` with an empty memory map.
    pub fn restore<F>(
        root: Hash256,
        vec_len: u64,
        db_get: F,
    ) -> Result<Self, Error>
    where
        F: Fn(&Hash256) -> Option<Tree<T>>,
    {
        let empty_map = HashMap::new();
        Self::diff_restore(root, vec_len, &empty_map, db_get)
    }

    /// Restores a `VecTree` from a backing Key-Value store, with an in-memory optimization.
    pub fn diff_restore<F>(
        root: Hash256,
        vec_len: u64,
        existing_kv: &HashMap<Hash256, Tree<T>>,
        db_get: F,
    ) -> Result<Self, Error>
    where
        F: Fn(&Hash256) -> Option<Tree<T>>,
    {
        if vec_len as usize > N::to_usize() {
            return Err(Error::VecLenTooLarge {
                vec_len,
                limit: N::to_u64(),
            });
        }

        let height = tree_height(N::to_usize());
        let mut kv = HashMap::new();
        let mut stack = vec![(root, height)];

        while let Some((current_hash, current_height)) = stack.pop() {
            // Optimization: If hash matches zero root, store Zero node directly
            if current_hash == zero_tree_root(current_height) {
                kv.insert(current_hash, Tree::Zero(current_height));
                continue;
            }

            if kv.contains_key(&current_hash) {
                continue;
            }

            // Try in-memory cache first, then fall back to database lookup
            let node_opt = existing_kv.get(&current_hash).cloned();

            let node = match node_opt {
                Some(n) => n,
                None => {
                    // Cache miss, fetch from database
                    match db_get(&current_hash) {
                        Some(n) => n,
                        None => {
                            // Node not in DB - check if it's an implicit zero node
                            if current_hash == zero_tree_root(current_height) {
                                Tree::Zero(current_height)
                            } else {
                                return Err(Error::InconsistentTreeMissingNode {
                                    height: current_height,
                                    hash: current_hash,
                                });
                            }
                        }
                    }
                }
            };

            match &node {
                Tree::Node { left, right } => {
                    if current_height == 0 {
                        return Err(Error::InconsistentTreeLeafAtNonZeroHeight {
                            height: 0,
                            hash: current_hash,
                        });
                    }
                    stack.push((*right, current_height - 1));
                    stack.push((*left, current_height - 1));
                }
                Tree::Leaf(_) => {
                    if current_height != 0 {
                        return Err(Error::InconsistentTreeLeafAtNonZeroHeight {
                            height: current_height,
                            hash: current_hash,
                        });
                    }
                }
                Tree::Zero(h) => {
                    if *h != current_height {
                         return Err(Error::InconsistentTreeZeroHeightMismatch {
                            expected: current_height,
                            found: *h,
                            hash: current_hash,
                        });
                    }
                }
            }
            kv.insert(current_hash, node);
        }

        // SSZ Collision Handling: Store default separately for collision types
        let default_val = T::default();
        let default_for_collision = if default_val.tree_hash_root() == zero_tree_root(0) {
            Some(default_val)
        } else {
            None
        };

        Ok(Self {
            root,
            kv,
            vec_len,
            height,
            default_for_collision,
            _phantom: PhantomData,
        })
    }


    pub fn save<F, E>(&self, mut db_put: F) -> Result<(), E>
    where
        F: FnMut(&Hash256, &Tree<T>) -> Result<(), E>,
    {
        for (hash, node) in &self.kv {
            if let Tree::Zero(h) = node {
                if *hash == zero_tree_root(*h) {
                    continue;
                }
            }
            db_put(hash, node)?;
        }
        Ok(())
    }

    /// Saves the `VecTree` nodes to a backing Key-Value store, with differential optimization.
    pub fn diff_save<F, C, E>(&self, mut db_put: F, mut db_contains: C) -> Result<(), E>
    where
        F: FnMut(&Hash256, &Tree<T>) -> Result<(), E>,
        C: FnMut(&Hash256) -> bool,
    {
        let mut visited = HashSet::new();
        let mut stack = vec![self.root];

        while let Some(hash) = stack.pop() {
            if !visited.insert(hash) {
                continue;
            }

            if db_contains(&hash) {
                continue;
            }

            if let Some(node) = self.kv.get(&hash) {
                if let Tree::Zero(h) = node {
                    if hash == zero_tree_root(*h) {
                        continue;
                    }
                }

                db_put(&hash, node)?;

                if let Tree::Node { left, right } = node {
                    stack.push(*right);
                    stack.push(*left);
                }
            }
        }
        Ok(())
    }

    pub fn root(&self) -> Hash256 {
        self.root
    }

    pub fn ssz_root(&self) -> Hash256 {
        let left_bytes: &[u8; 32] = self.root.as_ref();

        let mut chunk = [0u8; 32];
        chunk[..8].copy_from_slice(&self.vec_len.to_le_bytes());
        let right_bytes = chunk;

        let mut hasher = Sha256::new();
        hasher.update(left_bytes);
        hasher.update(&right_bytes);

        Hash256::from_slice(&hasher.finalize())
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len() {
            return None;
        }

        let height = self.height;
        let mut current_hash = self.root;

        for h in (0..height).rev() {
            let node = self.kv.get(&current_hash);
            match node {
                Some(Tree::Node { left, right }) => {
                    let bit = (index >> h) & 1;
                    current_hash = if bit == 0 { *left } else { *right };
                }
                Some(Tree::Zero(_)) | None => {
                    // Check if this is a valid "Zero" node (explicit or implicit)
                    let is_zero_node = match node {
                        Some(Tree::Zero(_)) => true,
                        None => current_hash == zero_tree_root(h + 1),
                        _ => false,
                    };

                    if is_zero_node {
                        // Collision Handling: Return default for collision types, None otherwise
                        return self.default_for_collision.as_ref();
                    }

                    // If it's None and NOT a zero root, the tree is corrupted.
                    panic!("Inconsistent tree: missing node for hash {:?} at height {}", current_hash, h + 1);
                }
                Some(Tree::Leaf(_)) => {
                    panic!("Inconsistent tree: found Leaf node at height {}", h + 1);
                }
            }
        }

        match self.kv.get(&current_hash) {
            Some(Tree::Leaf(value)) => Some(value),
            Some(Tree::Zero(0)) | None => {
                // Zero node or implicit zero at leaf level
                if current_hash == zero_tree_root(0) {
                    // Return collision default if it exists, None otherwise
                    return self.default_for_collision.as_ref();
                }
                if self.kv.get(&current_hash).is_none() {
                    panic!("Inconsistent tree: missing node for leaf hash {:?}", current_hash);
                }
                None
            }
            Some(Tree::Node { .. }) | Some(Tree::Zero(_)) => {
                panic!("Inconsistent tree: found non-Leaf node at height 0");
            }
        }
    }

    pub fn set(&mut self, index: usize, value: T) -> Result<(), Error> {
        if index >= self.len() {
            return Err(Error::OutOfBoundsUpdate {
                index: index as u64,
                len: self.vec_len,
            });
        }

        let _ = self.update_leaf(index, Some(value));
        Ok(())
    }

    pub fn push(&mut self, value: T) -> Result<(), Error>
    where T: Clone
    {
        let index = self.len();
        if index >= N::to_usize() {
            return Err(Error::VecLenTooLarge {
                vec_len: self.vec_len + 1, // The new length after push would exceed capacity
                limit: N::to_u64(),
            });
        }

        // Update the tree structure before incrementing length.
        let _ = self.update_leaf(index, Some(value));

        // Commit the length change after tree update succeeds
        self.vec_len += 1;
        Ok(())
    }

    /// Pushes multiple values at once, computing shared ancestor hashes only once.
    pub fn push_batch(&mut self, values: &[T]) -> Result<(), Error>
    where T: Clone
    {
        if values.is_empty() {
            return Ok(());
        }

        let start = self.len();
        let new_len = start + values.len();

        if new_len > N::to_usize() {
            return Err(Error::VecLenTooLarge {
                vec_len: new_len as u64,
                limit: N::to_u64(),
            });
        }

        // Insert leaves, collect hashes in order
        let mut hashes: Vec<Hash256> = values.iter().map(|v| {
            let h = v.tree_hash_root();
            self.kv.insert(h, Tree::Leaf(v.clone()));
            h
        }).collect();

        let mut level_start = start;

        // Build up level by level
        for level in 0..self.height {
            let parent_start = level_start >> 1;
            let parent_end = (level_start + hashes.len() - 1) >> 1;

            let mut parent_hashes = Vec::with_capacity(parent_end - parent_start + 1);

            for parent_idx in parent_start..=parent_end {
                let left_idx = parent_idx << 1;
                let right_idx = left_idx + 1;

                let left = self.batch_get_hash(&hashes, level_start, left_idx, level);
                let right = self.batch_get_hash(&hashes, level_start, right_idx, level);

                let mut hasher = Sha256::new();
                hasher.update(left.as_ref() as &[u8; 32]);
                hasher.update(right.as_ref() as &[u8; 32]);
                let parent = Hash256::from_slice(&hasher.finalize());

                if parent == zero_tree_root(level + 1) {
                    self.kv.insert(parent, Tree::Zero(level + 1));
                } else {
                    self.kv.insert(parent, Tree::Node { left, right });
                }
                parent_hashes.push(parent);
            }

            hashes = parent_hashes;
            level_start = parent_start;
        }

        self.root = hashes[0];
        self.vec_len = new_len as u64;
        Ok(())
    }

    fn batch_get_hash(&self, hashes: &[Hash256], level_start: usize, idx: usize, level: usize) -> Hash256 {
        if idx >= level_start && idx < level_start + hashes.len() {
            hashes[idx - level_start]
        } else {
            self.get_hash_at_level(idx, level)
        }
    }

    fn get_hash_at_level(&self, index: usize, level: usize) -> Hash256 {
        let mut hash = self.root;
        for h in (level + 1..=self.height).rev() {
            match self.kv.get(&hash) {
                Some(Tree::Node { left, right }) => {
                    hash = if (index >> (h - 1 - level)) & 1 == 0 { *left } else { *right };
                }
                _ => return zero_tree_root(level),
            }
        }
        hash
    }

    pub fn update_indices<F>(&mut self, indices: &HashSet<usize>, mut f: F) -> Result<(), Error>
    where
        F: FnMut(usize, &mut T),
        T: Clone + Default + PartialEq,
    {
        if indices.is_empty() {
            return Ok(());
        }

        // 1. Pre-validation for Atomicity
        for &idx in indices {
            if idx >= self.len() {
                return Err(Error::OutOfBoundsUpdate {
                    index: idx as u64,
                    len: self.vec_len,
                });
            }
        }

        let mut updated_hashes: HashMap<usize, Hash256> = HashMap::new();
        let default_val = T::default();

        // 2. Leaf Update Phase with Value Comparison
        for &idx in indices {
            let old_val = self.get(idx).cloned().unwrap_or_else(|| default_val.clone());
            let mut new_val = old_val.clone();

            f(idx, &mut new_val);

            // Optimization: If the value didn't change, avoid the expensive tree_hash_root()
            if old_val == new_val {
                continue;
            }

            // Only hash if a change occurred
            let new_hash = new_val.tree_hash_root();

            self.kv.insert(new_hash, Tree::Leaf(new_val));

            updated_hashes.insert(idx, new_hash);
        }

        // If no values actually changed, early exit
        if updated_hashes.is_empty() {
            return Ok(());
        }

        // 3. Bubble Up Phase
        for h in 0..self.height {
            let mut next_level_updates = HashMap::new();
            let target_zero_hash = zero_tree_root(h + 1);

            for (&idx, _) in &updated_hashes {
                let parent_idx = idx >> 1;
                if next_level_updates.contains_key(&parent_idx) {
                    continue;
                }

                let left_idx = parent_idx << 1;
                let right_idx = left_idx + 1;

                let left = updated_hashes.get(&left_idx).cloned()
                    .unwrap_or_else(|| self.get_hash_at_level(left_idx, h));

                let right = updated_hashes.get(&right_idx).cloned()
                    .unwrap_or_else(|| self.get_hash_at_level(right_idx, h));

                let mut hasher = Sha256::new();
                hasher.update(left.as_slice());
                hasher.update(right.as_slice());
                let parent_hash = Hash256::from_slice(&hasher.finalize());

                if parent_hash == target_zero_hash {
                    self.kv.insert(parent_hash, Tree::Zero(h + 1));
                } else {
                    self.kv.insert(parent_hash, Tree::Node { left, right });
                }

                next_level_updates.insert(parent_idx, parent_hash);
            }
            updated_hashes = next_level_updates;
        }

        if let Some(&new_root) = updated_hashes.get(&0) {
            self.root = new_root;
        }

        Ok(())
    }

    /// Removes and returns the last element from the `VecTree`.
    pub fn pop(&mut self) -> Option<T>
    where
        T: Default + Clone,
    {
        if self.is_empty() {
            return None;
        }

        self.vec_len -= 1;
        let index = self.len();

        let old_value_opt = self.update_leaf(index, None);

        Some(old_value_opt.unwrap_or_default())
    }

    /// Tries to pop a value from the end of the `VecTree`, distinguishing holes from values.
    pub fn try_pop(&mut self) -> Result<Option<T>, Error>
    where T: Clone
    {
        if self.is_empty() {
            return Ok(None);
        }

        self.vec_len -= 1;
        let index = self.len();

        let old_value_opt = self.update_leaf(index, None);

        match old_value_opt {
            Some(value) => Ok(Some(value)),
            None => Err(Error::PoppedEmptySlot { index: index as u64 }),
        }
    }

    /// Internal function to update a leaf and rebuild the tree path.
    fn update_leaf(&mut self, index: usize, new_value: Option<T>) -> Option<T>
    where T: Clone
    {
        let height = self.height;
        let mut siblings: Vec<Hash256> = Vec::with_capacity(height);
        let mut current_hash = self.root;

        for h in (1..=height).rev() {
            let (left_hash, right_hash) = match self.kv.get(&current_hash) {
                Some(Tree::Node { left, right }) => (*left, *right),
                Some(Tree::Zero(h_zero)) => {
                    if *h_zero != h { panic!("Inconsistent tree height"); }
                    (zero_tree_root(h - 1), zero_tree_root(h - 1))
                }
                Some(Tree::Leaf(_)) => panic!("Found Leaf at height {}", h),
                None => {
                    if current_hash != zero_tree_root(h) { panic!("Missing node"); }
                    (zero_tree_root(h - 1), zero_tree_root(h - 1))
                }
            };

            let bit = (index >> (h - 1)) & 1;
            if bit == 0 {
                siblings.push(right_hash);
                current_hash = left_hash;
            } else {
                siblings.push(left_hash);
                current_hash = right_hash;
            }
        }

        let old_value = match self.kv.get(&current_hash) {
            Some(Tree::Leaf(val)) => Some(val.clone()),
            Some(Tree::Zero(0)) | None => None,
            _ => panic!("Invalid leaf state"),
        };

        let mut new_node_hash;
        if let Some(ref value) = new_value {
            // Store the value as a leaf, hash computed from the value itself
            new_node_hash = value.tree_hash_root();
            self.kv.insert(new_node_hash, Tree::Leaf(value.clone()));
        } else {
            // Restore to empty state
            new_node_hash = zero_tree_root(0);

            // Collision handling: Preserve default value for collision types
            if let Some(ref default_val) = self.default_for_collision {
                self.kv.insert(new_node_hash, Tree::Leaf(default_val.clone()));
            } else {
                self.kv.insert(new_node_hash, Tree::Zero(0));
            }
        }

        for h in 0..height {
            let sibling_hash = siblings.pop().unwrap();
            let (left_hash, right_hash) = if (index >> h) & 1 == 0 {
                (new_node_hash, sibling_hash)
            } else {
                (sibling_hash, new_node_hash)
            };

            let mut hasher = Sha256::new();
            let left_bytes: &[u8; 32] = left_hash.as_ref();
            let right_bytes: &[u8; 32] = right_hash.as_ref();
            hasher.update(left_bytes);
            hasher.update(right_bytes);
            new_node_hash = Hash256::from_slice(&hasher.finalize());

            let current_height = h + 1;
            if new_node_hash == zero_tree_root(current_height) {
                self.kv.insert(new_node_hash, Tree::Zero(current_height));
            } else {
                self.kv.insert(new_node_hash, Tree::Node { left: left_hash, right: right_hash });
            }
        }

        self.root = new_node_hash;
        old_value
    }


    pub fn clear(&mut self) {
        self.vec_len = 0;
        self.root = zero_tree_root(self.height);
        self.kv.clear();
        // Add back the single root node representing the empty tree.
        self.kv.insert(self.root, Tree::Zero(self.height));
    }

    pub fn len(&self) -> usize {
        self.vec_len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> VecTreeIter<'_, T, N> {
        VecTreeIter { tree: self, index: 0 }
    }

    /// Removes all key-value pairs from the internal map that are not reachable from the current root.
    pub fn prune(&mut self) -> usize {
        let initial_size = self.kv.len();

        let mut reachable = HashSet::new();
        let mut stack = vec![self.root];

        // 1. Standard Reachability Traversal
        while let Some(current_hash) = stack.pop() {
            if !reachable.insert(current_hash) {
                continue;
            }
            if let Some(tree_node) = self.kv.get(&current_hash) {
                match tree_node {
                    Tree::Node { left, right } => {
                        stack.push(*left);
                        stack.push(*right);
                    }
                    _ => {} // Leaf and Zero are terminal
                }
            }
        }

        // 2. Retain only reachable nodes
        self.kv.retain(|hash, _| reachable.contains(hash));

        // 3. Return the count of removed items
        initial_size - self.kv.len()
    }
}

pub struct VecTreeIter<'a, T: Value, N: Unsigned> {
    tree: &'a VecTree<T, N>,
    index: usize,
}

// Note: For collision types, holes return defaults. For non-collision types, iteration stops at the first hole.
impl<'a, T: Value, N: Unsigned> Iterator for VecTreeIter<'a, T, N> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.tree.len() {
            return None;
        }

        let item = self.tree.get(self.index)?;
        self.index += 1;
        Some(item)
    }
}

impl<'a, T: Value, N: Unsigned> ExactSizeIterator for VecTreeIter<'a, T, N> {
    fn len(&self) -> usize {
        self.tree.len() - self.index
    }
}
