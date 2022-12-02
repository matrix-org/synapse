use std::{collections::HashMap, hash::Hash};

use anyhow::{bail, Error};

pub enum TreeCacheNode<K, V> {
    Leaf(V),
    Branch(usize, HashMap<K, TreeCacheNode<K, V>>),
}

impl<K, V> TreeCacheNode<K, V> {
    pub fn new_branch() -> Self {
        TreeCacheNode::Branch(0, Default::default())
    }

    fn len(&self) -> usize {
        match self {
            TreeCacheNode::Leaf(_) => 1,
            TreeCacheNode::Branch(size, _) => *size,
        }
    }
}

impl<'a, K: Eq + Hash + 'a, V> TreeCacheNode<K, V> {
    pub fn set(
        &mut self,
        mut key: impl Iterator<Item = K>,
        value: V,
    ) -> Result<(usize, usize), Error> {
        if let Some(k) = key.next() {
            match self {
                TreeCacheNode::Leaf(_) => bail!("Given key is too long"),
                TreeCacheNode::Branch(size, map) => {
                    let node = map.entry(k).or_insert_with(TreeCacheNode::new_branch);
                    let (added, removed) = node.set(key, value)?;

                    *size += added;
                    *size -= removed;

                    Ok((added, removed))
                }
            }
        } else {
            let added = if let TreeCacheNode::Branch(_, map) = self {
                (1, map.len())
            } else {
                (0, 0)
            };

            *self = TreeCacheNode::Leaf(value);

            Ok(added)
        }
    }

    pub fn pop(
        &mut self,
        current_key: &K,
        mut next_keys: impl Iterator<Item = &'a K>,
    ) -> Result<Option<TreeCacheNode<K, V>>, Error> {
        if let Some(next_key) = next_keys.next() {
            match self {
                TreeCacheNode::Leaf(_) => bail!("Given key is too long"),
                TreeCacheNode::Branch(size, map) => {
                    let node = if let Some(node) = map.get_mut(current_key) {
                        node
                    } else {
                        return Ok(None);
                    };

                    if let Some(popped) = node.pop(next_key, next_keys)? {
                        *size -= node.len();

                        Ok(Some(popped))
                    } else {
                        Ok(None)
                    }
                }
            }
        } else {
            match self {
                TreeCacheNode::Leaf(_) => bail!("Given key is too long"),
                TreeCacheNode::Branch(size, map) => {
                    if let Some(node) = map.remove(current_key) {
                        *size -= node.len();

                        Ok(Some(node))
                    } else {
                        Ok(None)
                    }
                }
            }
        }
    }

    pub fn items(&self) -> impl Iterator<Item = (Vec<&K>, &V)> {
        let mut stack = vec![(vec![], self)];

        std::iter::from_fn(move || {
            while let Some((prefix, node)) = stack.pop() {
                match node {
                    TreeCacheNode::Leaf(value) => return Some((prefix, value)),
                    TreeCacheNode::Branch(_, map) => {
                        stack.extend(map.iter().map(|(k, v)| {
                            let mut prefix = prefix.clone();
                            prefix.push(k);
                            (prefix, v)
                        }));
                    }
                }
            }

            None
        })
    }
}

pub struct TreeCache<K, V> {
    root: TreeCacheNode<K, V>,
}

impl<'a, K: Eq + Hash + 'a, V> TreeCache<K, V> {
    pub fn new() -> Self {
        TreeCache {
            root: TreeCacheNode::new_branch(),
        }
    }

    pub fn set(&mut self, key: impl IntoIterator<Item = K>, value: V) -> Result<(), Error> {
        self.root.set(key.into_iter(), value)?;

        Ok(())
    }

    pub fn get_node(
        &self,
        key: impl IntoIterator<Item = &'a K>,
    ) -> Result<Option<&TreeCacheNode<K, V>>, Error> {
        let mut node = &self.root;

        for k in key {
            match node {
                TreeCacheNode::Leaf(_) => bail!("Given key is too long"),
                TreeCacheNode::Branch(_, map) => {
                    node = if let Some(node) = map.get(k) {
                        node
                    } else {
                        return Ok(None);
                    };
                }
            }
        }

        Ok(Some(node))
    }

    pub fn get(&self, key: impl IntoIterator<Item = &'a K>) -> Result<Option<&V>, Error> {
        if let Some(node) = self.get_node(key)? {
            match node {
                TreeCacheNode::Leaf(value) => Ok(Some(value)),
                TreeCacheNode::Branch(_, _) => bail!("Given key is too short"),
            }
        } else {
            Ok(None)
        }
    }

    pub fn pop_node(
        &mut self,
        key: impl IntoIterator<Item = &'a K>,
    ) -> Result<Option<TreeCacheNode<K, V>>, Error> {
        let mut key_iter = key.into_iter();

        let k = if let Some(k) = key_iter.next() {
            k
        } else {
            let node = std::mem::replace(&mut self.root, TreeCacheNode::new_branch());
            return Ok(Some(node));
        };

        self.root.pop(k, key_iter)
    }

    pub fn pop(&mut self, key: &[K]) -> Result<Option<V>, Error> {
        if let Some(node) = self.pop_node(key)? {
            match node {
                TreeCacheNode::Leaf(value) => Ok(Some(value)),
                TreeCacheNode::Branch(_, _) => bail!("Given key is too short"),
            }
        } else {
            Ok(None)
        }
    }

    pub fn clear(&mut self) {
        self.root = TreeCacheNode::new_branch();
    }

    pub fn len(&self) -> usize {
        match self.root {
            TreeCacheNode::Leaf(_) => 1,
            TreeCacheNode::Branch(size, _) => size,
        }
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        let mut stack = vec![&self.root];

        std::iter::from_fn(move || {
            while let Some(node) = stack.pop() {
                match node {
                    TreeCacheNode::Leaf(value) => return Some(value),
                    TreeCacheNode::Branch(_, map) => {
                        stack.extend(map.values());
                    }
                }
            }

            None
        })
    }

    pub fn items(&self) -> impl Iterator<Item = (Vec<&K>, &V)> {
        self.root.items()
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn get_set() -> Result<(), Error> {
        let mut cache = TreeCache::new();

        cache.set(vec!["a", "b"], "c")?;

        assert_eq!(cache.get(&["a", "b"])?, Some(&"c"));

        let node = cache.get_node(&["a"])?.unwrap();

        match node {
            TreeCacheNode::Leaf(_) => bail!("expected branch"),
            TreeCacheNode::Branch(_, map) => {
                assert_eq!(map.len(), 1);
                assert!(map.contains_key("b"));
            }
        }

        Ok(())
    }

    #[test]
    fn length() -> Result<(), Error> {
        let mut cache = TreeCache::new();

        cache.set(vec!["a", "b"], "c")?;

        assert_eq!(cache.len(), 1);

        cache.set(vec!["a", "b"], "d")?;

        assert_eq!(cache.len(), 1);

        cache.set(vec!["e", "f"], "g")?;

        assert_eq!(cache.len(), 2);

        cache.set(vec!["e", "h"], "i")?;

        assert_eq!(cache.len(), 3);

        cache.set(vec!["e"], "i")?;

        assert_eq!(cache.len(), 2);

        cache.pop_node(&["a"])?;

        assert_eq!(cache.len(), 1);

        Ok(())
    }

    #[test]
    fn clear() -> Result<(), Error> {
        let mut cache = TreeCache::new();

        cache.set(vec!["a", "b"], "c")?;

        assert_eq!(cache.len(), 1);

        cache.clear();

        assert_eq!(cache.len(), 0);

        assert_eq!(cache.get(&["a", "b"])?, None);

        Ok(())
    }

    #[test]
    fn pop() -> Result<(), Error> {
        let mut cache = TreeCache::new();

        cache.set(vec!["a", "b"], "c")?;
        assert_eq!(cache.pop(&["a", "b"])?, Some("c"));
        assert_eq!(cache.pop(&["a", "b"])?, None);

        Ok(())
    }

    #[test]
    fn values() -> Result<(), Error> {
        let mut cache = TreeCache::new();

        cache.set(vec!["a", "b"], "c")?;

        let expected = ["c"].iter().collect();
        assert_eq!(cache.values().collect::<BTreeSet<_>>(), expected);

        cache.set(vec!["d", "e"], "f")?;

        let expected = ["c", "f"].iter().collect();
        assert_eq!(cache.values().collect::<BTreeSet<_>>(), expected);

        Ok(())
    }

    #[test]
    fn items() -> Result<(), Error> {
        let mut cache = TreeCache::new();

        cache.set(vec!["a", "b"], "c")?;
        cache.set(vec!["d", "e"], "f")?;

        let expected = [(vec![&"a", &"b"], &"c"), (vec![&"d", &"e"], &"f")]
            .into_iter()
            .collect();
        assert_eq!(cache.items().collect::<BTreeSet<_>>(), expected);

        Ok(())
    }
}
