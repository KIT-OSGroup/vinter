//! Utility functions for working with sets.

use bitvec::vec::BitVec;

/// Generate a random bitvec of the given size.
fn random_bitvec(rng: &mut fastrand::Rng, size: usize) -> BitVec {
    let elems = size / (usize::BITS as usize);
    let mut v = Vec::with_capacity(elems);
    for _ in 0..=elems {
        v.push(rng.usize(..));
    }
    let mut v = BitVec::from_vec(v);
    v.resize(size, false);
    v
}

pub struct RandomSubsets<'a, T> {
    rng: &'a mut fastrand::Rng,
    vec: &'a [T],
}

impl<'a, T: Copy> Iterator for RandomSubsets<'a, T> {
    type Item = Vec<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let bitvec = random_bitvec(self.rng, self.vec.len());
        Some(bitvec.iter_ones().map(|idx| self.vec[idx]).collect())
    }
}

/// Generate random subsets of the vector.
pub fn random_subsets<'a, T>(rng: &'a mut fastrand::Rng, vec: &'a [T]) -> RandomSubsets<'a, T> {
    RandomSubsets { rng, vec }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_subsets() {
        let vec = vec![1, 2, 3, 4, 5];
        let mut rng = fastrand::Rng::with_seed(0);
        let mut subsets = random_subsets(&mut rng, &vec);
        assert_eq!(subsets.next().as_deref(), Some([2, 3, 4].as_slice()));
        assert_eq!(subsets.next().as_deref(), Some([1, 3, 4].as_slice()));
        assert_eq!(subsets.next().as_deref(), Some([3].as_slice()));
    }
}
