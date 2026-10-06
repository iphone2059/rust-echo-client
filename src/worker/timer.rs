//! Worker-private index minimum heap over deadlines.
//!
//! Only the owning thread touches it, so no synchronisation is needed. The heap keeps a
//! position map so a session's deadline can be updated or removed in place, and its
//! capacity is fixed for the whole run: it is never allowed to grow.

/// One scheduled deadline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimerNode {
    pub deadline: u64,
    pub connection_index: u32,
}

#[derive(Debug)]
pub struct TimerHeap {
    capacity: usize,
    size: usize,
    nodes: Vec<TimerNode>,
    /// Index of a session inside `nodes`, or -1 when the session has no deadline.
    positions: Vec<i32>,
}

impl TimerHeap {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            size: 0,
            nodes: vec![TimerNode::default(); capacity],
            positions: vec![-1; capacity],
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn contains(&self, connection_index: u32) -> bool {
        (connection_index as usize) < self.capacity
            && self.positions[connection_index as usize] >= 0
    }

    /// Deadline of the nearest entry, or None when the heap is empty.
    pub fn next_deadline(&self) -> Option<u64> {
        if self.size == 0 {
            None
        } else {
            Some(self.nodes[0].deadline)
        }
    }

    fn less(&self, a: usize, b: usize) -> bool {
        let left = self.nodes[a];
        let right = self.nodes[b];
        (left.deadline, left.connection_index) < (right.deadline, right.connection_index)
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.nodes.swap(a, b);
        let left = self.nodes[a].connection_index as usize;
        let right = self.nodes[b].connection_index as usize;
        self.positions[left] = a as i32;
        self.positions[right] = b as i32;
    }

    fn sift_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if !self.less(index, parent) {
                break;
            }
            self.swap(index, parent);
            index = parent;
        }
    }

    fn sift_down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            if left >= self.size {
                break;
            }
            let right = left + 1;
            let smallest = if right < self.size && self.less(right, left) {
                right
            } else {
                left
            };
            if !self.less(smallest, index) {
                break;
            }
            self.swap(index, smallest);
            index = smallest;
        }
    }

    /// Schedules or reschedules a session. Returns false when the session has no slot and
    /// the heap is already full: the caller must treat that as a hard failure instead of
    /// silently dropping a deadline.
    pub fn insert_or_update(&mut self, deadline: u64, connection_index: u32) -> bool {
        let slot = connection_index as usize;
        if slot >= self.capacity {
            return false;
        }
        let existing = self.positions[slot];
        if existing >= 0 {
            let position = existing as usize;
            let previous = self.nodes[position].deadline;
            self.nodes[position].deadline = deadline;
            if deadline < previous {
                self.sift_up(position);
            } else if deadline > previous {
                self.sift_down(position);
            }
            return true;
        }
        if self.size == self.capacity {
            return false;
        }
        let position = self.size;
        self.size += 1;
        self.nodes[position] = TimerNode {
            deadline,
            connection_index,
        };
        self.positions[slot] = position as i32;
        self.sift_up(position);
        true
    }

    /// Drops a session's deadline. Removing an unscheduled session is not an error.
    pub fn remove(&mut self, connection_index: u32) -> bool {
        let slot = connection_index as usize;
        if slot >= self.capacity {
            return false;
        }
        let position = self.positions[slot];
        if position < 0 {
            return false;
        }
        let position = position as usize;
        let last = self.size - 1;
        self.positions[slot] = -1;
        if position != last {
            self.nodes.swap(position, last);
            self.positions[self.nodes[position].connection_index as usize] = position as i32;
            let moved_deadline = self.nodes[position].deadline;
            self.size = last;
            // Repair in whichever direction the moved entry can violate the invariant.
            let parent = if position > 0 {
                Some((position - 1) / 2)
            } else {
                None
            };
            if let Some(parent) = parent {
                if self.less(position, parent) {
                    self.sift_up(position);
                    return true;
                }
            }
            let _ = moved_deadline;
            self.sift_down(position);
        } else {
            self.size = last;
        }
        true
    }

    /// Wakes up only the sessions whose deadline has passed. Each removed session is
    /// reported so the caller can drive its timeout path.
    pub fn pop_expired(&mut self, now: u64, out: &mut Vec<u32>) -> usize {
        let mut count = 0;
        while self.size > 0 && self.nodes[0].deadline <= now {
            let node = self.nodes[0];
            self.remove(node.connection_index);
            out.push(node.connection_index);
            count += 1;
        }
        count
    }

    /// Milliseconds to wait for the nearest deadline, clamped so a caller can pass its own
    /// idle bound (for example a run deadline or an infinite wait).
    pub fn timeout_milliseconds(&self, now: u64, maximum: u32) -> u32 {
        match self.next_deadline() {
            None => maximum,
            Some(deadline) if deadline <= now => 0,
            Some(deadline) => {
                let delta = deadline - now;
                let capped = delta.min(u64::from(maximum));
                capped as u32
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_by_deadline_then_index() {
        let mut heap = TimerHeap::new(8);
        assert!(heap.insert_or_update(30, 2));
        assert!(heap.insert_or_update(10, 1));
        assert!(heap.insert_or_update(20, 0));
        assert_eq!(heap.next_deadline(), Some(10));
        let mut expired = Vec::new();
        assert_eq!(heap.pop_expired(25, &mut expired), 2);
        assert_eq!(expired, vec![1, 0]);
        assert_eq!(heap.next_deadline(), Some(30));
        assert_eq!(heap.len(), 1);
    }

    #[test]
    fn update_moves_the_entry_in_both_directions() {
        let mut heap = TimerHeap::new(4);
        assert!(heap.insert_or_update(100, 0));
        assert!(heap.insert_or_update(200, 1));
        assert!(heap.insert_or_update(5, 0));
        assert_eq!(heap.next_deadline(), Some(5));
        assert_eq!(heap.len(), 2);
        assert!(heap.insert_or_update(500, 0));
        assert_eq!(heap.next_deadline(), Some(200));
        assert!(heap.contains(0));
    }

    #[test]
    fn remove_reports_missing_entries_and_repairs_the_heap() {
        let mut heap = TimerHeap::new(4);
        assert!(!heap.remove(0));
        assert!(heap.insert_or_update(10, 0));
        assert!(heap.insert_or_update(20, 1));
        assert!(heap.insert_or_update(30, 2));
        assert!(heap.remove(0));
        assert!(!heap.contains(0));
        assert_eq!(heap.next_deadline(), Some(20));
        assert_eq!(heap.len(), 2);
        assert!(heap.remove(2));
        assert_eq!(heap.next_deadline(), Some(20));
    }

    #[test]
    fn capacity_is_fixed_and_indices_are_bounds_checked() {
        let mut heap = TimerHeap::new(2);
        assert!(heap.insert_or_update(1, 0));
        assert!(heap.insert_or_update(2, 1));
        // Full: a third distinct session is refused instead of growing the heap.
        assert!(!heap.insert_or_update(3, 2));
        // Out-of-range indices are refused even when a slot is free.
        assert!(!heap.insert_or_update(3, 99));
        assert_eq!(heap.len(), 2);
    }

    #[test]
    fn timeout_is_clamped() {
        let mut heap = TimerHeap::new(2);
        assert_eq!(heap.timeout_milliseconds(1_000, 250), 250);
        assert!(heap.insert_or_update(1_500, 0));
        assert_eq!(heap.timeout_milliseconds(1_000, 250), 250);
        assert!(heap.insert_or_update(1_100, 0));
        assert_eq!(heap.timeout_milliseconds(1_000, 250), 100);
        assert_eq!(heap.timeout_milliseconds(2_000, 250), 0);
    }
}
