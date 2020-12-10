// SPDX-License-Identifier: Apache-2.0

//! Linked List Allocator
//!
//! copied from [phil-opp/blog_os]
//!
//! [phil-opp/blog_os]: <https://github.com/phil-opp/blog_os/blob/post-12/src/allocator/linked_list.rs>

use core::mem;

fn align_up(addr: usize, align: usize) -> usize {
    let offset = (addr as *const u8).align_offset(align);
    addr.checked_add(offset).unwrap()
}

struct ListNode {
    size: usize,
    next: Option<&'static mut ListNode>,
}

impl ListNode {
    fn new(size: usize) -> Self {
        ListNode { size, next: None }
    }

    fn start_addr(&self) -> usize {
        self as *const Self as usize
    }

    fn end_addr(&self) -> usize {
        self.start_addr().checked_add(self.size).unwrap()
    }
}

/// A LinkedListAllocator
pub struct LinkedListAllocator {
    head: ListNode,
    free_mem: usize,
}

impl Default for LinkedListAllocator {
    fn default() -> Self {
        Self {
            head: ListNode::new(0),
            free_mem: 0,
        }
    }
}

impl LinkedListAllocator {
    /// Initialize the allocator with the given heap bounds.
    ///
    /// # Safety
    ///
    /// This function is unsafe because the caller must guarantee that the given
    /// heap bounds are valid and that the heap is unused. This method must be
    /// called only once.
    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.add_free_region(heap_start, heap_size);
    }

    /// Adds the given memory region to the front of the list.
    ///
    /// # Safety
    /// The caller has to ensure `addr` points to a valid memory
    /// slice of size `size`.
    pub unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        // ensure that the freed region is capable of holding ListNode
        assert_eq!(align_up(addr, mem::align_of::<ListNode>()), addr);
        assert!(size >= mem::size_of::<ListNode>());
        assert_ne!(addr, 0);

        // create a new list node and append it at the start of the list
        let mut node = ListNode::new(size);
        node.next = self.head.next.take();

        let node_ptr = addr as *mut ListNode;
        node_ptr.write(node);
        self.head.next = Some(&mut *node_ptr);

        self.free_mem += size;
    }

    /// Looks for a free region with the given size and alignment and removes
    /// it from the list.
    ///
    /// Returns a tuple of the list node and the start address of the allocation.
    fn find_region(&mut self, size: usize, align: usize) -> Option<(&'static mut ListNode, usize)> {
        // reference to current list node, updated for each iteration
        let mut current = &mut self.head;
        // look for a large enough memory region in linked list
        while let Some(ref mut region) = current.next {
            if let Ok(alloc_start) = Self::alloc_from_region(&region, size, align) {
                // region suitable for allocation -> remove node from list
                let next = region.next.take();
                let ret = (current.next.take().unwrap(), alloc_start);
                current.next = next;
                self.free_mem -= ret.0.size;
                return Some(ret);
            } else {
                // region not suitable -> continue with next region
                current = current.next.as_mut().unwrap();
            }
        }

        // no suitable region found
        None
    }

    /// Get free memory size
    pub fn has_free_mem(&mut self, size: usize) -> bool {
        self.free_mem >= size
    }

    /// Get free memory size
    pub fn free_mem(&mut self) -> usize {
        self.free_mem
    }

    /// Try to use the given region for an allocation with given size and alignment.
    ///
    /// Returns the allocation start address on success.
    fn alloc_from_region(region: &ListNode, size: usize, align: usize) -> Result<usize, ()> {
        let alloc_start = align_up(region.start_addr(), align);
        let alloc_end = alloc_start.checked_add(size).ok_or(())?;

        if alloc_end > region.end_addr() {
            // region too small
            return Err(());
        }

        let excess_size = region.end_addr().checked_sub(alloc_end).unwrap();
        if excess_size > 0 && excess_size < mem::size_of::<ListNode>() {
            // rest of region too small to hold a ListNode (required because the
            // allocation splits the region in a used and a free part)
            return Err(());
        }

        // region suitable for allocation
        Ok(alloc_start)
    }

    /// Adjust the given layout so that the resulting allocated memory
    /// region is also capable of storing a `ListNode`.
    ///
    /// Returns the adjusted size and alignment as a (size, align) tuple.
    fn size_align(size: usize, align: usize) -> (usize, usize) {
        let size = size.max(mem::size_of::<ListNode>());
        let align = align.max(mem::align_of::<ListNode>());
        (size, align)
    }

    /// Allocate memory
    pub fn alloc_bytes(&mut self, size: usize, align: usize) -> *mut u8 {
        // perform layout adjustments
        let (size, align) = LinkedListAllocator::size_align(size, align);
        if let Some((region, alloc_start)) = self.find_region(size, align) {
            let alloc_end = alloc_start.checked_add(size).expect("overflow");
            let excess_size = region.end_addr().checked_sub(alloc_end).unwrap();
            if excess_size > 0 {
                unsafe { self.add_free_region(alloc_end, excess_size) };
            }
            alloc_start as *mut u8
        } else {
            core::ptr::null_mut()
        }
    }

    /// Deallocate memory
    /// # Safety
    /// The caller has to ensure `ptr` points to a valid memory
    /// slice of size `size`.
    pub unsafe fn dealloc_bytes(&mut self, ptr: *mut u8, size: usize) {
        self.add_free_region(ptr as usize, size)
    }
}
