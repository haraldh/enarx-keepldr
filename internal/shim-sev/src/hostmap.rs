// SPDX-License-Identifier: Apache-2.0

//! The global FrameAllocator
use crate::addr::{HostVirtAddr, ShimPhysUnencryptedAddr};

//use crate::linked_list_allocator::LinkedListAllocator;
use crate::spin::RWLocked;
use crate::SHIM_CAN_PRINT;
use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::sync::atomic::Ordering;
use linked_list_allocator::Heap;
use lset::Line;
use primordial::{Address, Page as Page4KiB};
use spinning::{Lazy, RwLockWriteGuard};

/// The global ShimFrameAllocator RwLock
pub static HOSTMAP: Lazy<RWLocked<HostMap>> =
    Lazy::new(|| RWLocked::<HostMap>::new(HostMap::new()));

struct HostMemListPageHeader {
    next: Option<&'static mut HostMemListPage>,
}

#[derive(Clone, Copy)]
struct HostMemEntry {
    start: usize,
    end: usize,
    virt_offset: i64,
}

/// Number of memory list entries per page
pub const HOST_MEM_LIST_NUM_ENTRIES: usize = (Page4KiB::size()
    - core::mem::size_of::<HostMemListPageHeader>())
    / core::mem::size_of::<HostMemEntry>();

struct HostMemListPage {
    header: HostMemListPageHeader,
    ent: [HostMemEntry; HOST_MEM_LIST_NUM_ENTRIES],
}

/// A frame allocator
pub struct HostMap {
    host_mem: HostMemListPage,
}

impl HostMap {
    #[allow(clippy::integer_arithmetic)]
    fn new() -> Self {
        HostMap {
            host_mem: HostMemListPage {
                header: HostMemListPageHeader { next: None },
                ent: [HostMemEntry {
                    start: 0,
                    end: 0,
                    virt_offset: 0,
                }; HOST_MEM_LIST_NUM_ENTRIES],
            },
        }
    }

    fn get_virt_offset(&self, addr: usize) -> Option<i64> {
        let mut free = &self.host_mem;
        loop {
            for i in free.ent.iter() {
                if i.start == 0 {
                    panic!(
                        "Trying to get virtual offset from unmmapped location {:#x}",
                        addr
                    );
                }
                if i.end > addr {
                    return Some(i.virt_offset);
                }
            }
            match free.header.next {
                None => return None,
                Some(ref f) => free = *f,
            }
        }
    }
}

impl RWLocked<HostMap> {
    /// Extend the slots
    pub fn extend_slots(&self, mem_slots: usize, allocator: &mut Heap) {
        fn inner_extend_slots(
            mut this: RwLockWriteGuard<HostMap>,
            mem_slots: usize,
            allocator: &mut Heap,
        ) {
            // Allocate enough pages to hold all memory slots in advance
            let num_pages = mem_slots.checked_div(HOST_MEM_LIST_NUM_ENTRIES).unwrap();

            if this.host_mem.header.next.is_some() {
                return;
            }

            // There is already one HostMemListPage present, so we can ignore the rest of the division.
            let mut last_page = &mut this.host_mem as *mut HostMemListPage;

            for _i in 0..num_pages {
                unsafe {
                    last_page = match (*last_page).header.next {
                        None => {
                            let new_page = {
                                let page_res = allocator.allocate_first_fit(
                                    Layout::from_size_align(
                                        size_of::<HostMemListPage>(),
                                        align_of::<HostMemListPage>(),
                                    )
                                    .unwrap(),
                                );

                                if page_res.is_err() {
                                    return;
                                }

                                let page: *mut HostMemListPage = page_res.unwrap().as_ptr() as _;

                                page.write_bytes(0, 1);
                                page
                            };

                            (*last_page).header.next = Some(&mut *new_page);
                            new_page
                        }
                        Some(ref mut p) => *p as *mut _,
                    };
                }
            }
        }

        unsafe {
            SHIM_CAN_PRINT.store(false, Ordering::Release);
        }

        inner_extend_slots(self.write(), mem_slots, allocator);

        unsafe {
            SHIM_CAN_PRINT.store(true, Ordering::Release);
        }
    }

    /// Translate a shim virtual address to a host virtual address
    pub fn phys_to_host<U>(&self, val: ShimPhysUnencryptedAddr<U>) -> HostVirtAddr<U> {
        let this = self.read();
        let val: u64 = val.raw().raw();

        let offset = this.get_virt_offset(val as _).unwrap();

        unsafe {
            HostVirtAddr::new(Address::<u64, U>::unchecked(
                val.checked_add(offset as u64).unwrap(),
            ))
        }
    }

    /// set the initial entry
    pub fn first_entry(&self, start: usize, end: usize, virt_offset: i64) {
        let mut this = self.write();
        this.host_mem.ent[0].start = start;
        this.host_mem.ent[0].end = end;
        this.host_mem.ent[0].virt_offset = virt_offset;
    }

    /// Add a new HostMap entry
    pub fn new_entry(&self, size: usize, virt_offset: i64) -> Option<Line<usize>> {
        let mut this = self.write();
        let mut free = &mut this.host_mem;
        let mut last_end: usize = 0;

        loop {
            for i in free.ent.iter_mut() {
                if i.start == 0 {
                    i.virt_offset = virt_offset;
                    i.start = last_end;
                    i.end = i.start.checked_add(size).unwrap();
                    return Some(Line {
                        start: i.start,
                        end: i.end,
                    });
                }
                last_end = i.end;
            }

            // we have reached the end of the free slot page
            // advance to the next page
            if let Some(f) = free.header.next.as_deref_mut() {
                free = f;
            } else {
                return None;
            }
        }
    }
}
