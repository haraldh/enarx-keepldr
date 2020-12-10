// SPDX-License-Identifier: Apache-2.0

//! The global FrameAllocator
use crate::addr::{ShimPhysAddr, ShimVirtAddr};
use crate::hostcall::HOST_CALL_ALLOC;
use crate::hostmap::HOSTMAP;
use crate::linked_list_allocator::LinkedListAllocator;
use crate::{get_cbit_mask, BOOT_INFO, C_BIT_MASK};
use core::convert::TryFrom;
use core::mem::{align_of, size_of, MaybeUninit};
use core::sync::atomic::Ordering;
use lset::Span;
use nbytes::bytes;
use primordial::{Address, Page as Page4KiB};
use spinning::{Lazy, RwLock};
use x86_64::structures::paging::mapper::{MapToError, UnmapError};
use x86_64::structures::paging::{
    self, Mapper, Page, PageTableFlags, PhysFrame, Size2MiB, Size4KiB,
};
use x86_64::{align_down, PhysAddr, VirtAddr};

/// An aligned 2MiB Page
///
/// The `x86_64::structures::paging::Page<S>` is not aligned, so we use
/// memory::Page as Page4KiB and this Page2MiB
#[derive(Copy, Clone)]
#[repr(C, align(0x200000))]
#[allow(clippy::integer_arithmetic)]
pub struct Page2MiB([u8; bytes![2; MiB]]);

/// The global ShimFrameAllocator RwLock
pub static ALLOCATOR: Lazy<RwLock<EnarxAllocator>> = Lazy::new(|| {
    RwLock::<EnarxAllocator>::const_new(spinning::RawRwLock::const_new(), unsafe {
        EnarxAllocator::new()
    })
});

/// A frame allocator
pub struct EnarxAllocator {
    next_alloc: usize,
    max_alloc: usize,
    mem_slots: usize,
    allocator: LinkedListAllocator,
}

impl core::fmt::Debug for EnarxAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("FrameAllocator")
            .field("next_alloc", &self.next_alloc)
            .field("max_alloc", &self.max_alloc)
            .finish()
    }
}

/// Get the most significant bit set
/// Poor man's log2
#[inline]
#[allow(clippy::integer_arithmetic)]
fn msb(val: usize) -> u32 {
    let mut val = val;
    let mut r = 0;
    loop {
        val >>= 1;

        if val == 0 {
            return r;
        }

        r += 1;
    }
}

/// Error returned by the `FrameAllocator`
#[derive(Debug)]
pub enum AllocateError {
    /// Memory or Size not page aligned
    NotAligned,
    /// Out of Memory
    OutOfMemory,
    /// Requested memory size of zero
    ZeroSize,
    /// Error mapping the page
    PageAlreadyMapped,
    /// An upper level page table entry has the `HUGE_PAGE` flag set, which means that the
    /// given page is part of an already mapped huge page.
    ParentEntryHugePage,
}

impl EnarxAllocator {
    unsafe fn new() -> Self {
        let boot_info = BOOT_INFO.read().unwrap();

        let meminfo = {
            let mut host_call = HOST_CALL_ALLOC.try_alloc().unwrap();
            host_call.mem_info().unwrap()
        };

        const MIN_EXP: u32 = 25; // start with 2^25 = 32 MiB
        let c_bit_mask = C_BIT_MASK.load(Ordering::Relaxed);
        let target_exp: u32 = if c_bit_mask > 0 {
            msb(c_bit_mask as _).checked_sub(1).unwrap() // don't want to address more than c_bit_mask
        } else {
            47 // we want more than 2^47 = 128 TiB
        };

        debug_assert!(
            meminfo.mem_slots > (target_exp.checked_sub(MIN_EXP).unwrap()) as _,
            "Not enough memory slots available"
        );

        let log_rest = msb(meminfo
            .mem_slots
            .checked_sub(target_exp.checked_sub(MIN_EXP).unwrap() as usize)
            .unwrap());
        // cap, so that max_exp >= MIN_EXP
        let max_exp = target_exp
            .checked_sub(log_rest.min(target_exp.checked_sub(MIN_EXP).unwrap()))
            .unwrap();

        // With mem_slots == 509, this gives 508 slots for ballooning
        // Starting with 2^25 = 32 MiB to 2^38 = 256 GiB takes 13 slots
        // gives 495 slots a 2^39 = 512 GiB
        // equals a maximum memory of 495 * 512 GiB - (32 MiB - 1)
        // = 247.5 TiB - 32 MiB + 1
        // which is only a little bit less than the max. 256 TiB
        // max_mem = (mem_slots - max_exp + MIN_EXP) * (1usize << max_exp)
        //    - (1usize << (MIN_EXP - 1));

        let next_alloc = (2usize).checked_pow(MIN_EXP).unwrap();
        let max_alloc = (2usize).checked_pow(max_exp).unwrap();

        HOSTMAP.first_entry(boot_info.code.end, boot_info.mem_size, meminfo.virt_offset);

        debug_assert_ne!(boot_info.mem_size, 0);

        let mut allocator = LinkedListAllocator::default();

        let free_start_phys = Address::<usize, _>::from(boot_info.code.end as *const u8);
        let shim_phys_page = ShimPhysAddr::from(free_start_phys);
        let free_start: *mut u8 = ShimVirtAddr::from(shim_phys_page).into();

        let heap_size = boot_info.mem_size.checked_sub(boot_info.code.end).unwrap();

        if heap_size > 0 {
            allocator.init(free_start as _, heap_size);
        }

        EnarxAllocator {
            next_alloc,
            max_alloc,
            mem_slots: meminfo.mem_slots,
            allocator,
        }
    }

    fn balloon(&mut self) -> bool {
        let mut last_size: usize = self.next_alloc;

        loop {
            // request new memory from the host
            let new_size: usize = 2u64
                .checked_mul(last_size as u64)
                .unwrap_or(last_size as u64) as _;
            let new_size = new_size.min(self.max_alloc);
            let num_pages = new_size.checked_div(Page4KiB::size() as _).unwrap();

            let ret = HOST_CALL_ALLOC.try_alloc().unwrap().balloon(num_pages);

            if let Ok(virt_offset) = ret {
                match HOSTMAP.new_entry(new_size, virt_offset) {
                    None => return false,
                    Some(line) => {
                        let mut region = Span::from(line);
                        let free_start_phys = Address::<usize, _>::from(region.start as *const u8);
                        let shim_phys_page = ShimPhysAddr::from(free_start_phys);
                        let free_start: *mut u8 = ShimVirtAddr::from(shim_phys_page).into();
                        region.start = free_start as _;

                        unsafe {
                            self.allocator.add_free_region(region.start, region.count);
                        }
                        self.next_alloc = new_size;

                        HOSTMAP.extend_slots(self.mem_slots, &mut self.allocator);

                        return true;
                    }
                }
            }

            // Failed to get more memory.
            // Try again with half of the memory.
            last_size = last_size.checked_div(2).unwrap();
            if last_size < Page4KiB::size() {
                // Host does not have even a page of memory
                return false;
            }
        }
    }

    fn try_alloc_half(&mut self, mut size: usize) -> (*mut u8, usize) {
        assert!(size >= size_of::<Page4KiB>());
        loop {
            let p = self.allocator.alloc_bytes(size, align_of::<Page4KiB>());
            if !p.is_null() || size == size_of::<Page4KiB>() {
                return (p, size);
            }
            size = size.checked_div(2).unwrap();
        }
    }

    /// Allocate memory and map it to the given virtual address
    pub fn allocate_and_map_memory(
        &mut self,
        mapper: &mut (impl Mapper<Size4KiB> + Mapper<Size2MiB>),
        map_to: VirtAddr,
        size: usize,
        flags: PageTableFlags,
        parent_flags: PageTableFlags,
    ) -> Result<&'static mut [u8], AllocateError> {
        if size == 0 {
            return Err(AllocateError::ZeroSize);
        }

        if !map_to.is_aligned(align_of::<Page4KiB>() as u64) {
            return Err(AllocateError::NotAligned);
        }

        if size != align_down(size as _, Page::<Size4KiB>::SIZE) as usize {
            return Err(AllocateError::NotAligned);
        }

        let curr_size = (2usize).checked_pow(msb(size)).unwrap();

        let (first_half, first_half_size) = {
            while !self.allocator.has_free_mem(curr_size) {
                self.balloon();
            }
            let (chunk, chunk_size) = self.try_alloc_half(curr_size);

            if chunk.is_null() {
                self.balloon();
                self.try_alloc_half(curr_size)
            } else {
                (chunk, chunk_size)
            }
        };

        if first_half.is_null() {
            return Err(AllocateError::OutOfMemory);
        }

        let second_half_size = size.checked_sub(first_half_size).unwrap();

        if second_half_size > 0 {
            if let Err(e) = self.allocate_and_map_memory(
                mapper,
                map_to + first_half_size,
                second_half_size,
                flags,
                parent_flags,
            ) {
                unsafe {
                    self.allocator.dealloc_bytes(first_half, first_half_size);
                }
                return Err(e);
            }
        }

        let phys = shim_virt_to_enc_phys(first_half);
        if let Err(e) = self.map_memory(mapper, phys, map_to, first_half_size, flags, parent_flags)
        {
            unsafe {
                self.allocator.dealloc_bytes(first_half, first_half_size);
            }
            let _ = self.unmap_memory(mapper, map_to + first_half_size, second_half_size);
            return Err(e);
        }

        // transmute the whole thing to one big bytes slice
        Ok(unsafe { core::slice::from_raw_parts_mut(map_to.as_mut_ptr() as *mut u8, size) })
    }

    /// Map physical memory to the given virtual address
    ///
    /// FIXME: change PhysAddr to ShimPhysAddr to ensure encrypted memory
    pub fn map_memory<T: Mapper<Size4KiB> + Mapper<Size2MiB>>(
        &mut self,
        mapper: &mut T,
        map_from: PhysAddr,
        map_to: VirtAddr,
        size: usize,
        flags: PageTableFlags,
        parent_flags: PageTableFlags,
    ) -> Result<(), AllocateError> {
        if size == 0 {
            return Err(AllocateError::ZeroSize);
        }

        let frame_range_from = {
            let start = map_from;
            let end = start + size - 1u64;
            let start_frame = PhysFrame::<Size4KiB>::containing_address(start);
            let end_frame = PhysFrame::<Size4KiB>::containing_address(end);
            PhysFrame::range_inclusive(start_frame, end_frame)
        };

        let page_range_to = {
            let start = map_to;
            let end = start + size - 1u64;
            let start_page = Page::<Size4KiB>::containing_address(start);
            let end_page = Page::<Size4KiB>::containing_address(end);
            Page::range_inclusive(start_page, end_page)
        };

        for (frame_from, page_to) in frame_range_from.zip(page_range_to) {
            unsafe {
                mapper
                    .map_to_with_table_flags(page_to, frame_from, flags, parent_flags, self)
                    .map_err(|e| match e {
                        MapToError::FrameAllocationFailed => AllocateError::OutOfMemory,
                        MapToError::ParentEntryHugePage => AllocateError::ParentEntryHugePage,
                        MapToError::PageAlreadyMapped(_) => AllocateError::PageAlreadyMapped,
                    })?
                    .flush();
            }
        }

        Ok(())
    }

    /// FIXME: unmap
    pub fn unmap_memory<T: Mapper<Size4KiB> + Mapper<Size2MiB>>(
        &mut self,
        mapper: &mut T,
        virt_addr: VirtAddr,
        size: usize,
    ) -> Result<(), UnmapError> {
        if size == 0 {
            return Ok(());
        }

        let page_range_to = {
            let start = virt_addr;
            let end = start + size - 1u64;
            let start_page = Page::<Size4KiB>::containing_address(start);
            let end_page = Page::<Size4KiB>::containing_address(end);
            Page::range_inclusive(start_page, end_page)
        };

        for frame_from in page_range_to {
            let phys = {
                let (phys_frame, flush) = mapper.unmap(frame_from)?;
                flush.flush();
                phys_frame.start_address()
            };

            let free_start_phys = Address::<usize, _>::from(phys.as_u64() as *const u8);
            let shim_phys_page = ShimPhysAddr::from(free_start_phys);
            let shim_virt: *mut u8 = ShimVirtAddr::from(shim_phys_page).into();
            unsafe {
                self.allocator
                    .dealloc_bytes(shim_virt, Page::<Size4KiB>::SIZE as usize);
            }
        }

        Ok(())
    }

    /// Allocate memory
    pub fn try_alloc<T>(&mut self) -> Option<&mut MaybeUninit<T>> {
        unsafe {
            let b = self.allocator.alloc_bytes(size_of::<T>(), align_of::<T>());

            if b.is_null() && self.balloon() {
                // try once again to allocate
                let b = self.allocator.alloc_bytes(size_of::<T>(), align_of::<T>());
                (b as *mut MaybeUninit<T>).as_mut()
            } else {
                (b as *mut MaybeUninit<T>).as_mut()
            }
        }
    }

    /// Deallocate memory
    ///
    /// # Safety
    ///
    /// Unsafe, because the caller has to ensure to not use any references left.
    pub unsafe fn dealloc<T>(&mut self, ptr: *mut T) {
        self.allocator.dealloc_bytes(ptr as _, size_of::<T>())
    }
}

unsafe impl paging::FrameAllocator<Size4KiB> for EnarxAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        self.try_alloc::<Page4KiB>()
            .map(|a| PhysFrame::containing_address(shim_virt_to_enc_phys(a.as_mut_ptr())))
    }
}

unsafe impl paging::FrameAllocator<Size2MiB> for EnarxAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        self.try_alloc::<Page2MiB>()
            .map(|a| PhysFrame::containing_address(shim_virt_to_enc_phys(a.as_mut_ptr())))
    }
}

#[inline]
fn shim_virt_to_enc_phys<T>(p: *mut T) -> PhysAddr {
    let addr = Address::<u64, _>::from(p);
    let virt = ShimVirtAddr::try_from(addr).unwrap();
    let phys = ShimPhysAddr::try_from(virt).unwrap();
    PhysAddr::new(phys.raw().raw() | get_cbit_mask())
}
