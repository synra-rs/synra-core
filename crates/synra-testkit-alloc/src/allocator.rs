use super::{record_allocation, record_free};

/// Forwards to the system allocator and tells the counter what happened.
pub struct CountingAllocator;

// SAFETY: every method forwards directly to `System`, which is the allocator that would have been used anyway. The
// counter's bookkeeping happens after the call and touches only a thread-local, so it neither changes the returned
// pointer or its size nor can fail.
unsafe impl core::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is this method's contract, forwarded unchanged.
        let pointer = unsafe { std::alloc::System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: core::alloc::Layout) {
        record_free();
        // SAFETY: the caller's contract for `dealloc` is this method's contract, forwarded unchanged. The layout is
        // the one the block was allocated with, which the caller guarantees.
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        // SAFETY: the caller's contract for `realloc` is this method's contract, forwarded unchanged.
        let new_pointer = unsafe { std::alloc::System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            // A realloc that moved counts as an allocation and the old block as a free, which is what a caller
            // measuring "did this grow" wants to see.
            record_allocation(new_size);
            record_free();
        }
        new_pointer
    }
}
