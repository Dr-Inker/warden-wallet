//! Custom global allocator (Phase 1B Task 6 prerequisite).
//!
//! ## Why the default allocator had to go
//!
//! Task 5's measurement sweep (PHASE1B-MEASUREMENTS §"Task 5 measurement
//! sweep") found the `execute` account caps are bound by **SBF heap**, not CU
//! or bytes: two full `Vec<Snap>` conservation snapshots exhaust the default
//! 32 KiB at ~27 remaining accounts, and a top-level `RequestHeapFrame` does
//! NOT relieve it — the entrypoint's default `BumpAllocator` is constructed
//! `with_fixed_address_range(HEAP_START_ADDRESS, HEAP_LENGTH)`, a hard 32 KiB
//! cap that ignores whatever larger frame the runtime actually granted. A
//! ~40-account Jupiter route (Task 6 `swap`) cannot fit under that ceiling.
//!
//! ## What this allocator does differently — and what bounds it
//!
//! It bumps **upward from `HEAP_START_ADDRESS` with no length cap of its
//! own**. The bound is the runtime's: the SBF VM maps exactly the heap the
//! transaction was granted (32 KiB by default, up to 256 KiB via a top-level
//! `RequestHeapFrame`), and the first write past the mapped region faults the
//! transaction (`memory access violation`) — **fail-closed**, nothing
//! persists. So:
//!
//! - a transaction that needs ≤ 32 KiB behaves exactly as before;
//! - a large shape works iff its wrapper requested the frame — the same
//!   client contract as `SetComputeUnitLimit`, which the wrapper already
//!   injects (spec §5.2's compute-budget hoisting);
//! - the allocator itself never decides a size policy. Adding our own cap
//!   here would just recreate the bug at a different number.
//!
//! `dealloc` is a no-op (bump allocators never free; an instruction's heap
//! dies with the transaction). The cursor lives in the first word of the heap
//! region itself — the standard Solana pattern — so the allocator has no
//! static mutable state of its own.
//!
//! The arithmetic lives in [`bump`], a pure function unit-tested off-chain
//! (overflow-checked; the crate denies `arithmetic_side_effects`). The
//! `GlobalAlloc` impl is the thinnest possible shim over it.

/// One bump step: given the current `cursor` (first free address), an
/// alignment (a power of two — guaranteed by `core::alloc::Layout`) and a
/// size, return `(new_cursor, allocation_address)`, or `None` on address
/// overflow. NO upper bound is applied here — see the module docs: the
/// runtime's mapped heap frame is the bound, and faulting past it is the
/// fail-closed behaviour we want.
#[inline]
pub const fn bump(cursor: usize, align: usize, size: usize) -> Option<(usize, usize)> {
    // align_up(cursor, align): Layout guarantees align is a nonzero power of
    // two, so `align - 1` cannot underflow and the mask is well-formed.
    let mask = align.wrapping_sub(1);
    let aligned = match cursor.checked_add(mask) {
        Some(v) => v & !mask,
        None => return None,
    };
    match aligned.checked_add(size) {
        Some(next) => Some((next, aligned)),
        None => None,
    }
}

#[cfg(target_os = "solana")]
mod sbf {
    use super::bump;
    use core::alloc::{GlobalAlloc, Layout};

    use anchor_lang::solana_program::entrypoint::HEAP_START_ADDRESS;

    /// Upward bump allocator, unbounded above (the runtime's granted frame is
    /// the bound). The cursor is stored in the first `usize` of the heap.
    pub struct WardenAllocator;

    unsafe impl GlobalAlloc for WardenAllocator {
        #[inline]
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let cursor_ptr = HEAP_START_ADDRESS as usize as *mut usize;
            let mut cursor = *cursor_ptr;
            if cursor == 0 {
                // First allocation of the instruction: skip the cursor word.
                cursor = (HEAP_START_ADDRESS as usize).saturating_add(core::mem::size_of::<usize>());
            }
            match bump(cursor, layout.align(), layout.size()) {
                Some((next, addr)) => {
                    *cursor_ptr = next;
                    addr as *mut u8
                }
                // Address-space overflow: report allocation failure; Rust's
                // alloc error handler aborts the instruction.
                None => core::ptr::null_mut(),
            }
        }

        #[inline]
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // Bump allocators never free; the heap dies with the transaction.
        }
    }

    #[global_allocator]
    static ALLOCATOR: WardenAllocator = WardenAllocator;
}

#[cfg(test)]
mod tests {
    use super::bump;

    #[test]
    fn bumps_upward_with_alignment() {
        // cursor 0x300000008, align 8, size 16 → allocation at the cursor.
        let (next, addr) = bump(0x3000_0000_8, 8, 16).unwrap();
        assert_eq!(addr, 0x3000_0000_8);
        assert_eq!(next, 0x3000_0001_8);
        // Misaligned cursor rounds UP to the alignment, never down.
        let (next, addr) = bump(0x3000_0000_9, 8, 8).unwrap();
        assert_eq!(addr, 0x3000_0001_0);
        assert_eq!(next, 0x3000_0001_8);
    }

    #[test]
    fn no_upper_cap_below_address_overflow() {
        // Way past 32 KiB from the heap start: the allocator itself does not
        // refuse — the runtime's mapped frame is the bound (module docs).
        let heap_start = 0x3_0000_0000usize;
        let far = heap_start + 200 * 1024;
        let (next, addr) = bump(far, 8, 1024).unwrap();
        assert_eq!(addr, far);
        assert_eq!(next, far + 1024);
    }

    #[test]
    fn address_overflow_is_none_never_wrap() {
        assert!(bump(usize::MAX - 4, 8, 16).is_none());
        assert!(bump(usize::MAX, 1, 1).is_none());
    }

    #[test]
    fn zero_size_allocation_advances_only_to_alignment() {
        let (next, addr) = bump(100, 16, 0).unwrap();
        assert_eq!(addr, 112);
        assert_eq!(next, 112);
    }
}
