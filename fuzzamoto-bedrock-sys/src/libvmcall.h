/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libvmcall — guest-side library for bedrock's hypercall interface.
 *
 * Any guest code (userspace programs or kernel modules) can include this
 * header to call out to the hypervisor. The library is header-only, so there
 * is nothing to link. Hypercalls are issued with the VMCALL instruction, the
 * hypercall number in RAX, arguments in RBX/RCX/RDX/RSI/RDI, and the result
 * returned in RAX.
 *
 * The hypercall numbers and ABI mirror the hypervisor side; the source of
 * truth is crates/bedrock-vmx/src/hypercalls.rs and the dispatcher in
 * crates/bedrock-vmx/src/exits/vmcall.rs. Keep this header in sync with them.
 *
 * This header is dependency-free (no libc / no kernel headers) so it works in
 * both build environments. vmcall_u64 is the 64-bit register-width type used
 * for every argument and result.
 *
 * The library is header-only: every primitive and wrapper is `static inline`
 * so any guest code can use it by just including this header — there is no
 * object to link. This is what lets the independently-built consumers (the
 * standalone pebs-register userspace program and the bedrock-io /
 * bedrock-console out-of-tree kernel modules, each compiled from its own
 * isolated source tree) share one implementation.
 */

#ifndef BEDROCK_LIBVMCALL_H
#define BEDROCK_LIBVMCALL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long long vmcall_u64;

/* ------------------------------------------------------------------------- */
/* Hypercall numbers (RAX). See crates/bedrock-vmx/src/hypercalls.rs.         */
/* ------------------------------------------------------------------------- */

/* Shut the VM down cleanly. No arguments; does not return to the guest. */
#define HYPERCALL_SHUTDOWN 0ULL

/* Trigger a snapshot; exits to userspace and logs VM state if enabled. */
#define HYPERCALL_SNAPSHOT 1ULL

/*
 * Register a feedback buffer for fuzzing.
 *   RBX = buffer GVA
 *   RCX = buffer size in bytes (1..=VMCALL_FEEDBACK_BUFFER_MAX_SIZE)
 *   RDX = identifier GVA (pointer to id bytes in guest memory)
 *   RSI = identifier length (1..=VMCALL_FEEDBACK_BUFFER_ID_MAX_LEN)
 * Returns the assigned slot index on success, or VMCALL_ERR on failure.
 */
#define HYPERCALL_REGISTER_FEEDBACK_BUFFER 2ULL

/* Register a 4KB PEBS scratch page. RBX = page GVA (must be 4KB-aligned). */
#define HYPERCALL_REGISTER_PEBS_PAGE 3ULL

/* Register the 4KB shared I/O channel page. RBX = page GVA (4KB-aligned). */
#define HYPERCALL_IO_REGISTER_PAGE 4ULL

/*
 * Fetch the pending I/O request into the registered shared page.
 * Returns request length in bytes, 0 if none pending, VMCALL_ERR on error.
 */
#define HYPERCALL_IO_GET_REQUEST 5ULL

/* Deliver an I/O response. RBX = response length (clamped to PAGE_SIZE). */
#define HYPERCALL_IO_PUT_RESPONSE 6ULL

/* Signal the guest has finished boot/init and is ready for the workload. */
#define HYPERCALL_READY 7ULL

/* Register the 4KB shared console page. RBX = page GVA (4KB-aligned). */
#define HYPERCALL_SERIAL_REGISTER_PAGE 8ULL

/* Emit bytes from the registered console page. RBX = byte count (<=PAGE). */
#define HYPERCALL_SERIAL_WRITE 9ULL

/*
 * Fetch the next chunk of a host-side file into the registered file-transfer
 * feedback buffer. No register arguments — the request and response are framed
 * inside the buffer (see VMCALL_FILE_XFER_* below). Returns 0 in RAX; the real
 * result is the response header the host writes into the buffer.
 */
#define HYPERCALL_FILE_FETCH 10ULL

/*
 * Send the next chunk of a file on the guest to the host via a registered
 * file sending feedback buffer. This buffer is distinct from the one used to
 * fetch files.
 */
#define HYPERCALL_FILE_STORE 12ULL

/*
 * Fetch the next fuzzer testcase into the registered fuzz-input buffer. No
 * register arguments — the response is framed inside the buffer the guest
 * registered under VMCALL_FUZZ_INPUT_BUFFER_ID. Returns 0 in RAX; the real
 * result is the response the host writes into the buffer.
 */
#define HYPERCALL_FUZZ_NEXT_INPUT 13ULL

/* ------------------------------------------------------------------------- */
/* ABI constants.                                                            */
/* ------------------------------------------------------------------------- */

/* Generic failure sentinel returned in RAX by most hypercalls ((u64)-1). */
#define VMCALL_ERR ((vmcall_u64)~0ULL)

/* Generic success sentinel for hypercalls that return 0 on success. */
#define VMCALL_OK ((vmcall_u64)0ULL)

/* Page size of every shared/registered page. */
#define VMCALL_PAGE_SIZE 4096U

/* Feedback buffer limits (FEEDBACK_BUFFER_MAX_PAGES * 4096 = 1 MB, and the
 * id length cap). Mirrors the hypervisor's constants. */
#define VMCALL_FEEDBACK_BUFFER_MAX_SIZE (256U * 4096U)
#define VMCALL_FEEDBACK_BUFFER_ID_MAX_LEN 128U

/*
 * Feedback buffer registration failure codes returned in RAX (mirror the
 * FB_ERR_* constants in crates/bedrock-vmx/src/exits/vmcall.rs). On success
 * the call returns the assigned slot index (0..MAX_FEEDBACK_BUFFERS-1), which
 * can't collide with these. The _NOT_RESIDENT codes mean the passed page
 * wasn't faulted in: the hypervisor translates the pointer by walking the
 * guest page tables and can't fault a page in for you, so touch the buffer and
 * id (and mlock the buffer) before registering.
 */
#define VMCALL_FB_ERR_BAD_SIZE VMCALL_ERR                  /* (u64)-1 */
#define VMCALL_FB_ERR_BAD_ID_LEN (VMCALL_ERR - 1ULL)       /* (u64)-2 */
#define VMCALL_FB_ERR_ID_NOT_RESIDENT (VMCALL_ERR - 2ULL)  /* (u64)-3 */
#define VMCALL_FB_ERR_BUFFER_NOT_RESIDENT (VMCALL_ERR - 3ULL) /* (u64)-4 */
#define VMCALL_FB_ERR_NO_SLOTS (VMCALL_ERR - 4ULL)         /* (u64)-5 */

/*
 * PEBS registration failure codes returned in RAX (mirror
 * RegisterPebsPageResult in crates/bedrock-vmx/src/exits/pebs.rs).
 */
#define VMCALL_PEBS_ERR_UNSUPPORTED VMCALL_ERR          /* (u64)-1 */
#define VMCALL_PEBS_ERR_UNALIGNED (VMCALL_ERR - 1ULL)   /* (u64)-2 */
#define VMCALL_PEBS_ERR_WALK_FAILED (VMCALL_ERR - 2ULL) /* (u64)-3 */
#define VMCALL_PEBS_ERR_NO_EPT (VMCALL_ERR - 3ULL)      /* (u64)-4 */
#define VMCALL_PEBS_ERR_ALREADY (VMCALL_ERR - 4ULL)     /* (u64)-5 */

/*
 * File-transmission framing (HYPERCALL_FILE_FETCH). The guest registers one
 * feedback buffer under the id VMCALL_FILE_XFER_BUFFER_ID and uses it as the
 * shared transport. Mirrors crates/bedrock-vm/src/file_xfer.rs — keep in sync.
 *
 * The first VMCALL_FILE_XFER_HEADER_LEN bytes of the buffer are the header;
 * payload (the file name on a request, the file data on a response) follows it.
 *
 * Request (guest writes, before the hypercall):
 *   [0..8)   u64 little-endian file offset to read from
 *   [8..12)  u32 little-endian file-name length
 *   [12..16) reserved (zero)
 *   [16..16+name_len) the file name (e.g. "images.tar")
 *
 * Response (host writes, overwriting the buffer):
 *   [0..8)   i64 little-endian result: >=0 = data byte count (0 = EOF),
 *            VMCALL_FILE_XFER_NOT_FOUND = unknown/unreadable file
 *   [8..16)  reserved (zero)
 *   [16..16+result) the file data chunk
 */
#define VMCALL_FILE_XFER_BUFFER_ID "bedrock-file-xfer"
#define VMCALL_FILE_XFER_HEADER_LEN 16U
#define VMCALL_FILE_XFER_NOT_FOUND (-1LL)

/*
 * Format for HYPERCALL_FILE_STORE.
 *
 * Request (guest writes):
 *   [0..4)  u32 little-endian file-name length
 *   [4..8)  u32 little-endian chunk length
 *   [8..16) reserved (zero)
 *   [16..16+name_len) the file name
 *   [16+name_len..16+name_len+chunk_len) the file data chunk
 *
 * Response (host writes):
 *   [0..8)   i64 little-endian result: > 0 = bytes read,
 *            VMCALL_FILE_STORE_IO_ERROR = host error'd while writing chunk
 *   [8..16)  reserved (zero) to not introduce separate header lengths
 */
#define VMCALL_FILE_STORE_BUFFER_ID "bedrock-file-store"
#define VMCALL_FILE_STORE_HEADER_LEN 16U
#define VMCALL_FILE_STORE_IO_ERROR (-1LL)

/*
 * Fuzz-input framing (HYPERCALL_FUZZ_NEXT_INPUT). The guest registers one
 * feedback buffer under the id VMCALL_FUZZ_INPUT_BUFFER_ID and uses it as the
 * host->guest transport for testcases. Mirrors
 * crates/bedrock-vm/src/fuzz_input.rs — keep in sync.
 *
 * The header carries both directions, because both happen at the same
 * hypercall: the guest reports on the testcase it just finished in the same
 * call that asks for the next one.
 *
 *   [0..8)   u64 result   (host writes): input byte count
 *   [8..16)  u64 status   (guest writes): outcome of the PREVIOUS testcase,
 *                         one of VMCALL_FUZZ_STATUS_*
 *   [16..24) u64 aux      (guest writes): message length when status is FAIL
 *   [24..32) reserved     (zero)
 *   [32..32+result)       the input bytes (host writes), or the guest's failure
 *                         message when status is FAIL
 *
 * The buffer is sized by the guest at registration. A buffer larger than
 * VMCALL_FEEDBACK_BUFFER_MAX_SIZE must be a multiple of it and is registered
 * as consecutive slots under the same id (see
 * vmcall_register_fuzz_input_buffer); the host treats them as one buffer.
 * Usable input capacity is the total size less VMCALL_FUZZ_INPUT_HEADER_LEN.
 */
#define VMCALL_FUZZ_INPUT_BUFFER_ID "fuzz-input"
#define VMCALL_FUZZ_INPUT_HEADER_LEN 32U

/* Values for the guest-written status word at [8..16). */
#define VMCALL_FUZZ_STATUS_OK 0ULL
#define VMCALL_FUZZ_STATUS_SKIP 1ULL
#define VMCALL_FUZZ_STATUS_FAIL 2ULL

/* ------------------------------------------------------------------------- */
/* Generic VMCALL primitives — hypercall number plus up to five arguments.   */
/*                                                                           */
/* The "memory" clobber inside these is load-bearing: it forces the compiler */
/* to complete stores into any shared page before the VMCALL and to re-read   */
/* memory the hypervisor may have written afterwards. Use these directly for  */
/* hypercalls the named wrappers below don't cover.                          */
/* ------------------------------------------------------------------------- */

static inline vmcall_u64 vmcall0(vmcall_u64 nr)
{
	vmcall_u64 result;

	asm volatile("vmcall" : "=a"(result) : "a"(nr) : "memory");
	return result;
}

static inline vmcall_u64 vmcall1(vmcall_u64 nr, vmcall_u64 a1)
{
	vmcall_u64 result;

	asm volatile("vmcall" : "=a"(result) : "a"(nr), "b"(a1) : "memory");
	return result;
}

static inline vmcall_u64 vmcall2(vmcall_u64 nr, vmcall_u64 a1, vmcall_u64 a2)
{
	vmcall_u64 result;

	asm volatile("vmcall"
		     : "=a"(result)
		     : "a"(nr), "b"(a1), "c"(a2)
		     : "memory");
	return result;
}

static inline vmcall_u64 vmcall3(vmcall_u64 nr, vmcall_u64 a1, vmcall_u64 a2,
				 vmcall_u64 a3)
{
	vmcall_u64 result;

	asm volatile("vmcall"
		     : "=a"(result)
		     : "a"(nr), "b"(a1), "c"(a2), "d"(a3)
		     : "memory");
	return result;
}

static inline vmcall_u64 vmcall4(vmcall_u64 nr, vmcall_u64 a1, vmcall_u64 a2,
				 vmcall_u64 a3, vmcall_u64 a4)
{
	vmcall_u64 result;

	asm volatile("vmcall"
		     : "=a"(result)
		     : "a"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4)
		     : "memory");
	return result;
}

static inline vmcall_u64 vmcall5(vmcall_u64 nr, vmcall_u64 a1, vmcall_u64 a2,
				 vmcall_u64 a3, vmcall_u64 a4, vmcall_u64 a5)
{
	vmcall_u64 result;

	asm volatile("vmcall"
		     : "=a"(result)
		     : "a"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5)
		     : "memory");
	return result;
}

/* ------------------------------------------------------------------------- */
/* Named hypercall wrappers.                                                 */
/* ------------------------------------------------------------------------- */

/* Shut the VM down. Does not return if the hypervisor honours the request. */
static inline void vmcall_shutdown(void)
{
	vmcall0(HYPERCALL_SHUTDOWN);
}

/* Trigger a snapshot. */
static inline void vmcall_snapshot(void)
{
	vmcall0(HYPERCALL_SNAPSHOT);
}

/* Signal that the guest has finished boot/init and is ready. */
static inline void vmcall_ready(void)
{
	vmcall0(HYPERCALL_READY);
}

/*
 * Register a feedback buffer. `buf`/`size` describe the buffer; `id`/`id_len`
 * an identifier the host groups results under. Returns the assigned slot
 * index (>= 0) on success, or one of the VMCALL_FB_ERR_* codes on failure.
 *
 * `buf` and `id` must already be faulted-in (and `buf` should be mlock'd so it
 * stays resident at a stable GPA): the hypervisor translates both by walking
 * the guest page tables and rejects a not-present page with
 * VMCALL_FB_ERR_BUFFER_NOT_RESIDENT / VMCALL_FB_ERR_ID_NOT_RESIDENT.
 */
static inline vmcall_u64 vmcall_register_feedback_buffer(const void *buf,
							 vmcall_u64 size,
							 const void *id,
							 vmcall_u64 id_len)
{
	return vmcall4(HYPERCALL_REGISTER_FEEDBACK_BUFFER, (vmcall_u64)buf,
		       size, (vmcall_u64)id, id_len);
}

/* Register a 4KB PEBS scratch page. Returns VMCALL_OK or a VMCALL_PEBS_ERR_*. */
static inline vmcall_u64 vmcall_register_pebs_page(const void *page)
{
	return vmcall1(HYPERCALL_REGISTER_PEBS_PAGE, (vmcall_u64)page);
}

/* Register the 4KB shared I/O channel page. Returns VMCALL_OK / VMCALL_ERR. */
static inline vmcall_u64 vmcall_io_register_page(const void *page)
{
	return vmcall1(HYPERCALL_IO_REGISTER_PAGE, (vmcall_u64)page);
}

/*
 * Fetch the pending I/O request into the registered shared page. Returns the
 * request length, 0 if none pending, VMCALL_ERR on error.
 */
static inline vmcall_u64 vmcall_io_get_request(void)
{
	return vmcall0(HYPERCALL_IO_GET_REQUEST);
}

/* Deliver an I/O response of `len` bytes. Returns VMCALL_OK / VMCALL_ERR. */
static inline vmcall_u64 vmcall_io_put_response(vmcall_u64 len)
{
	return vmcall1(HYPERCALL_IO_PUT_RESPONSE, len);
}

/* Register the 4KB shared console page. Returns VMCALL_OK / VMCALL_ERR. */
static inline vmcall_u64 vmcall_serial_register_page(const void *page)
{
	return vmcall1(HYPERCALL_SERIAL_REGISTER_PAGE, (vmcall_u64)page);
}

/* Emit `len` bytes from the registered console page. Returns OK / ERR. */
static inline vmcall_u64 vmcall_serial_write(vmcall_u64 len)
{
	return vmcall1(HYPERCALL_SERIAL_WRITE, len);
}

/*
 * Fetch the next file chunk into the registered file-transfer buffer. The
 * request must already be framed at the start of the buffer (see
 * VMCALL_FILE_XFER_* above); the host overwrites the buffer with the response.
 * Always returns 0 — read the result out of the buffer header.
 */
static inline vmcall_u64 vmcall_file_fetch(void)
{
	return vmcall0(HYPERCALL_FILE_FETCH);
}

/* Store the next file chunk into the registered file store buffer. This is
 * distinct from the file-transfer buffer.
 */
static inline vmcall_u64 vmcall_file_store(void)
{
        return vmcall0(HYPERCALL_FILE_STORE);
}

/*
 * Block until the host supplies the next fuzzer testcase in the registered
 * fuzz-input buffer. Always returns 0 — read the result word out of the buffer
 * header to get the input length.
 *
 * The host checkpoints the VM at this exit, so on a forked VM this call is
 * where execution resumes, with a testcase already written into the buffer.
 */
static inline vmcall_u64 vmcall_fuzz_next_input(void)
{
	return vmcall0(HYPERCALL_FUZZ_NEXT_INPUT);
}

/*
 * Register `buf` as the fuzz-input buffer, one VMCALL_FEEDBACK_BUFFER_MAX_SIZE
 * slot at a time, in order. `size` must be a non-zero multiple of
 * VMCALL_FEEDBACK_BUFFER_MAX_SIZE. Same residency rules as
 * vmcall_register_feedback_buffer. Returns VMCALL_OK, or the first failing
 * VMCALL_FB_ERR_* code.
 */
static inline vmcall_u64 vmcall_register_fuzz_input_buffer(void *buf,
							   vmcall_u64 size)
{
        /* On the stack, not .rodata: the hypervisor can't fault in the id's page. */
        char id[] = VMCALL_FUZZ_INPUT_BUFFER_ID;
	vmcall_u64 off;

	if (size == 0 || size % VMCALL_FEEDBACK_BUFFER_MAX_SIZE)
		return VMCALL_FB_ERR_BAD_SIZE;

	for (off = 0; off < size; off += VMCALL_FEEDBACK_BUFFER_MAX_SIZE) {
		vmcall_u64 ret = vmcall_register_feedback_buffer(
			(char *)buf + off, VMCALL_FEEDBACK_BUFFER_MAX_SIZE, id,
			sizeof(id) - 1);

		if (ret >= VMCALL_FB_ERR_NO_SLOTS)
			return ret;
	}
	return VMCALL_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* BEDROCK_LIBVMCALL_H */
