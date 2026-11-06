#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>

#include "libvmcall.h"

#ifndef TARGET_MAP_SIZE
#define TARGET_MAP_SIZE 0
#endif

/* 8MB for the fuzz input buffer. */
#define AGENT_BUF_SLOTS 8
#define AGENT_BUF_SIZE (AGENT_BUF_SLOTS * VMCALL_FEEDBACK_BUFFER_MAX_SIZE)
#define AGENT_INPUT_CAPACITY (AGENT_BUF_SIZE - VMCALL_FUZZ_INPUT_HEADER_LEN)

#define STORE_BUF_SIZE VMCALL_FEEDBACK_BUFFER_MAX_SIZE

/* Coverage feedback buffer id. */
#define COVERAGE_BUFFER_ID "cov-afl"

/* Feedback buffer header layout. See VMCALL_FUZZ_INPUT_* in libvmcall.h. */
struct fuzz_header {
    uint64_t result;
    uint64_t status;
    uint64_t aux;
    uint64_t reserved;
};

static volatile struct fuzz_header *g_header;
static uint8_t *g_payload;

static uint8_t *trace_buffer = NULL;
static size_t trace_buffer_size = 0;

/* Emit a line to the host's serial event stream. */
void bedrock_println(const char *message, size_t size)
{
    (void)!write(2, message, size);
    (void)!write(2, "\n", 1);
}

/* Abort the VM, possibly logging a message. */
static void bedrock_abort(const char *reason)
{
    if (reason) {
        bedrock_println(reason, strlen(reason));
    }
    vmcall_shutdown();
}

/* Abort if buffer registration fails. */
static void abort_on_registration_error(vmcall_u64 slot, const char *what)
{
    if (slot < VMCALL_ERR - 4ULL)
        return;

    if (slot == VMCALL_FB_ERR_BAD_SIZE)
        bedrock_abort("buffer registration: bad size");
    else if (slot == VMCALL_FB_ERR_BAD_ID_LEN)
        bedrock_abort("buffer registration: bad id length");
    else if (slot == VMCALL_FB_ERR_ID_NOT_RESIDENT)
        bedrock_abort("buffer registration: id page not resident");
    else if (slot == VMCALL_FB_ERR_BUFFER_NOT_RESIDENT)
        bedrock_abort("buffer registration: buffer not resident");
    else if (slot == VMCALL_FB_ERR_NO_SLOTS)
        bedrock_abort("buffer registration: no slots left");
    else
        bedrock_abort(what);
}

/*
 * Register the shared coverage buffer and tell the host we finished booting.
 */
size_t bedrock_init()
{
    size_t size = (size_t)TARGET_MAP_SIZE;
    if (size == 0 || size > VMCALL_FEEDBACK_BUFFER_MAX_SIZE)
        bedrock_abort("Error: bedrock rejected configured TARGET_MAP_SIZE");

    int shmid = shmget(IPC_PRIVATE, size, IPC_CREAT | 0600);
    if (shmid < 0)
        bedrock_abort("Error: Failed to create shared memory region for trace buffer");

    void *buf = shmat(shmid, NULL, 0);
    if (buf == (void *)-1)
        bedrock_abort("Error: Failed to attach to shared memory segment for trace buffer");

    memset(buf, 0, size);
    if (mlock(buf, size) != 0)
        bedrock_abort("Error: Failed to mlock the coverage map");

    char id[sizeof(COVERAGE_BUFFER_ID)];
    memcpy(id, COVERAGE_BUFFER_ID, sizeof(id));

    vmcall_u64 slot = vmcall_register_feedback_buffer(buf, size, id,
                                                      sizeof(id) - 1);
    abort_on_registration_error(slot, "coverage buffer registration failed");

    // Update AFL++ environment variables.
    char value[24];
    snprintf(value, sizeof(value), "%d", shmid);
    setenv("__AFL_SHM_ID", value, 1);
    snprintf(value, sizeof(value), "%zu", size);
    setenv("AFL_MAP_SIZE", value, 1);

    trace_buffer = buf;
    trace_buffer_size = size;

    // Notify the host we are done booting. This is not the snapshot point; that
    // is set up in bedrock_get_fuzz_input().
    vmcall_ready();
    return AGENT_INPUT_CAPACITY;
}

/*
 * Copy the next fuzz input into `data` and return its size.
 *
 * Note: This will take the snapshot on the first call.
 */
size_t bedrock_get_fuzz_input(uint8_t *data, size_t max_size)
{
    // Register the fuzz input buffer before the snapshot is taken.
    void *buf = mmap(NULL, AGENT_BUF_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED)
        bedrock_abort("mmap of input buffer failed");
    if (mlock(buf, AGENT_BUF_SIZE) != 0)
        bedrock_abort("mlock of input buffer failed");
    memset(buf, 0, AGENT_BUF_SIZE);

    vmcall_u64 slot = vmcall_register_fuzz_input_buffer(buf, AGENT_BUF_SIZE);
    abort_on_registration_error(slot, "input buffer registration failed");

    g_header = buf;
    g_payload = (uint8_t *)buf + VMCALL_FUZZ_INPUT_HEADER_LEN;

    // Zero the trace buffer so setup coverage isn't included. This is racy
    // and may still include setup coverage from before the checkpoint.
    memset(trace_buffer, 0, trace_buffer_size);

    // This takes the snapshot on the first call.
    vmcall_fuzz_next_input();

    trace_buffer[0] = 1;

    uint64_t len = g_header->result;
    if (len > AGENT_INPUT_CAPACITY)
        bedrock_abort("host supplied an out-of-range input length");

    size_t n = (size_t)len;
    if (n > max_size)
        n = max_size;
    memcpy(data, g_payload, n);
    return n;
}

/* Record an outcome for the testcase just run, then hand control to the host. */
static void bedrock_report(uint64_t status)
{
	g_header->status = status;
	vmcall_fuzz_next_input();
}

/* Report that the harness detected a bug, with a message for the fuzzer. */
void bedrock_fail(const char *message)
{
    size_t len = message ? strlen(message) : 0;
    if (len > AGENT_INPUT_CAPACITY)
        len = AGENT_INPUT_CAPACITY;
    if (len)
        memcpy(g_payload, message, len);
    g_header->aux = len;
    bedrock_report(VMCALL_FUZZ_STATUS_FAIL);
}

/* Report that this testcase was unusable and should not be counted. */
void bedrock_skip(void)
{
    // TODO: this is racy, we should stop the target from writing to the trace
    // buffer before resetting it.
    memset(trace_buffer, 0, trace_buffer_size);
    trace_buffer[0] = 1;
    bedrock_report(VMCALL_FUZZ_STATUS_SKIP);
}

/* Report that this testcase completed cleanly. */
void bedrock_release(void)
{
	bedrock_report(VMCALL_FUZZ_STATUS_OK);
}

/*
 * Hand a file to the host via HYPERCALL_FILE_STORE by using a feedback buffer.
 */
void bedrock_dump_file_to_host(const char *name, size_t name_len,
			      const unsigned char *data, size_t len)
{
    // We only need to use one feedback buffer as the data is chunked.
    static uint8_t *store_buf;

    if (store_buf == NULL) {
        void *buf = mmap(NULL, STORE_BUF_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED || mlock(buf, STORE_BUF_SIZE) != 0) {
            bedrock_abort("store buffer mapping failed");
        }
        memset(buf, 0, STORE_BUF_SIZE);

        // On the stack, not .rodata: the hypervisor can't fault in the id's page.
        char id[sizeof(VMCALL_FILE_STORE_BUFFER_ID)];
        memcpy(id, VMCALL_FILE_STORE_BUFFER_ID, sizeof(id));

        vmcall_u64 slot = vmcall_register_feedback_buffer(
                buf, STORE_BUF_SIZE, id, sizeof(id) - 1);
        if (slot >= VMCALL_ERR - 4ULL) {
            bedrock_abort("store buffer registration failed");
        }
        store_buf = buf;
    }

    const size_t header = VMCALL_FILE_STORE_HEADER_LEN;
    if (name_len > STORE_BUF_SIZE - header)
        bedrock_abort("file name too large to send in store buffer");

    const size_t chunk_cap = STORE_BUF_SIZE - header - name_len;

    size_t sent = 0;
    do {
        size_t chunk = len - sent;
        if (chunk > chunk_cap)
            chunk = chunk_cap;

        uint32_t nl = (uint32_t)name_len;
        uint32_t cl = (uint32_t)chunk;
        memcpy(store_buf + 0, &nl, sizeof(nl));
        memcpy(store_buf + 4, &cl, sizeof(cl));
        memset(store_buf + 8, 0, 8);
        memcpy(store_buf + header, name, name_len);
        memcpy(store_buf + header + name_len, data + sent, chunk);

        vmcall_file_store();

        int64_t result;
        memcpy(&result, store_buf, sizeof(result));
        if (result < 0)
            bedrock_abort("host failed to read chunk");

        sent += chunk;
    } while (sent < len);
}
