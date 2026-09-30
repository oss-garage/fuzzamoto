/// Preloaded crash handler for nyx based fuzzing. Detects aborts, asserts and
/// other crashes in the target application and reports them to nyx (if
/// configured to do so).
///
/// The following ASan options are required, if the target is compiled for ASan:
/// - `log_path=<path>`: ASan will write errors to the specified log file.
/// - `abort_on_error=1`: ASan will call abort() on errors.
///
/// Compile-time options:
/// - -DCATCH_SIGNALS: Catch signals and print a backtrace. Do not use this when
///   compiling with sanitizers (e.g. ASan), as they provide their own signal
///   handlers.
/// - -DENABLE_NYX: Use nyx hypercalls to let nyx know that a crash has occured.
/// - -DCUSTOM_BACKTRACE: Enable custom backtrace.
///
/// Example instructions for compiling the crash handler for use with an ASan
/// compiled target:
/// ```
/// gcc -DENABLE_NYX -o nyx-crash-handler.so
/// -shared -fPIC nyx-crash-handler.c
/// ```

#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef ENABLE_NYX
#include "nyx.h"
#endif

#define SAN_LOG_PATH "/tmp/san.log"
#define MAX_CUSTOM_BACKTRACE_SIZE 50

static char *log = NULL;
static size_t log_size = 0;

// Append to the log, reallocate if necessary
void append_log(const char *msg) {
  if (log == NULL) {
    log_size = 0x10000;
    log = (char *)malloc(log_size);
    memset(log, 0, log_size);
  } else {
    size_t needed_size =
        strlen(log) + strlen(msg) + 1; // +1 for null terminator
    while (log_size < needed_size) {
      log_size *= 2;
    }
    log = (char *)realloc(log, log_size);
  }

  strcat(log, msg);
}

// Fetch the sanitizer log from the log file and append it to the global log
void append_san_log() {
  char *log_file_path = NULL;
  asprintf(&log_file_path, "%s.%d", SAN_LOG_PATH, getpid());

  FILE *file = fopen(log_file_path, "r");
  free(log_file_path);

  if (file == NULL) {
    return;
  }

  char buffer[0x100000];
  size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
  fclose(file);

  if (bytes_read == 0) {
    return;
  }

  buffer[bytes_read] = '\0';
  append_log(buffer);
}

extern void _exit(int);

#ifdef ENABLE_NYX
#define LOG(...) hprintf(__VA_ARGS__)
#else
#define LOG(...) printf(__VA_ARGS__)
#endif

#define EXIT_WITH_LOG()                                                     \
  do {                                                                         \
    LOG("%s\n", log);                                                          \
    _exit(1);                                                                  \
  } while (0)

#ifdef ENABLE_NYX

#define PANIC_WITH_LOG()                                                    \
  do {                                                                         \
    kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log);             \
    while (1) {                                                                \
    }                                                                          \
  } while (0)

#else

#define PANIC_WITH_LOG() EXIT_WITH_LOG()

#endif

void panic_with_backtrace(const char *extra_msg) {
  append_san_log();

#ifdef CUSTOM_BACKTRACE
  char custom_backtrace[0x10000];
  memset(custom_backtrace, 0, 0x10000);

  void *backtrace_buffer[MAX_CUSTOM_BACKTRACE_SIZE];
  int backtrace_size = backtrace(backtrace_buffer, MAX_CUSTOM_BACKTRACE_SIZE);

  char **symbolized_backtrace =
      backtrace_symbols(backtrace_buffer, backtrace_size);

  char *current = custom_backtrace;
  current += sprintf(current, "%s\n", "====== BACKTRACE ======");

  if (backtrace_size == MAX_CUSTOM_BACKTRACE_SIZE) {
    current += sprintf(current, "(%s)\n", "backtrace may be truncated");
  }

  if (extra_msg != NULL) {
    current += sprintf(current, "Reason: %s\n", extra_msg);
  }

  for (int i = 0; i < backtrace_size; ++i) {
    current += sprintf(current, "%s\n", symbolized_backtrace[i]);
  }

  append_log(custom_backtrace);
#endif

  PANIC_WITH_LOG();
}

#define OVERRIDE_ABORT(abort_name)                                             \
  void abort_name(void) {                                                      \
    panic_with_backtrace("abort");                                             \
    while (1) {                                                                \
    }                                                                          \
  }

OVERRIDE_ABORT(abort)
OVERRIDE_ABORT(_abort)
OVERRIDE_ABORT(__abort)

void __assert(const char *func, const char *file, int line,
              const char *failed_expr) {
  char signal_msg[0x1000];
  memset(signal_msg, 0, 0x1000);
  sprintf(signal_msg, "assertion failed: \"%s\" in %s (%s:%d)", failed_expr,
          func, file, line);
  panic_with_backtrace(signal_msg);
}
void __assert_fail(const char *assertion, const char *file, unsigned int line,
                   const char *function) {
  char signal_msg[0x1000];
  memset(signal_msg, 0, 0x1000);
  sprintf(signal_msg, "assertion failed: \"%s\" in %s (%s:%d)", assertion,
          function, file, line);
  panic_with_backtrace(signal_msg);
}
void __assert_perror_fail(int errnum, const char *file, unsigned int line,
                          const char *function) {
  char signal_msg[0x1000];
  memset(signal_msg, 0, 0x1000);
  sprintf(signal_msg, "assert_perror: in %s (%s:%d)", function, file, line);
  panic_with_backtrace(signal_msg);
}

#ifdef CATCH_SIGNALS

int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact) {
  int (*_sigaction)(int signum, const struct sigaction *act,
                    struct sigaction *oldact) = dlsym(RTLD_NEXT, "sigaction");

  switch (signum) {
  /* forbidden signals */
  case SIGFPE:
  case SIGILL:
  case SIGBUS:
  case SIGABRT:
  case SIGTRAP:
  case SIGSYS:
  case SIGSEGV:
    LOG("[warning] Target attempts to install own SIG: %d handler (ignoring)\n",
        signum);
    return 0;
  default:
    return _sigaction(signum, act, oldact);
  }
}

void fault_handler(int signo, siginfo_t *info, void *extra) {
  char signal_msg[0x1000];
  memset(signal_msg, 0, 0x1000);
  sprintf(signal_msg, "caught signal: %d\n", signo);

  panic_with_backtrace(signal_msg);
}

void initialize_crash_handling() {
  struct sigaction action;
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = fault_handler;

  // We need to call the actual `sigaction` to register our handlers.
  int (*_sigaction)(int signum, const struct sigaction *act,
                    struct sigaction *oldact) = dlsym(RTLD_NEXT, "sigaction");

  struct {
    int signal;
    const char *name;
  } signals[] = {{SIGSEGV, "sigsegv"}, {SIGFPE, "sigfpe"},   {SIGBUS, "sigbus"},
                 {SIGILL, "sigill"},   {SIGABRT, "sigabrt"}, {SIGIOT, "sigiot"},
                 {SIGTRAP, "sigtrap"}, {SIGSYS, "sigsys"},   {0, NULL}};

  for (int i = 0; signals[i].signal != 0; i++) {
    if (_sigaction(signals[i].signal, &action, NULL) == -1) {
      char signal_msg[0x10000];
      memset(signal_msg, 0, 0x10000);
      snprintf(signal_msg, 0x10000,
               "Failed to register signal handler for signal %s (%d): %s\n",
               signals[i].name, signals[i].signal, strerror(errno));

      append_log(signal_msg);
      EXIT_WITH_LOG();
    }
  }

  LOG("[info] All signal handlers installed!\n");
}
#else
void initialize_crash_handling() {}
#endif

__attribute__((constructor)) void init_handler(void) {
  LOG("[info] Initializing crash handler...\n");
  initialize_crash_handling();
  LOG("[info] Crash handler initialized!\n");
}
