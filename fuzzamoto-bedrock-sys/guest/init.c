#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libvmcall.h"

// Where the scenario and the node live in the initramfs.
#define SCENARIO_PATH "/scenario"
#define BITCOIND_PATH "/bitcoind"

static void die(const char *reason)
{
    // Best-effort, the console may not be up yet.
    fprintf(stderr, "init: %s failed: %s\n", reason, strerror(errno));
    fflush(stderr);
    vmcall_shutdown();
}

static void mount_one(const char *src, const char *dst, const char *fs, const char *opts)
{
    (void)mkdir(dst, 0755);
    if (mount(src, dst, fs, 0, opts) != 0)
        die(dst);
}

static void loopback_up(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        die("socket");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0)
        die("SIOCGIFFLAGS");

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0)
        die("SIOCSIFFLAGS");

    close(fd);
}

int main(void)
{
    mount_one("proc", "/proc", "proc", NULL);
    mount_one("sysfs", "/sys", "sysfs", NULL);
    mount_one("devtmpfs", "/dev", "devtmpfs", NULL);
    // The node's datadir goes here.
    mount_one("tmpfs", "/tmp", "tmpfs", "size=2G");
    // Where the coverage bitmap will live.
    mount_one("tmpfs", "/bedrock", "tmpfs", "size=16M");
    if (mkdir("/bedrock/coverage", 0755) != 0)
        die("mkdir /bedrock/coverage");

    loopback_up();

    char *argv[] = { (char *)SCENARIO_PATH, (char *)BITCOIND_PATH, NULL };
    char *envp[] = {
        (char *)"HOME=/tmp",
        (char *)"TMPDIR=/tmp",
        (char *)"PATH=/",
        (char *)"RUST_LOG=info",
        (char *)"ASAN_OPTIONS=detect_leaks=1:detect_stack_use_after_return=1:"
            "check_initialization_order=1:strict_init_order=1:"
            "abort_on_error=1:handle_abort=1",
        NULL,
    };
    execve(SCENARIO_PATH, argv, envp);
    die("execve " SCENARIO_PATH);
    return 1;
}
