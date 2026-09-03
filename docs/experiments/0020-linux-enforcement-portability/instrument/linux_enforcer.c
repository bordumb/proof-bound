#define _GNU_SOURCE

#include <errno.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

static const unsigned long long read_access =
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
static const unsigned long long write_access =
    LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
    LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;

static void fail(const char *stage) {
    fprintf(stderr, "%s: %s\n", stage, strerror(errno));
    exit(125);
}

static int create_ruleset(void) {
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 4) {
        errno = ENOTSUP;
        fail("landlock-abi");
    }
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = read_access | write_access |
                             LANDLOCK_ACCESS_FS_EXECUTE,
    };
    int fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (fd < 0) fail("landlock-create");
    return fd;
}

static void allow_path(int ruleset, const char *path,
                       unsigned long long access) {
    int parent = open(path, O_PATH | O_CLOEXEC);
    if (parent < 0) fail("landlock-open-path");
    struct landlock_path_beneath_attr rule = {
        .allowed_access = access,
        .parent_fd = parent,
    };
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH,
                &rule, 0) < 0) {
        close(parent);
        fail("landlock-add-rule");
    }
    close(parent);
}

static void install_landlock(const char *runtime, const char *source,
                             const char *input, const char *ephemeral) {
    int ruleset = create_ruleset();
    const char *system_roots[] = {
        "/dev", "/etc", "/lib", "/proc", "/sys", "/usr",
    };
    for (size_t i = 0; i < sizeof(system_roots) / sizeof(system_roots[0]); i++)
        allow_path(ruleset, system_roots[i], read_access);
    allow_path(ruleset, source, LANDLOCK_ACCESS_FS_READ_FILE);
    allow_path(ruleset, input, LANDLOCK_ACCESS_FS_READ_FILE);
    allow_path(ruleset, runtime,
               LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE);
    allow_path(ruleset, ephemeral, read_access | write_access);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        fail("no-new-privileges");
    if (syscall(SYS_landlock_restrict_self, ruleset, 0) < 0)
        fail("landlock-restrict");
    close(ruleset);
}

static void install_seccomp(void) {
#if defined(__aarch64__)
    const unsigned int expected_arch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
    const unsigned int expected_arch = AUDIT_ARCH_X86_64;
#else
#error unsupported architecture
#endif
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, expected_arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socketpair, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept4, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog programme = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &programme) < 0)
        fail("seccomp-install");
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--probe") == 0) {
        int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                          LANDLOCK_CREATE_RULESET_VERSION);
        if (abi < 0) fail("landlock-probe");
#if defined(__aarch64__)
        const char *architecture = "aarch64";
#elif defined(__x86_64__)
        const char *architecture = "x86_64";
#else
        const char *architecture = "unsupported";
#endif
        printf("linux-enforcer/1 architecture=%s landlock-abi=%d\n",
               architecture, abi);
        return abi >= 4 ? 0 : 125;
    }
    if (argc < 7) {
        fprintf(stderr,
                "usage: linux-enforcer RUNTIME SOURCE INPUT EPHEMERAL "
                "ARG...\n");
        return 125;
    }
    const char *runtime = argv[1];
    const char *source = argv[2];
    const char *input = argv[3];
    const char *ephemeral = argv[4];
    install_landlock(runtime, source, input, ephemeral);
    install_seccomp();
    if (clearenv() != 0 || setenv("PB_REGISTERED_VALUE", "registered-env", 1) != 0)
        fail("environment");
    execv(runtime, &argv[5]);
    fail("runtime-exec");
    return 125;
}
