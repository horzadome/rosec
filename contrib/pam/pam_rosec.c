/*
 * pam_rosec.c — PAM module for unlocking rosec providers on login/screen-unlock.
 *
 * This module stashes the user's password during the `auth` phase and
 * replays it to `rosec-pam-unlock` during the `session` phase.  This
 * allows rosec vaults to be unlocked at initial login (where the session
 * bus becomes available between the two phases) and at screen unlock.
 *
 * The module follows the same pattern as pam_gnome_keyring.so:
 *   auth    phase: capture password via pam_get_item(PAM_AUTHTOK), stash it
 *   session phase: retrieve stash, fork/exec the unlock helper with password
 *                  on stdin, wait for exit
 *
 * SAFETY PROPERTIES:
 *
 *   1. CANNOT block login:
 *      - All entry points return PAM_SUCCESS or PAM_IGNORE on any failure.
 *      - Never returns PAM_AUTH_ERR, PAM_SERVICE_ERR, or any error that
 *        would cause a login/unlock failure.
 *      - The PAM config line uses `optional`, providing defence-in-depth.
 *
 *   2. Password security:
 *      - Password is zeroized with explicit_bzero() + volatile barrier
 *        before free() in the cleanup callback.
 *      - Password never logged to syslog (only opaque status messages).
 *      - Password passed to helper via pipe stdin, never argv or env.
 *      - Pipe write-end closed immediately after write, signalling EOF.
 *
 *   3. Fork/exec safety:
 *      - Child closes all fds > STDERR before exec.
 *      - Child uses _exit() on error (not exit()) to avoid running atexit
 *        handlers from the parent.
 *      - SIGPIPE ignored during the fork/write/wait window.
 *      - SIGCHLD set to SIG_DFL so waitpid() works correctly.
 *      - Parent waits for child to prevent zombies.
 *
 *   4. Memory safety:
 *      - No unbounded allocations — only one strdup of the password.
 *      - All pipe fds tracked and closed on every exit path.
 *      - No buffer overflows — strlen-bounded operations only.
 *
 * Build:
 *   cc -shared -fPIC -O2 -Wall -Wextra -o pam_rosec.so pam_rosec.c -lpam
 *
 * Install:
 *   install -m755 pam_rosec.so /usr/lib/security/
 *
 * PAM config (/etc/pam.d/system-login or screen locker):
 *   auth     optional  pam_rosec.so
 *   session  optional  pam_rosec.so
 *
 * Copyright (c) 2025 rosec contributors.  MIT license.
 */

#define _GNU_SOURCE  /* for explicit_bzero */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* ── Configuration ────────────────────────────────────────────────── */

/*
 * Path to the rosec-pam-unlock binary.  This binary reads a password
 * from stdin (null-terminated), connects to rosecd over D-Bus, and
 * attempts to unlock all locked providers via pipe fd-passing.
 *
 * Override at compile time:
 *   cc -DROSEC_PAM_UNLOCK_PATH='"/custom/path"' ...
 */
#ifndef ROSEC_PAM_UNLOCK_PATH
#define ROSEC_PAM_UNLOCK_PATH "/usr/lib/rosec/rosec-pam-unlock"
#endif

/* Key for pam_set_data / pam_get_data stash */
#define STASH_KEY "rosec_pam_authtok"

/* Timeout for the helper process (seconds).  If exceeded, the helper
 * is killed and we return PAM_IGNORE. */
#define HELPER_TIMEOUT_SECS 10

/* ── Password zeroization ─────────────────────────────────────────── */

/*
 * Zeroize and free a password string.  Uses explicit_bzero (which the
 * compiler cannot elide) plus a volatile read barrier for defence in
 * depth against aggressive LTO.
 */
static void
zeroize_free(char *password)
{
    size_t len;
    volatile char *vp;

    if (!password)
        return;

    len = strlen(password);

    /* Primary: compiler-guaranteed zeroing */
    explicit_bzero(password, len);

    /* Secondary: volatile read barrier defeats any residual
     * optimisation that might skip the bzero. */
    vp = (volatile char *)password;
    while (len--)
        (void)*vp++;

    free(password);
}

/*
 * pam_set_data cleanup callback.  PAM calls this when the stash is
 * overwritten or when pam_end() runs (end of PAM transaction).
 */
static void
cleanup_stash(pam_handle_t *ph, void *data, int pam_end_status)
{
    (void)ph;
    (void)pam_end_status;
    zeroize_free((char *)data);
}

/* ── Pipe helper ──────────────────────────────────────────────────── */

static void
close_safe(int fd)
{
    if (fd >= 0)
        close(fd);
}

/*
 * Write `data` (with a trailing NUL, matching pam_exec expose_authtok
 * protocol) to the write end of a pipe and close it.  Returns 0 on
 * success, -1 on failure (write-end is always closed regardless).
 */
static int
write_password_to_pipe(int write_fd, const char *password)
{
    size_t len = strlen(password);
    const char nul = '\0';
    ssize_t written;

    /* Write the password bytes */
    while (len > 0) {
        written = write(write_fd, password, len);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            close(write_fd);
            return -1;
        }
        password += written;
        len -= (size_t)written;
    }

    /* Write trailing NUL (pam_exec convention) */
    while ((written = write(write_fd, &nul, 1)) < 0 && errno == EINTR)
        ;

    close(write_fd);
    return (written == 1) ? 0 : -1;
}

/* ── Fork/exec the unlock helper ──────────────────────────────────── */

/*
 * Fork rosec-pam-unlock, pass the password on its stdin via pipe,
 * wait for it to exit.  Returns 0 if the helper exited successfully,
 * -1 otherwise.  All failures are silent — this function NEVER causes
 * a login failure.
 */
static int
run_unlock_helper(const char *password)
{
    int pipe_fds[2] = { -1, -1 };
    pid_t pid;
    int status;
    struct sigaction sa_ign, sa_def, sa_old_pipe, sa_old_chld;

    if (pipe(pipe_fds) < 0)
        return -1;

    /*
     * Ignore SIGPIPE so writing to a broken pipe doesn't kill the
     * login process.  Set SIGCHLD to SIG_DFL so waitpid works.
     */
    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    sigaction(SIGPIPE, &sa_ign, &sa_old_pipe);

    memset(&sa_def, 0, sizeof(sa_def));
    sa_def.sa_handler = SIG_DFL;
    sigemptyset(&sa_def.sa_mask);
    sigaction(SIGCHLD, &sa_def, &sa_old_chld);

    pid = fork();

    if (pid < 0) {
        /* Fork failed */
        close_safe(pipe_fds[0]);
        close_safe(pipe_fds[1]);
        sigaction(SIGPIPE, &sa_old_pipe, NULL);
        sigaction(SIGCHLD, &sa_old_chld, NULL);
        return -1;
    }

    if (pid == 0) {
        /* ── Child process ──────────────────────────────────────── */

        /* Restore default signal handlers */
        signal(SIGPIPE, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        /* Redirect pipe read-end to stdin */
        if (dup2(pipe_fds[0], STDIN_FILENO) < 0)
            _exit(1);

        /* Close all fds above stderr.  This prevents leaking parent
         * fds (D-Bus sockets, log files, etc.) into the helper. */
        for (int fd = STDERR_FILENO + 1; fd < 1024; fd++)
            close(fd);

        /* Redirect stdout/stderr to /dev/null.  The helper should
         * never produce visible output — all communication is via
         * exit code and D-Bus. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO)
                close(devnull);
        }

        /*
         * Exec the helper.  argv[0] is the binary name, no other args.
         * Environment is inherited from the PAM caller (contains
         * DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR, etc.).
         */
        execl(ROSEC_PAM_UNLOCK_PATH, "rosec-pam-unlock", (char *)NULL);

        /* exec failed — _exit (not exit) to avoid atexit handlers */
        _exit(127);
    }

    /* ── Parent process ─────────────────────────────────────────── */

    /* Close the read end — only the child reads from the pipe */
    close_safe(pipe_fds[0]);
    pipe_fds[0] = -1;

    /* Write the password and close the write end */
    write_password_to_pipe(pipe_fds[1], password);
    pipe_fds[1] = -1;  /* already closed by write_password_to_pipe */

    /* Wait for the child with a timeout to prevent hanging login */
    {
        int elapsed = 0;
        int waited = 0;

        while (elapsed < HELPER_TIMEOUT_SECS) {
            pid_t ret = waitpid(pid, &status, WNOHANG);
            if (ret == pid) {
                waited = 1;
                break;
            }
            if (ret < 0 && errno != EINTR) {
                waited = 0;
                break;
            }
            /* Sleep 100ms between polls */
            usleep(100000);
            elapsed++;  /* ~100ms granularity, close enough */
        }

        if (!waited) {
            /* Timeout or waitpid error — kill the child and reap */
            kill(pid, SIGTERM);
            usleep(50000);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }
    }

    /* Restore original signal handlers */
    sigaction(SIGPIPE, &sa_old_pipe, NULL);
    sigaction(SIGCHLD, &sa_old_chld, NULL);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;

    return -1;
}

/* ── PAM entry points ─────────────────────────────────────────────── */

/*
 * pam_sm_authenticate — `auth` phase.
 *
 * Capture the password from PAM_AUTHTOK (set by pam_unix or prior
 * modules) and stash a zeroize-on-cleanup copy for the session phase.
 *
 * ALWAYS returns PAM_SUCCESS or PAM_IGNORE — never blocks login.
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    const char *password = NULL;
    char *stash = NULL;
    int ret;

    (void)flags;
    (void)argc;
    (void)argv;

    syslog(LOG_DEBUG, "pam_rosec: auth phase entered");

    /* Get the password that was set by an earlier auth module
     * (typically pam_unix).  If no password is available, that's fine
     * — we just won't be able to unlock anything. */
    ret = pam_get_item(ph, PAM_AUTHTOK, (const void **)&password);
    if (ret != PAM_SUCCESS || password == NULL || password[0] == '\0') {
        syslog(LOG_DEBUG, "pam_rosec: auth phase — no password available (ret=%d, null=%d)",
               ret, password == NULL);
        return PAM_SUCCESS;
    }

    syslog(LOG_DEBUG, "pam_rosec: auth phase — got password, stashing");

    /* Stash a copy.  The cleanup callback zeroizes + frees it when
     * the PAM transaction ends or the data is overwritten. */
    stash = strdup(password);
    if (!stash) {
        syslog(LOG_ERR, "pam_rosec: out of memory");
        return PAM_SUCCESS;  /* still don't block login */
    }

    ret = pam_set_data(ph, STASH_KEY, stash, cleanup_stash);
    if (ret != PAM_SUCCESS) {
        zeroize_free(stash);
        syslog(LOG_ERR, "pam_rosec: failed to stash password");
        return PAM_SUCCESS;
    }

    syslog(LOG_DEBUG, "pam_rosec: auth phase — password stashed OK");
    return PAM_SUCCESS;
}

/*
 * pam_sm_setcred — required by PAM but we have nothing to do.
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    (void)ph;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

/*
 * pam_sm_open_session — `session` phase.
 *
 * Retrieve the stashed password and pass it to rosec-pam-unlock.
 * By the time the session phase runs, the D-Bus session bus is
 * available (pam_systemd has set it up) and rosecd can be reached.
 *
 * ALWAYS returns PAM_SUCCESS or PAM_IGNORE — never blocks login.
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    const char *password = NULL;
    int ret;

    (void)flags;
    (void)argc;
    (void)argv;

    syslog(LOG_DEBUG, "pam_rosec: session phase entered");

    /* Retrieve the stashed password from the auth phase */
    ret = pam_get_data(ph, STASH_KEY, (const void **)&password);
    if (ret != PAM_SUCCESS || password == NULL || password[0] == '\0') {
        syslog(LOG_DEBUG, "pam_rosec: session phase — no stashed password (ret=%d, null=%d)",
               ret, password == NULL);
        return PAM_SUCCESS;
    }

    syslog(LOG_DEBUG, "pam_rosec: session phase — got stashed password, running helper");

    /* Run the unlock helper.  Failure is non-fatal. */
    ret = run_unlock_helper(password);

    if (ret == 0) {
        syslog(LOG_INFO, "pam_rosec: unlocked providers");
    } else {
        syslog(LOG_DEBUG, "pam_rosec: session phase — helper returned %d", ret);
    }

    /*
     * Clear the stash.  The cleanup callback zeroizes the old copy.
     * Passing NULL data with NULL cleanup removes the entry.
     */
    pam_set_data(ph, STASH_KEY, NULL, NULL);

    return PAM_SUCCESS;
}

/*
 * pam_sm_close_session — required by PAM but nothing to do.
 */
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    (void)ph;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
