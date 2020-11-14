// for portability (kill, readlink, strdup, strtok_r)
#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

// modern glibc will complain without this
#define _DEFAULT_SOURCE

#include "command.h"

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "util/log.h"

bool
cmd_search(const char *file) {
    char *path = getenv("PATH");
    if (!path)
        return false;
    path = strdup(path);
    if (!path)
        return false;

    bool ret = false;
    size_t file_len = strlen(file);
    char *saveptr;
    for (char *dir = strtok_r(path, ":", &saveptr); dir;
            dir = strtok_r(NULL, ":", &saveptr)) {
        size_t dir_len = strlen(dir);
        char *fullpath = malloc(dir_len + file_len + 2);
        if (!fullpath)
            continue;
        memcpy(fullpath, dir, dir_len);
        fullpath[dir_len] = '/';
        memcpy(fullpath + dir_len + 1, file, file_len + 1);

        struct stat sb;
        bool fullpath_executable = stat(fullpath, &sb) == 0 &&
            sb.st_mode & S_IXUSR;
        free(fullpath);
        if (fullpath_executable) {
            ret = true;
            break;
        }
    }

    free(path);
    return ret;
}

enum process_result
cmd_execute_redirect(const char *const argv[], pid_t *pid, int *pipe_stdin,
                     int *pipe_stdout, int *pipe_stderr) {
    int in[2];
    int out[2];
    int err[2];
    int internal[2]; // communication between parent and children

    if (pipe(internal) == -1) {
        perror("pipe");
        return PROCESS_ERROR_GENERIC;
    }
    if (pipe_stdin) {
        if (pipe(in) == -1) {
            perror("pipe");
            close(internal[0]);
            close(internal[1]);
            return PROCESS_ERROR_GENERIC;
        }
    }
    if (pipe_stdout) {
        if (pipe(out) == -1) {
            perror("pipe");
            // clean up
            if (pipe_stdin) {
                close(in[0]);
                close(in[1]);
            }
            close(internal[0]);
            close(internal[1]);
            return PROCESS_ERROR_GENERIC;
        }
    }
    if (pipe_stderr) {
        if (pipe(err) == -1) {
            perror("pipe");
            // clean up
            if (pipe_stdout) {
                close(out[0]);
                close(out[1]);
            }
            if (pipe_stdin) {
                close(in[0]);
                close(in[1]);
            }
            close(internal[0]);
            close(internal[1]);
            return PROCESS_ERROR_GENERIC;
        }
    }

    *pid = fork();
    if (*pid == -1) {
        perror("fork");
        // clean up
        if (pipe_stderr) {
            close(err[0]);
            close(err[1]);
        }
        if (pipe_stdout) {
            close(out[0]);
            close(out[1]);
        }
        if (pipe_stdin) {
            close(in[0]);
            close(in[1]);
        }
        close(internal[0]);
        close(internal[1]);
        return PROCESS_ERROR_GENERIC;
    }

    if (*pid == 0) {
        if (pipe_stdin) {
            if (in[0] != STDIN_FILENO) {
                dup2(in[0], STDIN_FILENO);
                close(in[0]);
            }
            close(in[1]);
        }
        if (pipe_stdout) {
            if (out[1] != STDOUT_FILENO) {
                dup2(out[1], STDOUT_FILENO);
                close(out[1]);
            }
            close(out[0]);
        }
        if (pipe_stderr) {
            if (err[1] != STDERR_FILENO) {
                dup2(err[1], STDERR_FILENO);
                close(err[1]);
            }
            close(err[0]);
        }
        close(internal[0]);
        enum process_result err;
        if (fcntl(internal[1], F_SETFD, FD_CLOEXEC) == 0) {
            execvp(argv[0], (char *const *) argv);
            perror("exec");
            err = errno == ENOENT ? PROCESS_ERROR_MISSING_BINARY
                                  : PROCESS_ERROR_GENERIC;
        } else {
            perror("fcntl");
            err = PROCESS_ERROR_GENERIC;
        }
        // send err to the parent
        if (write(internal[1], &err, sizeof(err)) == -1) {
            perror("write");
        }
        close(internal[1]);
        _exit(1);
    }

    // parent
    assert(*pid > 0);

    close(internal[1]);

    enum process_result res = PROCESS_SUCCESS;
    // wait for EOF or receive err from child
    if (read(internal[0], &res, sizeof(res)) == -1) {
        perror("read");
        res = PROCESS_ERROR_GENERIC;
    }

    close(internal[0]);

    if (pipe_stdin) {
        close(in[0]);
        *pipe_stdin = in[1];
    }
    if (pipe_stdout) {
        *pipe_stdout = out[0];
        close(out[1]);
    }
    if (pipe_stderr) {
        *pipe_stderr = err[0];
        close(err[1]);
    }

    return res;
}

enum process_result
cmd_execute(const char *const argv[], pid_t *pid) {
    return cmd_execute_redirect(argv, pid, NULL, NULL, NULL);
}

bool
cmd_terminate(pid_t pid) {
    if (pid <= 0) {
        LOGC("Requested to kill %d, this is an error. Please report the bug.\n",
             (int) pid);
        abort();
    }
    return kill(pid, SIGTERM) != -1;
}

bool
cmd_simple_wait(pid_t pid, int *exit_code) {
    int status;
    int code;
    if (waitpid(pid, &status, 0) == -1 || !WIFEXITED(status)) {
        // could not wait, or exited unexpectedly, probably by a signal
        code = -1;
    } else {
        code = WEXITSTATUS(status);
    }
    if (exit_code) {
        *exit_code = code;
    }
    return !code;
}

char *
get_executable_path(void) {
// <https://stackoverflow.com/a/1024937/1987178>
#ifdef __linux__
    char buf[PATH_MAX + 1]; // +1 for the null byte
    ssize_t len = readlink("/proc/self/exe", buf, PATH_MAX);
    if (len == -1) {
        perror("readlink");
        return NULL;
    }
    buf[len] = '\0';
    return SDL_strdup(buf);
#else
    // in practice, we only need this feature for portable builds, only used on
    // Windows, so we don't care implementing it for every platform
    // (it's useful to have a working version on Linux for debugging though)
    return NULL;
#endif
}

bool
is_regular_file(const char *path) {
    struct stat path_stat;

    if (stat(path, &path_stat)) {
        perror("stat");
        return false;
    }
    return S_ISREG(path_stat.st_mode);
}

int
read_pipe(int pipe, char *data, size_t len) {
    return read(pipe, data, len);
}

void
close_pipe(int pipe) {
    if (close(pipe)) {
        perror("close pipe");
    }
}
