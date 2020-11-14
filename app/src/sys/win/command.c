#include "command.h"

#include <sys/stat.h>

#include "config.h"
#include "util/log.h"
#include "util/str_util.h"

static int
build_cmd(char *cmd, size_t len, const char *const argv[]) {
    // Windows command-line parsing is WTF:
    // <http://daviddeley.com/autohotkey/parameters/parameters.htm#WINPASS>
    // only make it work for this very specific program
    // (don't handle escaping nor quotes)
    size_t ret = xstrjoin(cmd, argv, ' ', len);
    if (ret >= len) {
        LOGE("Command too long (%" PRIsizet " chars)", len - 1);
        return -1;
    }
    return 0;
}

enum process_result
cmd_execute_redirect(const char *const argv[], HANDLE *handle,
                     HANDLE *pipe_stdin, HANDLE *pipe_stdout,
                     HANDLE *pipe_stderr) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE stdin_read_handle;
    HANDLE stdout_write_handle;
    HANDLE stderr_write_handle;
    if (pipe_stdin) {
        if (!CreatePipe(&stdin_read_handle, pipe_stdin, &sa, 0)) {
            perror("pipe");
            return PROCESS_ERROR_GENERIC;
        }
    }
    if (pipe_stdout) {
        if (!CreatePipe(pipe_stdout, &stdout_write_handle, &sa, 0)) {
            perror("pipe");
            // clean up
            if (pipe_stdin) {
               CloseHandle(&stdin_read_handle);
               CloseHandle(pipe_stdin);
            }
            return PROCESS_ERROR_GENERIC;
        }
    }
    if (pipe_stderr) {
        if (!CreatePipe(pipe_stderr, &stderr_write_handle, &sa, 0)) {
            perror("pipe");
            // clean up
            if (pipe_stdin) {
                CloseHandle(&stdin_read_handle);
                CloseHandle(pipe_stdin);
            }
            if (pipe_stdout) {
                CloseHandle(pipe_stdout);
                CloseHandle(&stdout_write_handle);
            }
            return PROCESS_ERROR_GENERIC;
        }
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (pipe_stdin || pipe_stdout || pipe_stderr) {
        si.dwFlags = STARTF_USESTDHANDLES;
        if (pipe_stdin) {
            si.hStdInput = stdin_read_handle;
        }
        if (pipe_stdout) {
            si.hStdOutput = stdout_write_handle;
        }
        if (pipe_stderr) {
            si.hStdError = stderr_write_handle;
        }
    }

    char cmd[256];
    if (build_cmd(cmd, sizeof(cmd), argv)) {
        *handle = NULL;
        return PROCESS_ERROR_GENERIC;
    }

    wchar_t *wide = utf8_to_wide_char(cmd);
    if (!wide) {
        LOGC("Could not allocate wide char string");
        return PROCESS_ERROR_GENERIC;
    }

#ifdef WINDOWS_NOCONSOLE
    int flags = CREATE_NO_WINDOW;
#else
    int flags = 0;
#endif
    if (!CreateProcessW(NULL, wide, NULL, NULL, FALSE, flags, NULL, NULL, &si,
                        &pi)) {
        SDL_free(wide);
        *handle = NULL;
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            return PROCESS_ERROR_MISSING_BINARY;
        }
        return PROCESS_ERROR_GENERIC;
    }

    SDL_free(wide);
    *handle = pi.hProcess;
    return PROCESS_SUCCESS;
}

enum process_result
cmd_execute(const char *const argv[], HANDLE *handle) {
    return cmd_execute_redirect(argv, handle, NULL, NULL, NULL);
}

bool
cmd_terminate(HANDLE handle) {
    return TerminateProcess(handle, 1) && CloseHandle(handle);
}

bool
cmd_simple_wait(HANDLE handle, DWORD *exit_code) {
    DWORD code;
    if (WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0
            || !GetExitCodeProcess(handle, &code)) {
        // could not wait or retrieve the exit code
        code = -1; // max value, it's unsigned
    }
    if (exit_code) {
        *exit_code = code;
    }
    return !code;
}

char *
get_executable_path(void) {
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule) {
        return NULL;
    }
    WCHAR buf[MAX_PATH + 1]; // +1 for the null byte
    int len = GetModuleFileNameW(hModule, buf, MAX_PATH);
    if (!len) {
        return NULL;
    }
    buf[len] = '\0';
    return utf8_from_wide_char(buf);
}

bool
is_regular_file(const char *path) {
    wchar_t *wide_path = utf8_to_wide_char(path);
    if (!wide_path) {
        LOGC("Could not allocate wide char string");
        return false;
    }

    struct _stat path_stat;
    int r = _wstat(wide_path, &path_stat);
    SDL_free(wide_path);

    if (r) {
        perror("stat");
        return false;
    }
    return S_ISREG(path_stat.st_mode);
}

int
read_pipe(HANDLE pipe, char *data, size_t len) {
    DWORD r;
    if (!ReadFile(pipe, data, len, &r, NULL)) {
        return -1;
    }
    return r;
}

void
close_pipe(HANDLE pipe) {
    if (!CloseHandle(pipe)) {
        LOGW("Cannot close pipe");
    }
}
