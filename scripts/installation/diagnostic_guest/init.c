#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define DEBUGCON_PORT 0xE9
#define TOKEN_LENGTH 32
#define LINE_CAPACITY 192
#define INPUT_TIMEOUT_SECONDS 180
#define INVALID_LINE 0
#define VALID_LINE 1

static void debugcon_marker(char marker)
{
    outb((uint8_t)marker, DEBUGCON_PORT);
}

static int prepare_devtmpfs(void)
{
    if (mkdir("/dev", 0755) < 0 && errno != EEXIST) {
        return -1;
    }

    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") < 0 && errno != EBUSY) {
        struct stat tty1;
        struct stat serial;
        if (stat("/dev/tty1", &tty1) < 0 || stat("/dev/ttyS1", &serial) < 0) {
            return -1;
        }
    }
    return 0;
}

static int configure_keyboard_tty(int descriptor)
{
    struct termios settings;
    if (tcgetattr(descriptor, &settings) < 0) {
        return -1;
    }
    settings.c_lflag |= ICANON;
    settings.c_lflag &= ~(ECHO | ECHONL);
    settings.c_iflag |= ICRNL;
    settings.c_cc[VMIN] = 1;
    settings.c_cc[VTIME] = 0;
    return tcsetattr(descriptor, TCSANOW, &settings);
}

static int remaining_milliseconds(const struct timespec *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return -1;
    }
    long seconds = deadline->tv_sec - now.tv_sec;
    long nanoseconds = deadline->tv_nsec - now.tv_nsec;
    if (nanoseconds < 0) {
        seconds -= 1;
        nanoseconds += 1000000000L;
    }
    if (seconds < 0 || (seconds == 0 && nanoseconds <= 0)) {
        return 0;
    }
    long milliseconds = seconds * 1000 + nanoseconds / 1000000;
    return milliseconds > 2147483647L ? 2147483647 : (int)milliseconds;
}

static int read_line(int descriptor, char *line, size_t capacity)
{
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) < 0) {
        return INVALID_LINE;
    }
    deadline.tv_sec += INPUT_TIMEOUT_SECONDS;

    size_t length = 0;
    bool overflow = false;
    for (;;) {
        struct pollfd input = {.fd = descriptor, .events = POLLIN};
        int timeout = remaining_milliseconds(&deadline);
        if (timeout <= 0) {
            return INVALID_LINE;
        }
        int ready = poll(&input, 1, timeout);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0 || (input.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            return INVALID_LINE;
        }

        char character;
        ssize_t count = read(descriptor, &character, 1);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count != 1) {
            return INVALID_LINE;
        }
        if (character == '\n' || character == '\r') {
            if (overflow) {
                return INVALID_LINE;
            }
            line[length] = '\0';
            return VALID_LINE;
        }
        if ((unsigned char)character < 0x20 || (unsigned char)character > 0x7e
                || length + 1 >= capacity) {
            overflow = true;
            continue;
        }
        line[length++] = character;
    }
}

static bool is_hex_token(const char *token, bool allow_uppercase)
{
    if (strlen(token) != TOKEN_LENGTH) {
        return false;
    }
    for (size_t index = 0; index < TOKEN_LENGTH; index++) {
        unsigned char character = (unsigned char)token[index];
        if (!isdigit(character) && !(character >= 'a' && character <= 'f')
                && !(allow_uppercase && character >= 'A' && character <= 'F')) {
            return false;
        }
    }
    return true;
}

static bool token_is_fresh(const char *token, const char *first, const char *second)
{
    return (first == NULL || strcasecmp(token, first) != 0)
        && (second == NULL || strcasecmp(token, second) != 0);
}

static int write_all(int descriptor, const char *data, size_t length)
{
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(descriptor, data + written, length - written);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return -1;
        }
        written += (size_t)count;
    }
    return 0;
}

static int write_probe_record(int serial, const char *token)
{
    char record[TOKEN_LENGTH + 40];
    int length = snprintf(record, sizeof(record), "ATLASO-PROBE:%s:READY\n", token);
    if (length <= 0 || (size_t)length >= sizeof(record)) {
        return -1;
    }
    if (write_all(serial, record, (size_t)length) < 0) {
        return -1;
    }
    return tcdrain(serial);
}

static bool parse_production_command(const char *line, char *token)
{
    static const char prefix[] =
        "test -c /dev/ttyS1 && exec 3>/dev/ttyS1 && printf '%s\\n' ATLASO-PROBE:";
    static const char suffix[] = ":READY >&3";
    size_t prefix_length = sizeof(prefix) - 1;
    size_t suffix_length = sizeof(suffix) - 1;
    size_t length = strlen(line);
    if (length != prefix_length + TOKEN_LENGTH + suffix_length
            || strncmp(line, prefix, prefix_length) != 0
            || strcmp(line + length - suffix_length, suffix) != 0) {
        return false;
    }
    memcpy(token, line + prefix_length, TOKEN_LENGTH);
    token[TOKEN_LENGTH] = '\0';
    return is_hex_token(token, true);
}

static int run_production_command(const char *line)
{
    pid_t child = fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        execl("/bin/busybox", "busybox", "sh", "-c", line, (char *)NULL);
        _exit(127);
    }

    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

int main(void)
{
    if (prepare_devtmpfs() < 0) {
        _exit(1);
    }

    int keyboard = open("/dev/tty1", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (keyboard < 0 || configure_keyboard_tty(keyboard) < 0) {
        _exit(1);
    }

    if (ioperm(DEBUGCON_PORT, 1, 1) < 0) {
        _exit(1);
    }
    debugcon_marker('R');

    bool open_gate = false;
    char line[LINE_CAPACITY];
    for (unsigned int attempt = 0; attempt < 4 && !open_gate; attempt++) {
        open_gate = read_line(keyboard, line, sizeof(line)) == VALID_LINE && strcmp(line, "open") == 0;
    }
    if (!open_gate) {
        _exit(1);
    }

    int serial = open("/dev/ttyS1", O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (serial < 0) {
        _exit(1);
    }
    debugcon_marker('O');

    char tokens[2][TOKEN_LENGTH + 1];
    for (size_t challenge = 0; challenge < 2; challenge++) {
        bool accepted = false;
        for (unsigned int attempt = 0; attempt < 4 && !accepted; attempt++) {
            if (read_line(keyboard, line, sizeof(line)) != VALID_LINE
                    || !is_hex_token(line, false)
                    || !token_is_fresh(line, challenge == 0 ? NULL : tokens[0], NULL)) {
                continue;
            }
            memcpy(tokens[challenge], line, TOKEN_LENGTH + 1);
            if (write_probe_record(serial, tokens[challenge]) < 0) {
                _exit(1);
            }
            debugcon_marker(challenge == 0 ? 'W' : 'X');
            accepted = true;
        }
        if (!accepted) {
            _exit(1);
        }
    }

    bool command_accepted = false;
    for (unsigned int attempt = 0; attempt < 4 && !command_accepted; attempt++) {
        char command_token[TOKEN_LENGTH + 1];
        if (read_line(keyboard, line, sizeof(line)) != VALID_LINE
                || !parse_production_command(line, command_token)
                || !token_is_fresh(command_token, tokens[0], tokens[1])) {
            continue;
        }
        if (run_production_command(line) < 0 || tcdrain(serial) < 0) {
            _exit(1);
        }
        debugcon_marker('Y');
        command_accepted = true;
    }
    if (!command_accepted) {
        _exit(1);
    }

    for (;;) {
        pause();
    }
}
