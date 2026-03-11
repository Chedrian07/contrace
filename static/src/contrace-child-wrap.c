#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void die(const char *message) {
  perror(message);
  exit(111);
}

static long parse_long(const char *text, long fallback) {
  if (text == NULL || *text == '\0') {
    return fallback;
  }
  char *end = NULL;
  long value = strtol(text, &end, 10);
  if (end == NULL || *end != '\0') {
    fprintf(stderr, "invalid integer: %s\n", text);
    exit(111);
  }
  return value;
}

static void write_pid_file(const char *path, pid_t pid) {
  if (path == NULL || *path == '\0') {
    return;
  }
  int fd = open(path, O_WRONLY | O_TRUNC | O_CREAT, 0666);
  if (fd < 0) {
    return;
  }
  char buffer[64];
  int length = snprintf(buffer, sizeof(buffer), "%ld\n", (long)pid);
  if (length > 0) {
    (void)write(fd, buffer, (size_t)length);
  }
  close(fd);
}

static int confirm_attach(const char *path, pid_t pid) {
  if (path == NULL || *path == '\0') {
    return 1;
  }

  FILE *handle = fopen(path, "r");
  if (handle == NULL) {
    return 0;
  }

  char buffer[64] = {0};
  if (fgets(buffer, sizeof(buffer), handle) == NULL) {
    fclose(handle);
    return 0;
  }
  fclose(handle);

  long current = parse_long(buffer, -1);
  return current == (long)pid;
}

int main(void) {
  const char *target = getenv("CONTRACE_EXEC_TARGET");
  if (target == NULL || *target == '\0') {
    fprintf(stderr, "[contrace] child wrapper missing CONTRACE_EXEC_TARGET\n");
    return 111;
  }

  pid_t pid = getpid();
  write_pid_file("/run/contrace/last-child.pid", pid);

  long wait_secs = parse_long(getenv("CONTRACE_ATTACH_WAIT_SECS"), 0);
  const char *confirm_path = getenv("CONTRACE_ATTACH_CONFIRM_FILE");
  for (long i = 0; i < wait_secs; i++) {
    if (confirm_attach(confirm_path, pid)) {
      break;
    }
    sleep(1);
  }

  char *const argv[] = {(char *)target, NULL};
  execve(target, argv, environ);
  die("execve");
  return 111;
}
