#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static void die(const char *message) {
  perror(message);
  exit(111);
}

static long parse_long(const char *text) {
  char *end = NULL;
  long value = strtol(text, &end, 10);
  if (end == NULL || *end != '\0') {
    fprintf(stderr, "invalid integer: %s\n", text);
    exit(111);
  }
  return value;
}

static void apply_groups(const char *csv) {
  if (strcmp(csv, "-") == 0 || csv[0] == '\0') {
    if (setgroups(0, NULL) != 0) {
      die("setgroups");
    }
    return;
  }

  size_t count = 1;
  for (const char *p = csv; *p; ++p) {
    if (*p == ',') {
      count++;
    }
  }

  gid_t *groups = calloc(count, sizeof(gid_t));
  if (groups == NULL) {
    die("calloc");
  }

  char *buffer = strdup(csv);
  if (buffer == NULL) {
    die("strdup");
  }

  size_t index = 0;
  for (char *token = strtok(buffer, ","); token != NULL; token = strtok(NULL, ",")) {
    groups[index++] = (gid_t)parse_long(token);
  }

  if (setgroups(index, groups) != 0) {
    die("setgroups");
  }

  free(groups);
  free(buffer);
}

int main(int argc, char **argv) {
  if (argc < 6) {
    fprintf(stderr, "usage: %s <cwd> <uid> <gid> <groups-csv|-> -- <argv...>\n", argv[0]);
    return 111;
  }

  const char *cwd = argv[1];
  uid_t uid = (uid_t)parse_long(argv[2]);
  gid_t gid = (gid_t)parse_long(argv[3]);
  const char *groups = argv[4];

  int separator = 5;
  if (strcmp(argv[separator], "--") != 0) {
    fprintf(stderr, "expected -- separator\n");
    return 111;
  }
  separator++;
  if (separator >= argc) {
    fprintf(stderr, "missing argv after --\n");
    return 111;
  }

  if (chdir(cwd) != 0) {
    die("chdir");
  }
  apply_groups(groups);
  if (setgid(gid) != 0) {
    die("setgid");
  }
  if (setuid(uid) != 0) {
    die("setuid");
  }
  execvp(argv[separator], &argv[separator]);
  die("execvp");
  return 111;
}
