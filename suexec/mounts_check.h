#ifndef _SUEXEC_MOUNTS_H
#define _SUEXEC_MOUNTS_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include "suexec.h"

#define CMP_START (sizeof(CHROOT_DIR) - 1)

int check_mount (char *userdir, char *homedir);

#endif /* _SUEXEC_MOUNTS_H */
