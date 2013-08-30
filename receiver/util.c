/*
 * Contains the utility functions for the KMaldetect Receiver application.
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <pwd.h>
#include <sched.h>
#include <unistd.h>
#include "util.h"

/* Change our scheduler to a soft-realtime round robin scheduler. This requires evelated privileges */
int set_rr_scheduler(void)
{
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_RR);
    if (sched_setscheduler(0, SCHED_RR, &param) != 0)
    {
        return -1;
    }

    return 0;
}

/* Changes the uid and gid to that of system account "maldetect" */
int drop_privileges(void)
{
    struct passwd *user_info = getpwnam(SYSACCOUNT);
    if (!user_info)
    {
        return -1;
    }

    if (setgid(user_info->pw_gid) != 0 || setuid(user_info->pw_uid) != 0)
    {
        return -1;
    }

    return 0;
}

