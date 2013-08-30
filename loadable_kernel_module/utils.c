/*
 * Contains utility functions to be used in the rest of the KMaldetect LKM.
 *
 * Copyright (c) 2013 Sebastiaan Groot
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/syscall.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <linux/mount.h>

/* Looks at the currently scheduled process and returns the first associated executable as inode number */
unsigned long get_inode(void)
{
    struct dentry *dentry = NULL;
    struct vfsmount *mnt = NULL;
    struct vm_area_struct * vma;
    down_read(&current->mm->mmap_sem);

    vma = current->mm->mmap;
    while(vma)
    {
        if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
        {
            break;
        }
        vma = vma->vm_next;
    }
    if (vma)
    {
        mnt = mntget(vma->vm_file->f_path.mnt);
        dentry = dget(vma->vm_file->f_path.dentry);
    }

    up_read(&current->mm->mmap_sem);

    if (dentry)
    {
        return dentry->d_inode->i_ino;
    }
	return 0;
}

