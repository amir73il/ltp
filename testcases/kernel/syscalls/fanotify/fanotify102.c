/*
 * Copyright (c) 2017 CTERA Networks.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it is
 * free of the rightful claim of any third person regarding infringement
 * or the like.  Any license provided herein, whether implied or
 * otherwise, applies only to this software file.  Patent licenses, if
 * any, provided herein do not apply to combinations of this program with
 * other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Started by Amir Goldstein <amir73il@gmail.com>
 *
 * DESCRIPTION
 *     Check that fanotify dentry events work
 */
#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include "tst_test.h"
#include "fanotify.h"

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>
#include <sys/inotify.h>


#define EVENT_MAX 1024
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct fanotify_event_metadata))
/* reasonable guess as to size of 1024 events */
#define EVENT_BUF_LEN        (EVENT_MAX * EVENT_SIZE)

#define BUF_SIZE 256
#define TST_TOTAL 10

static char fname1[BUF_SIZE], fname2[BUF_SIZE];
static char dname1[BUF_SIZE], dname2[BUF_SIZE];
static int fd, fd_notify;

struct event_t {
	char name[BUF_SIZE];
	unsigned long long mask;
};
static struct event_t event_set[EVENT_MAX];

static char event_buf[EVENT_BUF_LEN];

#define DIR_NAME1 "test_dir1"
#define DIR_NAME2 "test_dir2"
#define FILE_NAME1 "test_file1"
#define FILE_NAME2 "test_file2"
#define MOUNT_PATH "fs_mnt"

void test01(void)
{
	int ret, len = 0, i = 0, test_num = 0;
	unsigned int stored_cookie = UINT_MAX;

	int tst_count = 0;

	if (fanotify_mark(fd_notify, FAN_MARK_ADD |
			  FAN_MARK_FILESYSTEM, FAN_ATTRIB |
			  FAN_CREATE | FAN_DELETE | FAN_MOVE |
			  FAN_EVENT_ON_CHILD | FAN_ONDIR, AT_FDCWD,
			  MOUNT_PATH) < 0) {
		tst_brk(TBROK | TERRNO,
		    "fanotify_mark (%d, FAN_MARK_ADD | "
		    "FAN_MARK_FILESYSTEM, FAN_ATTRIB | "
		    "FAN_CREATE | FAN_DELETE | FAN_MOVE | "
		    "FAN_EVENT_ON_CHILD | FAN_ONDIR, "
		    "AT_FDCWD, '"MOUNT_PATH"') "
		    "failed", fd_notify);
	}

	/*
	 * generate sequence of events
	 */
	if (mkdir(dname1, 0755) < 0) {
		tst_brk(TBROK | TERRNO,
				"mkdir('"DIR_NAME1"', 0755) failed");
	}

	/*
	 * FAN_ATTRIB is received once for watched parent with filename and
	 * FAN_EVENT_ON_CHILD and once for watched child without filename.
	 */
	event_set[tst_count].mask = FAN_ONDIR | FAN_CREATE |
				    FAN_EVENT_ON_CHILD | FAN_ATTRIB;
	strcpy(event_set[tst_count].name, DIR_NAME1);
	tst_count++;

	if ((fd = creat(fname1, 0755)) == -1) {
		tst_brk(TBROK | TERRNO,
				"creat(\"%s\", 755) failed", FILE_NAME1);
	}

	/*
	 * FAN_ATTRIB is received once for watched parent with filename and
	 * FAN_EVENT_ON_CHILD and once for watched child without filename.
	 */
	event_set[tst_count].mask = FAN_CREATE | FAN_EVENT_ON_CHILD | FAN_ATTRIB;
	strcpy(event_set[tst_count].name, FILE_NAME1);
	tst_count++;

	if (close(fd) == -1) {
		tst_brk(TBROK | TERRNO,
				"close(%s) failed", FILE_NAME1);
	}

	if ((fd = chmod(fname1, 0755)) == -1) {
		tst_brk(TBROK | TERRNO,
				"chmod(\"%s\", 755) failed", FILE_NAME1);
	}

	event_set[tst_count].mask = FAN_ATTRIB;
	tst_count++;

	if (rename(fname1, fname2) == -1) {
		tst_brk(TBROK | TERRNO,
				"rename(%s, %s) failed",
				FILE_NAME1, FILE_NAME2);
	}

	event_set[tst_count].mask = FAN_MOVED_FROM;
	strcpy(event_set[tst_count].name, FILE_NAME1);
	tst_count++;

	event_set[tst_count].mask = FAN_MOVED_TO;
	strcpy(event_set[tst_count].name, FILE_NAME2);
	tst_count++;

	if (unlink(fname2) == -1) {
		tst_brk(TBROK | TERRNO,
				"unlink(%s) failed", FILE_NAME2);
	}

	event_set[tst_count].mask = FAN_DELETE;
	strcpy(event_set[tst_count].name, FILE_NAME2);
	tst_count++;

	/*
	 * Generate events on directory
	 */
	if (chmod(dname1, 0755) < 0) {
		tst_brk(TBROK | TERRNO,
				"chmod('"DIR_NAME1"', 0755) failed");
	}

	event_set[tst_count].mask = FAN_ONDIR | FAN_ATTRIB;
	tst_count++;

	if (rename(dname1, dname2) == -1) {
		tst_brk(TBROK | TERRNO,
				"rename(%s, %s) failed",
				DIR_NAME1, DIR_NAME2);
	}

	event_set[tst_count].mask = FAN_ONDIR | FAN_MOVED_FROM;
	strcpy(event_set[tst_count].name, DIR_NAME1);
	tst_count++;

	event_set[tst_count].mask = FAN_ONDIR | FAN_MOVED_TO;
	strcpy(event_set[tst_count].name, DIR_NAME2);
	tst_count++;

	if (rmdir(dname2) == -1) {
		tst_brk(TBROK | TERRNO,
				"rmdir(%s) failed", DIR_NAME2);
	}

	event_set[tst_count].mask = FAN_ONDIR | FAN_DELETE;
	strcpy(event_set[tst_count].name, DIR_NAME2);
	tst_count++;

	/*
	 * Cleanup the mark
	 */
	if (fanotify_mark(fd_notify, FAN_MARK_FLUSH, 0,
			    AT_FDCWD, MOUNT_PATH) < 0) {
		tst_brk(TBROK | TERRNO,
		    "fanotify_mark (%d, FAN_MARK_FLUSH, 0,"
		    "AT_FDCWD, '"MOUNT_PATH"') failed",
		    fd_notify);
	}

	if (tst_count != TST_TOTAL) {
		tst_brk(TBROK,
				"tst_count and TST_TOTAL are not equal");
	}

	/*
	 * Check events
	 */
	ret = SAFE_READ(0, fd_notify, event_buf + len,
			EVENT_BUF_LEN - len);
	len += ret;

	while (i < len) {
		struct fanotify_event_metadata *event;
		struct fanotify_event_info_fid *event_fid;
		struct file_handle *file_handle;
		const char *filename;
		int namelen;

		event = (struct fanotify_event_metadata *)&event_buf[i];
		event_fid = (struct fanotify_event_info_fid *)(event + 1);
		file_handle = (struct file_handle *)event_fid->handle;
		filename = (char *)file_handle->f_handle + file_handle->handle_bytes;
		namelen = ((char *)event + event->event_len) - filename;
		if (!namelen)
			filename = "";

		if (test_num >= TST_TOTAL) {
			tst_res(TFAIL,
				 "get unnecessary event: mask=%llx "
				 "pid=%u fd=%d",
				 (unsigned long long)event->mask,
				 (unsigned)event->pid, event->fd);
			event->mask = 0;
		} else if (event->event_len > event->metadata_len) {
			/* fanotify filename events should not be merged */
			if (event->mask != event_set[test_num].mask) {
				tst_res(TFAIL,
					 "get event: mask=%llx (expected %llx) "
					 "pid=%u fd=%d name='%s'",
					 (unsigned long long)event->mask,
					 event_set[test_num].mask,
					 (unsigned)event->pid, event->fd,
					 filename);
			} else if (namelen && strncmp(event_set[test_num].name,
						      filename, namelen)) {
				tst_res(TFAIL,
					 "get event: mask=%llx "
					 "pid=%u fd=%d name='%s' expected(%s)",
					 (unsigned long long)event->mask,
					 (unsigned)event->pid, event->fd,
					 filename,
					 event_set[test_num].name);
			} else if (event->mask & FAN_MOVE) {
				int fail = 0;

				/* check that rename cookie is unique */
				if (event->mask & FAN_MOVED_FROM) {
					if ((unsigned)event->pid == stored_cookie)
						fail = 1;
					else
						stored_cookie = (unsigned)event->pid;
				} else if (event->mask & FAN_MOVED_TO) {
					if ((unsigned)event->pid != stored_cookie)
						fail = 1;
				}
				if (!fail) {
					tst_res(TPASS,
						    "get event: mask=%llx cookie=%u fd=%d name='%s'",
						    (unsigned long long)event->mask,
						    (unsigned)event->pid, event->fd,
						    filename);
				} else {
					tst_res(TFAIL,
						    "get event: mask=%llx cookie=%u (last=%u) fd=%d name='%s'",
						    (unsigned long long)event->mask,
						    (unsigned)event->pid, stored_cookie, event->fd,
						    filename);
				}
			} else {
				tst_res(TPASS,
					    "get event: mask=%llx pid=%u fd=%d name='%s'",
					    (unsigned long long)event->mask,
					    (unsigned)event->pid, event->fd,
					    filename);
			}
		} else if (!(event->mask & event_set[test_num].mask)) {
			tst_res(TFAIL,
				 "get event: mask=%llx (expected %llx) "
				 "pid=%u fd=%d",
				 (unsigned long long)event->mask,
				 event_set[test_num].mask,
				 (unsigned)event->pid, event->fd);
		} else if (event->pid != getpid()) {
			tst_res(TFAIL,
				 "get event: mask=%llx pid=%u "
				 "(expected %u) fd=%d",
				 (unsigned long long)event->mask,
				 (unsigned)event->pid,
				 (unsigned)getpid(),
				 event->fd);
		} else {
			tst_res(TPASS,
				    "get event: mask=%llx pid=%u fd=%d",
				    (unsigned long long)event->mask,
				    (unsigned)event->pid, event->fd);
		}
		event->mask &= ~event_set[test_num].mask;
		/* No events left in current mask? Go for next event */
		if (event->mask == 0) {
			i += event->event_len;
			close(event->fd);
		}
		test_num++;
	}
	for (; test_num < TST_TOTAL; test_num++) {
		tst_res(TFAIL, "didn't get event: mask=%llx",
			 event_set[test_num].mask);

	}
}

static void setup(void)
{
	sprintf(dname1, "%s/%s", MOUNT_PATH, DIR_NAME1);
	sprintf(dname2, "%s/%s", MOUNT_PATH, DIR_NAME2);
	sprintf(fname1, "%s/%s", dname1, FILE_NAME1);
	sprintf(fname2, "%s/%s", dname1, FILE_NAME2);
	fd_notify = SAFE_FANOTIFY_INIT(FAN_REPORT_FID | FAN_REPORT_FILENAME |
				       FAN_REPORT_COOKIE, 0);
}

static void cleanup(void)
{
	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);
}

static struct tst_test test = {
	.test_all = test01,
	.setup = setup,
	.cleanup = cleanup,
	.mount_device = 1,
	.mntpoint = MOUNT_PATH,
	.needs_tmpdir = 1,
	.needs_root = 1
};

#else
	TST_TEST_TCONF("system doesn't have required fanotify support");
#endif
