// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 CTERA Networks.  All Rights Reserved.
 */

/*\
 * Verify that FAN_DELETE_SELF is reported only once, after the last alias of
 * an unlinked inode is gone, and that the inode marks are not removed while
 * the unlinked inode is still open.
 *
 * Create two hardlinks to a file with an inode mark for FAN_MODIFY, open the
 * file via one link and unlink both links, so the unlink of the last link
 * drops the last dentry reference of that link while the inode is still open
 * via the other link.  Then write to the open file and close it.
 *
 * Before the fix, the unlink of the last link reported FAN_DELETE_SELF and
 * removed all the inode marks of the still open inode, so the write to the
 * open file did not report FAN_MODIFY.  Closing the file then reported a
 * second FAN_DELETE_SELF event.
 */

#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <string.h>
#include "tst_test.h"

#ifdef HAVE_SYS_FANOTIFY_H
#include "fanotify.h"

#define MOUNT_PATH "mntpoint"
#define FILE_A MOUNT_PATH "/file_a"
#define FILE_B MOUNT_PATH "/file_b"
#define EVENT_BUF_LEN 4096

#if defined(HAVE_NAME_TO_HANDLE_AT)
static int fanotify_fd = -1;
static int file_fd = -1;
static struct fanotify_fid_t victim_fid;

static int event_matches_victim(struct fanotify_event_metadata *metadata)
{
	struct fanotify_event_info_fid *info;
	struct file_handle *handle;

	info = get_event_info_fid(metadata);
	if (!info)
		return 0;

	handle = (struct file_handle *)info->handle;
	if (handle->handle_type != victim_fid.handle.handle_type ||
	    handle->handle_bytes != victim_fid.handle.handle_bytes)
		return 0;

	return !memcmp(handle->f_handle, victim_fid.handle.f_handle,
		       handle->handle_bytes);
}

static void read_events(unsigned int *delete_self, unsigned int *modify)
{
	struct fanotify_event_metadata *metadata;
	char buf[EVENT_BUF_LEN];
	int len;

	*delete_self = *modify = 0;

	while ((len = read(fanotify_fd, buf, sizeof(buf))) > 0) {
		for (metadata = (struct fanotify_event_metadata *)buf;
		     FAN_EVENT_OK(metadata, len);
		     metadata = FAN_EVENT_NEXT(metadata, len)) {
			if (!event_matches_victim(metadata))
				continue;
			if (metadata->mask & FAN_DELETE_SELF)
				(*delete_self)++;
			if (metadata->mask & FAN_MODIFY)
				(*modify)++;
		}
	}

	if (len < 0 && errno != EAGAIN)
		tst_brk(TBROK | TERRNO, "read(fanotify_fd) failed");
}

static void setup(void)
{
	REQUIRE_FANOTIFY_EVENTS_SUPPORTED_ON_FS(FAN_REPORT_FID,
		FAN_MARK_FILESYSTEM, FAN_DELETE_SELF, MOUNT_PATH);

	fanotify_fd = SAFE_FANOTIFY_INIT(FAN_CLASS_NOTIF | FAN_REPORT_FID |
					 FAN_NONBLOCK | FAN_CLOEXEC,
					 O_RDONLY | O_LARGEFILE);
	SAFE_FANOTIFY_MARK(fanotify_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
			   FAN_DELETE_SELF, AT_FDCWD, MOUNT_PATH);
}

static void cleanup(void)
{
	if (file_fd >= 0)
		SAFE_CLOSE(file_fd);
	if (fanotify_fd >= 0)
		SAFE_CLOSE(fanotify_fd);
}

static void run(void)
{
	unsigned int delete_self, modify;

	SAFE_TOUCH(FILE_A, 0600, NULL);
	memset(&victim_fid, 0, sizeof(victim_fid));
	fanotify_save_fid(FILE_A, &victim_fid);
	SAFE_LINK(FILE_A, FILE_B);
	SAFE_FANOTIFY_MARK(fanotify_fd, FAN_MARK_ADD, FAN_MODIFY,
			   AT_FDCWD, FILE_A);

	file_fd = SAFE_OPEN(FILE_B, O_WRONLY);
	SAFE_UNLINK(FILE_B);
	SAFE_UNLINK(FILE_A);

	read_events(&delete_self, &modify);
	if (delete_self)
		tst_res(TFAIL, "Got FAN_DELETE_SELF while file is still open");
	else
		tst_res(TPASS, "No FAN_DELETE_SELF while file is still open");

	SAFE_WRITE(SAFE_WRITE_ALL, file_fd, "x", 1);
	read_events(&delete_self, &modify);
	if (modify != 1)
		tst_res(TFAIL, "Got %u FAN_MODIFY events on unlinked open file, expected 1",
			modify);
	else
		tst_res(TPASS, "Inode mark still alive on unlinked open file");

	SAFE_CLOSE(file_fd);
	read_events(&delete_self, &modify);
	if (delete_self != 1)
		tst_res(TFAIL, "Got %u FAN_DELETE_SELF events on last close, expected 1",
			delete_self);
	else
		tst_res(TPASS, "Got one FAN_DELETE_SELF event on last close");
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.needs_root = 1,
	.mount_device = 1,
	.mntpoint = MOUNT_PATH,
	.tags = (const struct tst_tag[]) {
		{"linux-git", "669bb5af15d41a21359d00a441490f87a88eb52a"},
		{}
	}
};

#else
	TST_TEST_TCONF("System does not have required name_to_handle_at() support");
#endif
#else
	TST_TEST_TCONF("System does not have required fanotify support");
#endif
