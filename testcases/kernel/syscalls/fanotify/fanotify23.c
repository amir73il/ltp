// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 CTERA Networks.  All Rights Reserved.
 *
 * Author: Amir Goldstein <amir73il@gmail.com>
 */

/*\
 * [Description]
 * Check evictable fanotify inode marks.
 */

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include "tst_test.h"

#ifdef HAVE_SYS_FANOTIFY_H
#include "fanotify.h"

#define EVENT_MAX 1024
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct fanotify_event_metadata))
/* reasonable guess as to size of 1024 events */
#define EVENT_BUF_LEN        (EVENT_MAX * EVENT_SIZE)
/* limit number and size of large marks to allocate */
#define LARGE_MARK_PAGE_ORDER 9 /* 2MB */
#define LARGE_MARK_KB (4 << LARGE_MARK_PAGE_ORDER)
#define LARGE_MARKS_MAX	50000
#define LARGE_MARKS_MAX_KB (LARGE_MARKS_MAX * LARGE_MARK_KB)

#define MOUNT_PATH "fs_mnt"
#define TEST_FILE MOUNT_PATH "/testfile"

#define DROP_CACHES_FILE "/proc/sys/vm/drop_caches"
#define CACHE_PRESSURE_FILE "/proc/sys/vm/vfs_cache_pressure"

static int old_cache_pressure;
static int fd_notify;

static unsigned long long event_set[EVENT_MAX];

static char event_buf[EVENT_BUF_LEN];

static void fsync_file(const char *path)
{
	int fd = SAFE_OPEN(path, O_RDONLY);

	SAFE_FSYNC(fd);
	SAFE_CLOSE(fd);
}

static int check_ignore_mark(void)
{
	unsigned int ignored_mask, mflags;
	char procfdinfo[100];

	sprintf(procfdinfo, "/proc/%d/fdinfo/%d", (int)getpid(), fd_notify);
	if (FILE_LINES_SCANF(procfdinfo, "fanotify ino:%*x sdev:%*x mflags: %x mask:0 ignored_mask:%x",
				&mflags, &ignored_mask)) {
		tst_res(TINFO, "No fanotify ignore marks");
		return 0;
	} else {
		tst_res(TINFO, "Found %sevictable ignore mark (ignored_mask=%x, mflags=%x) in %s",
				(mflags & FAN_MARK_EVICTABLE) ? "" : "non-",
				ignored_mask, mflags, procfdinfo);
		return 1;
	}
}

static void verify_mark_removed(const char *path, const char *when)
{
	int ret;

	/*
	 * We know that inode with evictable mark was evicted when a
	 * bogus call remove ACCESS from event mask returns ENOENT.
	 */
	errno = 0;
	ret = fanotify_mark(fd_notify, FAN_MARK_REMOVE,
			    FAN_ACCESS, AT_FDCWD, path);
	if (ret == -1 && errno == ENOENT) {
		tst_res(TPASS,
			"FAN_MARK_REMOVE failed with ENOENT as expected"
			" %s", when);
	} else {
		tst_res(TFAIL | TERRNO,
			"FAN_MARK_REMOVE did not fail with ENOENT as expected"
			" %s", when);
	}
	check_ignore_mark();
}

static int add_large_mark(const char *path)
{
	time_t end, start = time(NULL);
	int ret;

	/*
	 * Adding a large mark should either succeed or fail with ENOMEM.
	 */
	errno = 0;
	ret = fanotify_mark(fd_notify, FAN_MARK_ADD,
			    FAN_ACCESS, AT_FDCWD, path);
	if (ret == -1 && errno == ENOMEM) {
		tst_res(TPASS,
			"Adding large mark failed with ENOMEM as expected");
	} else if (ret) {
		tst_res(TFAIL | TERRNO,
			"Adding large mark failed with unexpected error");
	} else {
		end = time(NULL);
		ret = ((end - start) > 1);
	}

	return ret;
}

static void test_direct_reclaim(void)
{
	long free;
	int i = 0;

	SAFE_FILE_LINES_SCANF("/proc/meminfo", "MemFree: %ld", &free);
	tst_res(TINFO, "System has %ld kB of free mem", free);

	if (free > LARGE_MARKS_MAX_KB) {
		tst_res(TCONF, "Skipping direct reclaim test on large system");
		return;
	}

	/*
	 * Test direct reclaim of inode with evictable mark.
	 *
	 * We try to get into direct reclaim by allocating an infinite number
	 * of empty marks.
	 */
	fsync_file(TEST_FILE);
	SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD | FAN_MARK_EVICTABLE |
			   FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
			   FAN_ACCESS, AT_FDCWD, TEST_FILE);
	check_ignore_mark();

	tst_res(TINFO, "Setting large mark size to %d kB", LARGE_MARK_KB);
	SAFE_IOCTL(fd_notify, FAN_IOC_SET_MARK_PAGE_ORDER, LARGE_MARK_PAGE_ORDER);
	tst_res(TINFO, "Allocating %d large marks...", LARGE_MARKS_MAX);
	while (i < LARGE_MARKS_MAX) {
		if (add_large_mark(MOUNT_PATH))
			break;
		if (++i % 1000 == 0) {
			tst_res(TINFO, "Allocated %d large marks", i);
			/* Stop if ignore mark was evicted */
			if (!check_ignore_mark())
				return;
		}
	}
	tst_res(TINFO, "Allocated %d large marks", i);

	/*
	 * Kicking reclaim may or may not have evicted the evictable mark.
	 * The important thing is not to deadlock in direct reclaim!!!
	 */
	check_ignore_mark();
}

static void test_fanotify(void)
{
	int ret, len, test_num = 0;
	struct fanotify_event_metadata *event;
	int tst_count = 0;

	fd_notify = SAFE_FANOTIFY_INIT(FAN_CLASS_NOTIF | FAN_REPORT_FID |
				       FAN_NONBLOCK | FAN_UNLIMITED_MARKS,
				       O_RDONLY);

	/*
	 * Verify that evictable mark can be upgraded to non-evictable
	 * and cannot be downgraded to evictable.
	 */
	SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD | FAN_MARK_EVICTABLE,
			   FAN_ACCESS,
			   AT_FDCWD, TEST_FILE);
	SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD,
			   FAN_ACCESS,
			   AT_FDCWD, TEST_FILE);
	errno = 0;
	ret = fanotify_mark(fd_notify, FAN_MARK_ADD | FAN_MARK_EVICTABLE,
			    FAN_ACCESS,
			    AT_FDCWD, TEST_FILE);
	if (ret == -1 && errno == EEXIST) {
		tst_res(TPASS,
			"FAN_MARK_ADD failed with EEXIST as expected"
			" when trying to downgrade to evictable mark");
	} else {
		tst_res(TFAIL | TERRNO,
			"FAN_MARK_ADD did not fail with EEXIST as expected"
			" when trying to downgrade to evictable mark");
	}
	SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_REMOVE,
			   FAN_ACCESS,
			   AT_FDCWD, TEST_FILE);
	verify_mark_removed(TEST_FILE, "after empty mask");


	/*
	 * Watch ATTRIB events on entire mount
	 */
	SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
			   FAN_ATTRIB, AT_FDCWD, MOUNT_PATH);

	/*
	 * Generate events
	 */
	SAFE_CHMOD(TEST_FILE, 0600);
	event_set[tst_count] = FAN_ATTRIB;
	tst_count++;

	/* Read events so far */
	ret = SAFE_READ(0, fd_notify, event_buf, EVENT_BUF_LEN);
	len = ret;

	/*
	 * Evictable mark on file ignores ATTRIB events
	 */
	SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD | FAN_MARK_EVICTABLE |
			   FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
			   FAN_ATTRIB, AT_FDCWD, TEST_FILE);

	/* ATTRIB event should be ignored */
	SAFE_CHMOD(TEST_FILE, 0600);

	/*
	 * Read events to verify event was ignored
	 */
	ret = read(fd_notify, event_buf + len, EVENT_BUF_LEN - len);
	if (ret < 0 && errno == EAGAIN) {
		tst_res(TPASS, "Got no events as expected");
	} else {
		tst_res(TFAIL, "Got expected events");
		len += ret;
	}

	/*
	 * drop_caches should evict inode from cache and remove evictable mark
	 */
	fsync_file(TEST_FILE);
	SAFE_FILE_PRINTF(DROP_CACHES_FILE, "2");

	verify_mark_removed(TEST_FILE, "after drop_caches");

	SAFE_CHMOD(TEST_FILE, 0600);
	event_set[tst_count] = FAN_ATTRIB;
	tst_count++;

	/* Read events to verify ATTRIB event was properly generated */
	ret = SAFE_READ(0, fd_notify, event_buf + len, EVENT_BUF_LEN - len);
	len += ret;

	/*
	 * Check events
	 */
	event = (struct fanotify_event_metadata *)event_buf;

	/* Iterate over and validate events against expected result set */
	while (FAN_EVENT_OK(event, len) && test_num < tst_count) {
		if (!(event->mask & event_set[test_num])) {
			tst_res(TFAIL,
				"got event: mask=%llx (expected %llx)",
				(unsigned long long)event->mask,
				event_set[test_num]);
		} else {
			tst_res(TPASS,
				"got event: mask=%llx",
				(unsigned long long)event->mask);
		}
		/*
		 * Close fd and invalidate it so that we don't check it again
		 * unnecessarily
		 */
		if (event->fd >= 0)
			SAFE_CLOSE(event->fd);
		event->fd = FAN_NOFD;
		event->mask &= ~event_set[test_num];
		/* No events left in current mask? Go for next event */
		if (event->mask == 0) {
			event = FAN_EVENT_NEXT(event, len);
		}
		test_num++;
	}

	while (FAN_EVENT_OK(event, len)) {
		tst_res(TFAIL,
			"got unnecessary event: mask=%llx",
			(unsigned long long)event->mask);
		if (event->fd != FAN_NOFD)
			SAFE_CLOSE(event->fd);
		event = FAN_EVENT_NEXT(event, len);
	}

	test_direct_reclaim();

	SAFE_CLOSE(fd_notify);
}

static void setup(void)
{
	SAFE_TOUCH(TEST_FILE, 0666, NULL);

	REQUIRE_MARK_TYPE_SUPPORTED_BY_KERNEL(FAN_MARK_EVICTABLE);
	REQUIRE_FANOTIFY_EVENTS_SUPPORTED_ON_FS(FAN_CLASS_NOTIF|FAN_REPORT_FID,
						FAN_MARK_FILESYSTEM,
						FAN_ATTRIB, ".");

	SAFE_FILE_SCANF(CACHE_PRESSURE_FILE, "%d", &old_cache_pressure);
	/* Set high priority for evicting inodes */
	SAFE_FILE_PRINTF(CACHE_PRESSURE_FILE, "500");
}

static void cleanup(void)
{
	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);

	SAFE_FILE_PRINTF(CACHE_PRESSURE_FILE, "%d", old_cache_pressure);
}

static struct tst_test test = {
	.test_all = test_fanotify,
	.setup = setup,
	.cleanup = cleanup,
	.needs_root = 1,
	.mount_device = 1,
	.mntpoint = MOUNT_PATH,
};

#else
	TST_TEST_TCONF("system doesn't have required fanotify support");
#endif
