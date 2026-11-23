// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2013 SUSE.  All Rights Reserved.
 * Copyright (c) 2025 CTERA Networks.  All Rights Reserved.
 *
 * Started by Jan Kara <jack@suse.cz>
 */

/*\
 * - Variant of fanotify24 with pre-content events that report fid+name info
 * - Do not test permission events, because only pre-content events can
 *   report fid+name info
 * - Do not use flag FAN_EVENT_ON_CHILD to watch children, but because this
 *   flag is implied, expect pre-content events on children
 */

#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include "tst_test.h"

#ifdef HAVE_SYS_FANOTIFY_H
# include "fanotify.h"

#define EVENT_MAX 1024
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof(struct fanotify_event_metadata))
/* reasonable guess as to size of 1024 events */
#define EVENT_BUF_LEN        (EVENT_MAX * EVENT_SIZE)
/* Size large enough to hold a reasonable amount of expected event objects */
#define EVENT_SET_MAX 16

#define BUF_SIZE 256
#define TST_TOTAL 3
#define TEST_APP "fanotify_child"
#define MOUNT_PATH "fs_mnt"
#define MNT2_PATH "bind_mnt"
#define TEST_DIR_NAME "testdir"
#define TEST_DIR MOUNT_PATH"/"TEST_DIR_NAME

static char notfound[BUF_SIZE];
/*
 * The test dir on the watched filesystem, where the test files are created
 * and marks are set, and the test dir via which the child accesses them.
 */
static const char *watch_dir = TEST_DIR;
static const char *access_dir = TEST_DIR;

/* Paths in access_dir */
static char fname[BUF_SIZE];
static char exec_path[BUF_SIZE];
static char lookup_path[BUF_SIZE];
static char newent_path[BUF_SIZE];
static char entry_path[BUF_SIZE];
static char renamed_path[BUF_SIZE];
/* The name of TEST_DIR in lookup events */
static const char testdir_name[] = TEST_DIR_NAME;
static char buf[BUF_SIZE];
static volatile int fd_notify;
static size_t page_sz;

static pid_t child_pid;
static int bind_mount_fd;

static int pre_dir_access_unsupported;

static char event_buf[EVENT_BUF_LEN];

struct event {
	unsigned long long mask;
	unsigned int response;
	const char *name;	/* path of the expected name in event, NULL for readdir */
};

/*
 * FAN_DENY_ERRNO(ENOENT) is not a valid response. It is used in this test as
 * a response marker for a lookup event, which tells the listener to populate
 * a negative entry and respond with FAN_ALLOW.
 * It means that if the listener fails to populate and replies FAN_ALLOW, the
 * lookup will fail with ENOENT.
 */
#define FAN_ALLOW_ENOENT FAN_DENY_ERRNO(ENOENT)

static struct tcase {
	const char *tname;
	struct fanotify_mark_type mark;
	unsigned long long mask;
	struct event event_set[EVENT_SET_MAX];
} tcases[] = {
	{
		"inode mark, FAN_PRE_ACCESS events",
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_PRE_ACCESS,
		{
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EIO), fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EBUSY), TEST_APP},
		}
	},
	{
		"inode mark, FAN_PRE_ACCESS event allowed",
		INIT_FANOTIFY_MARK_TYPE(INODE),
		FAN_PRE_ACCESS,
		{
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			/* The last allowed event may repeat any number of times */
			{FAN_PRE_ACCESS, FAN_ALLOW, TEST_APP},
		}
	},
	{
		"mount mark, FAN_PRE_ACCESS events",
		INIT_FANOTIFY_MARK_TYPE(MOUNT),
		FAN_PRE_ACCESS,
		{
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EIO), fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EBUSY), TEST_APP},
		}
	},
	{
		"mount mark, FAN_PRE_DIR_ACCESS | FAN_PRE_ACCESS events",
		INIT_FANOTIFY_MARK_TYPE(MOUNT),
		FAN_PRE_DIR_ACCESS | FAN_PRE_ACCESS,
		{
			/* lookup of TEST_DIR in the mount root */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, testdir_name},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW_ENOENT, lookup_path},
			/* open() denied and creat() allowed of a new name */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, NULL},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_DENY, fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EIO), TEST_APP},
		}
	},
	{
		"filesystem mark, FAN_PRE_ACCESS events",
		INIT_FANOTIFY_MARK_TYPE(FILESYSTEM),
		FAN_PRE_ACCESS,
		{
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EIO), fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EBUSY), TEST_APP},
		}
	},
	{
		"filesystem mark, FAN_PRE_DIR_ACCESS | FAN_PRE_ACCESS events",
		INIT_FANOTIFY_MARK_TYPE(FILESYSTEM),
		FAN_PRE_DIR_ACCESS | FAN_PRE_ACCESS,
		{
			/* lookup of TEST_DIR in the mount root */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, testdir_name},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW_ENOENT, lookup_path},
			/* open() denied and creat() allowed of a new name */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, NULL},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_DENY, fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EIO), TEST_APP},
		}
	},
	{
		"parent (implicitly) watching children, FAN_PRE_ACCESS events",
		INIT_FANOTIFY_MARK_TYPE(PARENT),
		FAN_PRE_ACCESS,
		{
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_DENY, fname},
			{FAN_PRE_ACCESS, FAN_DENY, fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EBUSY), TEST_APP},
		}
	},
	{
		"parent watching children and self, FAN_PRE_DIR_ACCESS | FAN_PRE_ACCESS events",
		INIT_FANOTIFY_MARK_TYPE(PARENT),
		FAN_PRE_DIR_ACCESS | FAN_PRE_ACCESS,
		{
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW_ENOENT, lookup_path},
			/* open() denied and creat() allowed of a new name */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, NULL},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_ALLOW, fname},
			{FAN_PRE_ACCESS, FAN_DENY, fname},
			{FAN_PRE_ACCESS, FAN_DENY_ERRNO(EIO), TEST_APP},
		}
	},
	{
		"parent watching only itself, FAN_PRE_DIR_ACCESS events",
		INIT_FANOTIFY_MARK_TYPE(PARENT),
		FAN_PRE_DIR_ACCESS,
		{
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW_ENOENT, lookup_path},
			/* open() denied and creat() allowed of a new name */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, NULL},
		}
	},
	{
		"mount mark, FAN_PRE_DIR_ACCESS events denied",
		INIT_FANOTIFY_MARK_TYPE(MOUNT),
		FAN_PRE_DIR_ACCESS,
		{
			/* lookup of TEST_DIR in the mount root */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, testdir_name},
			/* lookup */
			{FAN_PRE_DIR_ACCESS, FAN_DENY_ERRNO(EIO), lookup_path},
			/* open() denied and creat() allowed of a new name */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, newent_path},
			/* readdir, retried until allowed */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, NULL},
			{FAN_PRE_DIR_ACCESS, FAN_DENY_ERRNO(EAGAIN), NULL},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, NULL},
		}
	},
	{
		"parent watching only itself, FAN_PRE_DIR_ACCESS events denied",
		INIT_FANOTIFY_MARK_TYPE(PARENT),
		FAN_PRE_DIR_ACCESS,
		{
			/* lookup */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, lookup_path},
			/* open() denied and creat() allowed of a new name */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, newent_path},
			/* readdir, retried until allowed */
			{FAN_PRE_DIR_ACCESS, FAN_DENY_ERRNO(EBUSY), NULL},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, NULL},
		}
	},
	{
		"mount mark, FAN_PRE_DIR_ACCESS events on create, rename and remove",
		INIT_FANOTIFY_MARK_TYPE(MOUNT),
		FAN_PRE_DIR_ACCESS,
		{
			/* lookup of TEST_DIR in the mount root */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, testdir_name},
			/* lookup, without readdir */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW_ENOENT, lookup_path},
			/* open() denied and creat() allowed of a new name */
			{FAN_PRE_DIR_ACCESS, FAN_DENY, newent_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, newent_path},
			/* mknod(), retry after one deny */
			{FAN_PRE_DIR_ACCESS, FAN_DENY_ERRNO(EAGAIN), entry_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, entry_path},
			/* rename() old and new name */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, entry_path},
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, renamed_path},
			/* unlink() */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, renamed_path},
			/* open() */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, fname},
			/* execve() */
			{FAN_PRE_DIR_ACCESS, FAN_ALLOW, TEST_APP},
		},
	},
};

static int expected_errno(unsigned int response)
{
	switch (response) {
	case 0:
	case FAN_ALLOW:
		return 0;
	case FAN_ALLOW_ENOENT:
		/* The listener populates the entry */
		return 0;
	case FAN_DENY:
		return EPERM;
	default:
		return FAN_RESPONSE_ERRNO(response);
	}
}

/* Whether the next event in the event set is the event of an operation */
static int is_event(const struct event *event, unsigned long long mask,
		    const char *name)
{
	return event->mask == mask && event->name == name;
}

/*
 * Consume the event of an operation, if it is the next event in the event set,
 * and return the errno expected from the operation.
 * An operation that is not expected to generate an event is expected to succeed.
 */
static int consume_event(struct event **event, unsigned long long mask,
			 const char *name)
{
	if (!is_event(*event, mask, name))
		return 0;
	return expected_errno((*event)++->response);
}

/* Convert a path in access_dir to the same path in watch_dir */
static const char *watch_path(char *buf, const char *path)
{
	snprintf(buf, BUF_SIZE, "%s%s", watch_dir, path + strlen(access_dir));
	return buf;
}

/* The name in events of a path is the last path component */
static const char *path_name(const char *path)
{
	const char *name = strrchr(path, '/');

	return name ? name + 1 : path;
}

static void generate_events(struct tcase *tc)
{
	int fd;
	char *addr;
	char *const argv[] = {exec_path, NULL};
	struct event *event = tc->event_set;
	int exp_ret, exp_errno = 0;

	if (tc->mask & FAN_PRE_DIR_ACCESS) {
		DIR *dir;
		struct dirent *ent;

		/*
		 * Lookup a unique name each test case to avoid negative cached
		 * lookup result and generate FAN_PRE_DIR_ACCESS.
		 * The lookup succeeds after the listener populates the entry
		 * (FAN_ALLOW_ENOENT) or fails with the errno of the response if
		 * denied.
		 */
		/* TEST_DIR is looked up first if the mount root is watched */
		consume_event(&event, FAN_PRE_DIR_ACCESS, testdir_name);
		exp_errno = consume_event(&event, FAN_PRE_DIR_ACCESS, lookup_path);
		TST_EXP_PASS_OR_FAIL(faccessat(AT_FDCWD, lookup_path, F_OK, 0),
				     exp_errno, "faccessat(%s)", lookup_path);

		/*
		 * open() and creat() of a new name generate FAN_PRE_DIR_ACCESS
		 * for the lookup of the last component.  open() fails with the
		 * errno of the response if denied and creat() creates the entry
		 * if allowed.
		 */
		exp_errno = consume_event(&event, FAN_PRE_DIR_ACCESS, newent_path);
		TST_EXP_FD_OR_FAIL(open(newent_path, O_RDONLY), exp_errno,
				   "open(%s)", newent_path);
		if (TST_RET >= 0)
			SAFE_CLOSE(TST_RET);
		exp_errno = consume_event(&event, FAN_PRE_DIR_ACCESS, newent_path);
		TST_EXP_FD_OR_FAIL(creat(newent_path, 0600), exp_errno,
				   "creat(%s)", newent_path);
		if (TST_RET >= 0)
			SAFE_CLOSE(TST_RET);

		/*
		 * Generate FAN_PRE_DIR_ACCESS on readdir, if a readdir event is
		 * expected.
		 * A denied event was not handled, so the next readdir generates
		 * the event again.  Retry until readdir is allowed.
		 * After this, no more FAN_PRE_DIR_ACCESS events are expected
		 * on this dir until mount cycle.
		 */
		while (is_event(event, FAN_PRE_DIR_ACCESS, NULL)) {
			exp_errno = consume_event(&event, FAN_PRE_DIR_ACCESS, NULL);
			dir = SAFE_OPENDIR(access_dir);
			errno = 0;
			ent = readdir(dir);
			if (exp_errno ? ent || errno != exp_errno : !ent) {
				tst_res(TFAIL, "readdir() got errno %d (expected %d)",
					errno, exp_errno);
				exit(2);
			}
			tst_res(TINFO, "readdir() got errno %d as expected", errno);
			SAFE_CLOSEDIR(dir);
			if (!exp_errno)
				break;
		}

		/*
		 * After readdir, create, rename and remove don't generate events.
		 * Without readdir, mknod() and unlink() report an event each and
		 * rename() reports events for the old name and the new name.
		 * A denied mknod() event was not handled, so the retried mknod()
		 * generates the event again.
		 */
		do {
			exp_errno = consume_event(&event, FAN_PRE_DIR_ACCESS, entry_path);
			TST_EXP_PASS_OR_FAIL(mknod(entry_path, S_IFREG | 0600, 0),
					     exp_errno, "mknod(%s)", entry_path);
			if (!TST_PASS)
				exit(2);
			/* Retry create on failure */
		} while (exp_errno);

		consume_event(&event, FAN_PRE_DIR_ACCESS, entry_path);
		consume_event(&event, FAN_PRE_DIR_ACCESS, renamed_path);
		TST_EXP_PASS(rename(entry_path, renamed_path), "rename(%s, %s)",
			     entry_path, renamed_path);
		if (!TST_PASS)
			exit(2);
		consume_event(&event, FAN_PRE_DIR_ACCESS, renamed_path);
		TST_EXP_PASS(unlink(renamed_path), "unlink(%s)", renamed_path);
		if (!TST_PASS)
			exit(2);
	}

	/*
	 * Generate sequence of events
	 */
	/* Without readdir, open() reports an event for the lookup of fname */
	consume_event(&event, FAN_PRE_DIR_ACCESS, fname);
	fd = SAFE_OPEN(fname, O_RDWR);

	exp_errno = consume_event(&event, FAN_PRE_ACCESS, fname);
	exp_ret = exp_errno ? -1 : 1;
	/*
	 * FAN_PRE_ACCESS events are reported on map() and write(), but should
	 * not be reported when faulting in the user page at offset page_sz*100
	 * that is used as an input buffer to the write() syscall.
	 */
	errno = 0;
	addr = SAFE_MMAP(NULL, page_sz, PROT_READ, MAP_PRIVATE, fd, page_sz*100);
	if (!addr || errno != exp_errno) {
		tst_res(TFAIL, "mmap() got errno %d (expected %d)", errno, exp_errno);
		exit(3);
	} else if (errno == exp_errno) {
		tst_res(TINFO, "mmap() got errno %d as expected", errno);
	}

	exp_errno = consume_event(&event, FAN_PRE_ACCESS, fname);
	exp_ret = exp_errno ? -1 : 1;
	errno = 0;
	if (write(fd, addr, 1) != exp_ret || errno != exp_errno) {
		tst_res(TFAIL, "write() got errno %d (expected %d)", errno, exp_errno);
		exit(3);
	} else if (errno == exp_errno) {
		tst_res(TINFO, "write() got errno %d as expected", errno);
	}

	SAFE_LSEEK(fd, 0, SEEK_SET);

	exp_errno = consume_event(&event, FAN_PRE_ACCESS, fname);
	exp_ret = exp_errno ? -1 : BUF_SIZE;
	errno = 0;
	if (read(fd, buf, BUF_SIZE) != exp_ret || errno != exp_errno) {
		tst_res(TFAIL, "read() got errno %d (expected %d)", errno, exp_errno);
		exit(4);
	} else if (errno == exp_errno) {
		tst_res(TINFO, "read() got errno %d as expected", errno);
	}

	SAFE_CLOSE(fd);

	/* Without readdir, execve() reports an event for the lookup of TEST_APP */
	consume_event(&event, FAN_PRE_DIR_ACCESS, TEST_APP);
	exp_errno = consume_event(&event, FAN_PRE_ACCESS, TEST_APP);
	/*
	 * Check if executing a file that open for write is allowed.
	 * HSM needs to be able to write to file during pre-content event, so it
	 * requires that a file being executed can be open for write, which also
	 * means that a file open for write can be executed.
	 * Therefore, ETXTBSY is to be expected when file is not being watched
	 * at all or being watched but not with pre-content events in mask.
	 */
	if (!exp_errno && !(tc->mask & FAN_PRE_DIR_ACCESS)) {
		fd = SAFE_OPEN(exec_path, O_RDWR);
		if (!tc->event_set[0].mask)
			exp_errno = ETXTBSY;
	}

	exp_ret = exp_errno ? -1 : 0;
	errno = 0;
	if (execve(exec_path, argv, environ) != exp_ret || errno != exp_errno) {
		tst_res(TFAIL, "execve() got errno %d (expected %d)", errno, exp_errno);
		exit(5);
	} else if (errno == exp_errno) {
		tst_res(TINFO, "execve() got errno %d as expected", errno);
	}

	if (fd >= 0)
		SAFE_CLOSE(fd);
}

static void child_handler(int tmp)
{
	(void)tmp;
	/*
	 * Close notification fd so that we cannot block while reading
	 * from it
	 */
	SAFE_CLOSE(fd_notify);
	fd_notify = -1;
}

static void run_child(struct tcase *tc)
{
	struct sigaction child_action;

	child_action.sa_handler = child_handler;
	sigemptyset(&child_action.sa_mask);
	child_action.sa_flags = SA_NOCLDSTOP;

	if (sigaction(SIGCHLD, &child_action, NULL) < 0) {
		tst_brk(TBROK | TERRNO,
			"sigaction(SIGCHLD, &child_action, NULL) failed");
	}

	child_pid = SAFE_FORK();

	if (child_pid == 0) {
		/* Child will generate events now */
		SAFE_CLOSE(fd_notify);
		generate_events(tc);
		exit(0);
	}
}

static void check_child(void)
{
	struct sigaction child_action;
	int child_ret;

	child_action.sa_handler = SIG_IGN;
	sigemptyset(&child_action.sa_mask);
	child_action.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &child_action, NULL) < 0) {
		tst_brk(TBROK | TERRNO,
			"sigaction(SIGCHLD, &child_action, NULL) failed");
	}
	SAFE_WAITPID(-1, &child_ret, 0);

	if (WIFEXITED(child_ret) && WEXITSTATUS(child_ret) == 0)
		tst_res(TPASS, "child exited correctly");
	else
		tst_res(TFAIL, "child %s", tst_strstatus(child_ret));
}

static int setup_mark(unsigned int n)
{
	unsigned int i = 0;
	struct tcase *tc = &tcases[n];
	struct fanotify_mark_type *mark = &tc->mark;
	char files[2][BUF_SIZE];

	tst_res(TINFO, "Test #%d: %s", n, tc->tname);

	if (tc->mask & FAN_PRE_DIR_ACCESS) {
		if (pre_dir_access_unsupported) {
			tst_res(TCONF, "pre-content events on dir not supported in kernel?");
			return -1;
		}
	}

	fd_notify = SAFE_FANOTIFY_INIT(FAN_CLASS_PRE_CONTENT_FID, O_RDONLY);

	/* Ignore pre-content events on mnt2 so we can use it for open_by_handle_at() */
	SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD | FAN_MARK_MOUNT | FAN_MARK_IGNORE_SURV,
			   tc->mask, AT_FDCWD, MNT2_PATH);

	if (mark->flag == FAN_MARK_PARENT) {
		SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD | mark->flag,
				   tc->mask, AT_FDCWD, watch_dir);
		return 0;
	}

	/*
	 * Mark the mount or sb via the mount root, so that setting the mark
	 * does not instantiate dentries in watch_dir.
	 */
	if (mark->flag != FAN_MARK_INODE) {
		SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD | mark->flag,
				   tc->mask, AT_FDCWD, MOUNT_PATH);
		return 0;
	}

	watch_path(files[0], fname);
	watch_path(files[1], exec_path);
	for (; i < ARRAY_SIZE(files); i++) {
		SAFE_FANOTIFY_MARK(fd_notify, FAN_MARK_ADD | mark->flag,
				  tc->mask, AT_FDCWD, files[i]);
	}

	return 0;
}

static void umount_bind_mount(void)
{
	if (bind_mount_fd) {
		if (bind_mount_fd > 0)
			SAFE_CLOSE(bind_mount_fd);
		SAFE_UMOUNT(MNT2_PATH);
		SAFE_RMDIR(MNT2_PATH);
	}
}

/* Unmount the mounts on top of the watched filesystem */
static void umount_layers(void)
{
	umount_bind_mount();
}

/* Mount the mounts on top of the watched filesystem */
static void mount_layers(void)
{
	/* Create another bind mount at another path for open_by_file_handle() */
	SAFE_MKDIR(MNT2_PATH, 0755);
	SAFE_MOUNT(MOUNT_PATH, MNT2_PATH, "none", MS_BIND, NULL);
	bind_mount_fd = -1;
	bind_mount_fd = SAFE_OPEN(MNT2_PATH, O_DIRECTORY);
}

/* Remove the entries populated or created by the last test case */
static void reset_test_dir(void)
{
	static const char *const paths[] = {lookup_path, newent_path};
	char path[BUF_SIZE];

	for (unsigned int i = 0; i < ARRAY_SIZE(paths); i++) {
		if (!*paths[i])
			continue;
		watch_path(path, paths[i]);
		if (unlink(path) && errno != ENOENT)
			tst_brk(TBROK | TERRNO, "unlink(%s) failed", path);
	}
}

/*
 * Mount cycle to evict the dentries which cache the "HSM handled" dir status
 * between test cases.
 * The test dir is reset while no fanotify group is watching and the
 * mounts on top of the watched filesystem are not mounted.
 */
static void mount_cycle(void)
{
	umount_layers();
	reset_test_dir();
	SAFE_UMOUNT(MOUNT_PATH);
	SAFE_MOUNT(tst_device->dev, MOUNT_PATH, tst_device->fs_type, 0, NULL);
	mount_layers();
}

static void test_fanotify(unsigned int n)
{
	int ret, len = 0, i = 0, test_num = 0;
	struct tcase *tc = &tcases[n];
	struct event *event_set = tc->event_set;

	if (setup_mark(n) != 0)
		return;

	sprintf(lookup_path, "%s/enoent_%u", access_dir, n);
	sprintf(newent_path, "%s/newent_%u", access_dir, n);
	sprintf(entry_path, "%s/entry_%u", access_dir, n);
	sprintf(renamed_path, "%s/renamed_%u", access_dir, n);

	run_child(tc);

	/*
	 * Process events
	 *
	 * even if we do not expect another event, let read() wait for child
	 * process to exit and accomodate for multiple access events
	 */
	while (test_num < EVENT_SET_MAX && fd_notify != -1) {
		struct fanotify_event_metadata *event;
		struct fanotify_event_info_fid *event_fid;
		struct fanotify_event_info_fid *child_fid = NULL;
		struct file_handle *file_handle = NULL;
		const char *filename = NULL;
		const char *exp_name;
		int matched = 0;
		unsigned int fhlen = 0;
		int namelen = 0;

		if (i == len) {
			/* Get more events */
			ret = read(fd_notify, event_buf + len,
				   EVENT_BUF_LEN - len);
			/* Received SIGCHLD */
			if (fd_notify == -1)
				break;
			if (ret < 0) {
				tst_brk(TBROK,
					"read(%d, buf, %zu) failed",
					fd_notify, EVENT_BUF_LEN);
			}
			len += ret;
		}

		/*
		 * If we got an event after the last event and the last event was
		 * an allowed FAN_PRE_ACCESS event, then assume this is another
		 * event of the same type.
		 * This is to accomodate for the fact that a single execve() may
		 * generate an unknown number of FAN_PRE_ACCESS events if they
		 * are allowed.
		 */
		if (test_num > 0 && !event_set[test_num].mask &&
		    event_set[test_num-1].mask == FAN_PRE_ACCESS &&
		    event_set[test_num-1].response == FAN_ALLOW)
			test_num--;

		event = (struct fanotify_event_metadata *)&event_buf[i];
		event_fid = (struct fanotify_event_info_fid *)(event + 1);
		if (event_fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID ||
		    event_fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
			file_handle = (struct file_handle *)event_fid->handle;
			fhlen = file_handle->handle_bytes;
			filename = (char *)file_handle->f_handle + fhlen;
			child_fid = (void *)((char *)event_fid + event_fid->hdr.len);
			namelen = (char *)child_fid - (char *)filename;
			/* End of event_fid could have name, zero padding, both or none */
			if (namelen > 0) {
				namelen = strlen(filename);
			} else {
				filename = "";
				namelen = 0;
			}
			/* Is there a child fid after first fid record? */
			if (((char *)child_fid - (char *)event) >= event->event_len)
				child_fid = NULL;
		}

		exp_name = event_set[test_num].name ?
			   path_name(event_set[test_num].name) : "";

		/*
		 * Permission events cannot be merged, so the event mask
		 * reported should exactly match the event mask within the
		 * event set.
		 */
		if (event->mask != event_set[test_num].mask) {
			tst_res(TFAIL,
				"got event: mask=%llx (expected %llx) "
				"pid=%u fd=%d",
				(unsigned long long)event->mask,
				event_set[test_num].mask,
				(unsigned int)event->pid, event->fd);
		} else if (event->pid != child_pid) {
			tst_res(TFAIL,
				"got event: mask=%llx pid=%u "
				"(expected %u) fd=%d",
				(unsigned long long)event->mask,
				(unsigned int)event->pid,
				(unsigned int)child_pid,
				event->fd);
		} else if (!fhlen || !filename) {
			tst_res(TFAIL,
				"got event without fid: mask=%llx pid=%u fd=%d, "
				"len=%d info_type=%d info_len=%d fh_len=%d, namelen=%d",
				(unsigned long long)event->mask,
				(unsigned int)event->pid, event->fd,
				event->event_len, event_fid->hdr.info_type,
				event_fid->hdr.len, fhlen, namelen);
		} else if (strcmp(filename, exp_name)) {
			tst_res(TFAIL,
				"got event: mask=%llx pid=%u fd=%d filename=%s "
				"(expected %s)",
				(unsigned long long)event->mask,
				(unsigned int)event->pid, event->fd,
				filename, exp_name);
		} else {
			matched = 1;
			tst_res(TPASS,
				"got event: mask=%llx pid=%u fd=%d filename=%s",
				(unsigned long long)event->mask,
				(unsigned int)event->pid, event->fd,
				filename);
		}

		/* Write response to the permission event */
		if (event->fd >= 0) {
			struct fanotify_response resp;

			resp.fd = event->fd;
			resp.response = event_set[test_num].response;
			/* Do not populate an entry for an unexpected event */
			if (resp.response == FAN_ALLOW_ENOENT && !matched) {
				resp.response = FAN_ALLOW;
			} else if (resp.response == FAN_ALLOW_ENOENT) {
				/* Populate the entry in the dir via the ignored bind mount */
				int dirfd = open_by_handle_at(bind_mount_fd, file_handle,
							      O_RDONLY | O_DIRECTORY);

				if (dirfd < 0)
					tst_brk(TBROK | TERRNO, "open_by_handle_at() failed");
				if (mknodat(dirfd, filename, S_IFREG | 0600, 0))
					tst_brk(TBROK | TERRNO, "mknodat(%s) failed", filename);
				SAFE_CLOSE(dirfd);
				resp.response = FAN_ALLOW;
			}
			SAFE_WRITE(SAFE_WRITE_ALL, fd_notify, &resp, sizeof(resp));
			tst_res(TPASS, "response=%x fd=%d", resp.response, resp.fd);
		}

		i += event->event_len;

		if (child_fid)
			file_handle = (struct file_handle *)child_fid->handle;

		/* open fd by handle instead of using the event->fd */
		if (file_handle) {
			if (event->fd >= 0)
				SAFE_CLOSE(event->fd);

			/* Verify that fd opened from ignored bind mount does not generate events */
			event->fd = open_by_handle_at(bind_mount_fd, file_handle, O_RDONLY);
			if (event->fd < 0)
				tst_res(TFAIL | TERRNO, "failed to open fd by handle");
			else
				tst_res(TINFO, "opened fd %d by handle", event->fd);
		}
		if (event->fd >= 0) {
			char c;

			if (event->mask & FAN_PRE_DIR_ACCESS) {
				/*
				 * Verify that lookup with a directory event fd does not
				 * generate FAN_PRE_DIR_ACCESS events.
				 */
				sprintf(notfound, "nonotify_%d", (int)(tc - tcases));
				TST_EXP_FAIL(faccessat(event->fd, notfound, F_OK, 0),
					     ENOENT, "faccessat(%d, %s)",
					     event->fd, notfound);
			} else {
				/* Verify that read from event fd does not generate events */
				SAFE_READ(0, event->fd, &c, 1);
			}
			SAFE_CLOSE(event->fd);
		}

		test_num++;
	}

	for (; event_set[test_num].mask && test_num < EVENT_SET_MAX; test_num++) {
		tst_res(TFAIL, "didn't get event: mask=%llx filename=%s",
			event_set[test_num].mask,
			event_set[test_num].name ?: "");

	}

	check_child();

	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);

	mount_cycle();
}

static void setup(void)
{
	char path[BUF_SIZE];

	page_sz = getpagesize();

	sprintf(fname, "%s/fname_%d", access_dir, getpid());
	sprintf(exec_path, "%s/%s", access_dir, TEST_APP);

	/* Create the test files on the watched filesystem */
	SAFE_MKDIR(watch_dir, 0755);
	watch_path(path, fname);
	SAFE_FILE_PRINTF(path, "1");
	SAFE_TRUNCATE(path, page_sz*101);

	require_fanotify_pre_content_fid_supported_on_fs(path);
	pre_dir_access_unsupported = fanotify_flags_supported_on_fs(
						FAN_CLASS_PRE_CONTENT |
						FAN_REPORT_DFID_NAME_TARGET,
						FAN_MARK_INODE,
						FAN_PRE_DIR_ACCESS, MOUNT_PATH);

	SAFE_CP(TEST_APP, watch_path(path, exec_path));

	mount_cycle();
}

static void cleanup(void)
{
	if (fd_notify > 0)
		SAFE_CLOSE(fd_notify);

	umount_layers();
}

static const char *const resource_files[] = {
	TEST_APP,
	NULL
};

static struct tst_test test = {
	.timeout = 1,
	.test = test_fanotify,
	.tcnt = ARRAY_SIZE(tcases),
	.setup = setup,
	.cleanup = cleanup,
	.forks_child = 1,
	.needs_root = 1,
	.mount_device = 1,
	.all_filesystems = 1,
	.mntpoint = MOUNT_PATH,
	.resource_files = resource_files
};

#else
	TST_TEST_TCONF("system doesn't have required fanotify support");
#endif
