/*
 * Embedded Linux library
 * Copyright (C) 2017  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ell/ell.h>

enum test_op {
	OP_NULL,
	OP_OPEN,
	OP_CREAT,
	OP_UNLINK,
	OP_TRUNCATE,
	OP_RENAME,
};

struct test_result {
	const char *dir;
	const char *file;
	bool ignore;
	enum l_dir_watch_event event;
};

typedef struct test_result test_result_t;

#define MAX_RESULTS 2

struct test_data {
	enum test_op op;
	const char *orig_dir;
	const char *orig_file;
	const char *dest_dir;
	const char *dest_file;
	unsigned int length;
	const char *content;
	const struct test_result *results[MAX_RESULTS + 1];
};

struct test_entry {
	const struct test_data *data;
	char **test_dirs;
	char **test_files;
	char **watch_dirs;
	unsigned int idx;
	unsigned int res_idx;
	struct l_queue *watch_list;
	bool failed;
};

struct test_watch {
	char *pathname;
	struct test_entry *entry;
};

#define TEST_FULL(_dir, _file, _op) \
			.orig_dir = _dir, .orig_file = _file, .op = _op

#define test_open(_dir, _file, _length) \
			TEST_FULL(_dir, _file, OP_OPEN), .length = _length
#define test_creat(_dir, _file, _content) \
			TEST_FULL(_dir, _file, OP_CREAT), .content = _content
#define test_unlink(_dir, _file) \
			TEST_FULL(_dir, _file, OP_UNLINK)
#define test_truncate(_dir, _file, _length) \
			TEST_FULL(_dir, _file, OP_TRUNCATE), .length = _length
#define test_rename(_olddir, _oldfile, _newdir, _newfile) \
			TEST_FULL(_olddir, _oldfile, OP_RENAME), \
				.dest_dir = _newdir, .dest_file = _newfile

#define RESULT_PTR(_dir, _file, _ignore, _event) \
			(&(test_result_t) { _dir, _file, _ignore, _event })

#define results(args...)	.results = { args, RESULT_PTR(NULL, NULL, true, 0) }

#define created(_dir, _file)	RESULT_PTR(_dir, _file, false, L_DIR_WATCH_EVENT_CREATED)
#define removed(_dir, _file)	RESULT_PTR(_dir, _file, false, L_DIR_WATCH_EVENT_REMOVED)
#define modified(_dir, _file)	RESULT_PTR(_dir, _file, false, L_DIR_WATCH_EVENT_MODIFIED)
#define accessed(_dir, _file)	RESULT_PTR(_dir, _file, false, L_DIR_WATCH_EVENT_ACCESSED)

#define result_ignore()			.results = { RESULT_PTR(NULL, NULL, true, 0) }
#define result_created(_dir, _file)	results(created(_dir, _file))
#define result_removed(_dir, _file)	results(removed(_dir, _file))
#define result_modified(_dir, _file)	results(modified(_dir, _file))
#define result_accessed(_dir, _file)	results(accessed(_dir, _file))

static void start_single_test(void *user_data);

static void event_callback(const char *pathname, enum l_dir_watch_event event,
								void *user_data)
{
	struct test_watch *watch_data = user_data;
	struct test_entry *entry = watch_data->entry;
	const struct test_data *data = &entry->data[entry->idx];
	const struct test_result *result = data->results[entry->res_idx];
	const char *str;

	switch (event) {
	case L_DIR_WATCH_EVENT_CREATED:
		str = "CREATED";
		break;
	case L_DIR_WATCH_EVENT_REMOVED:
		str = "REMOVED";
		break;
	case L_DIR_WATCH_EVENT_MODIFIED:
		str = "MODIFIED";
		break;
	case L_DIR_WATCH_EVENT_ACCESSED:
		str = "ACCESSED";
		break;
	case L_DIR_WATCH_EVENT_ATTRIB:
		str = "ATTRIB";
		break;
	default:
		str = "UNKNOWN";
		break;
	}

	l_debug("l_dir_watch event:%s pathname:%s [%s]", str, pathname,
							watch_data->pathname);

	/* This will result in waiting for the timeout */
	if (result->ignore)
		return;

	/* The watching directory needs to match the watch callback data */
	if (strcmp(result->dir, watch_data->pathname))
		return;

	/* The file inside the watch directory needs to match */
	if (strcmp(result->file, pathname)) {
		entry->failed = true;
		return;
	}

	/* The expected event needs to match as well */
	if (result->event != event) {
		entry->failed = true;
		return;
	}

	/* Successful match of the expected event data */
	l_debug("l_dir_watch ==> MATCH index %u", entry->res_idx);

	if (entry->res_idx < MAX_RESULTS) {
		entry->res_idx++;
		result = data->results[entry->res_idx];
		if (result->dir) {
			/* More results are required to match */
			return;
		}
	}

	/* Move to next test case */
	entry->idx++;
	entry->res_idx = 0;

	l_idle_oneshot(start_single_test, entry, NULL);
}

static void run_cleanup(char **dirs, char **files)
{
	int i;

	for (i = 0; files[i]; i++) {
		l_debug("unlink(\"%s\")", files[i]);
		unlink(files[i]);
	}

	for (i = 0; dirs[i]; i++) {
		l_debug("rmdir(\"%s\")", dirs[i]);
		rmdir(dirs[i]);
	}
}

static void dir_watch_free(void *data)
{
	struct l_dir_watch *watch = data;

	l_debug("free l_dir_watch [%p]", watch);

	l_dir_watch_destroy(watch);
}

static void free_test_entry(void *data)
{
	struct test_entry *entry = data;

	l_debug("free test_entry [%p]", entry);

	l_queue_destroy(entry->watch_list, dir_watch_free);

	/* Clean run should remove any leftovers */
	run_cleanup(entry->test_dirs, entry->test_files);

	l_strv_free(entry->test_dirs);
	l_strv_free(entry->test_files);
	l_strv_free(entry->watch_dirs);

	l_free(entry);
}

static void op_open(const char *dir, const char *file, unsigned int length)
{
	char *pathname;
	int fd, err;

	pathname = l_strdup_printf("%s/%s", dir, file);

	l_debug("open(\"%s\", O_RDONLY)", pathname);
	fd = open(pathname, O_RDONLY);
	l_debug("=> %d", fd);

	if (length > 0) {
		unsigned char *buf = l_malloc(length);
		ssize_t res;

		l_debug("read(%d, %p, %u)", fd, buf, length);
		res = read(fd, buf, length);
		l_debug("=> %zd", res);

		l_free(buf);
	}

	l_debug("close(%d)", fd);
	err = close(fd);
	l_debug("=> %d", err);

	l_free(pathname);
}

static void op_creat(const char *dir, const char *file, const char *content)
{
	char *pathname;
	int fd, err;

	pathname = l_strdup_printf("%s/%s", dir, file);

	l_debug("creat(\"%s\", 0600)", pathname);
	fd = creat(pathname, 0600);
	l_debug("=> %d", fd);

	if (content) {
		int len = strlen(content);
		ssize_t res;

		l_debug("write(%d, \"%s\", %d)", fd, content, len);
		res = write(fd, content, len);
		l_debug("=> %zd", res);
	}

	l_debug("close(%d)", fd);
	err = close(fd);
	l_debug("=> %d", err);

	l_free(pathname);
}

static void op_unlink(const char *dir, const char *file)
{
	char *pathname;
	int err;

	pathname = l_strdup_printf("%s/%s", dir, file);

	l_debug("unlink(\"%s\")", pathname);
	err = unlink(pathname);
	l_debug("=> %d", err);

	l_free(pathname);
}

static void op_truncate(const char *dir, const char *file, unsigned int length)
{
	char *pathname;
	int err;

	pathname = l_strdup_printf("%s/%s", dir, file);

	l_debug("truncate(\"%s\", %u)", pathname, length);
	err = truncate(pathname, length);
	l_debug("=> %d", err);

	l_free(pathname);
}

static void op_rename(const char *olddir, const char *oldfile,
				const char *newdir, const char *newfile)
{
	char *oldpath, *newpath;
	int err;

	oldpath = l_strdup_printf("%s/%s", olddir, oldfile);
	newpath = l_strdup_printf("%s/%s", newdir, newfile);

	l_debug("rename(\"%s\", \"%s\")", oldpath, newpath);
	err = rename(oldpath, newpath);
	l_debug("=> %d", err);

	l_free(oldpath);
	l_free(newpath);
}

static void start_single_test(void *user_data)
{
	struct test_entry *entry = user_data;
	const struct test_data *data = &entry->data[entry->idx];
	const struct test_result *result = data->results[entry->res_idx];
	bool failed = entry->failed;
	bool ignore = false;

	switch (data->op) {
	case OP_NULL:
		free_test_entry(entry);
		assert(!failed);
		l_main_quit();
		return;
	case OP_OPEN:
		op_open(data->orig_dir, data->orig_file, data->length);
		break;
	case OP_CREAT:
		op_creat(data->orig_dir, data->orig_file, data->content);
		break;
	case OP_UNLINK:
		op_unlink(data->orig_dir, data->orig_file);
		break;
	case OP_TRUNCATE:
		op_truncate(data->orig_dir, data->orig_file, data->length);
		break;
	case OP_RENAME:
		op_rename(data->orig_dir, data->orig_file,
					data->dest_dir, data->dest_file);
		break;
	default:
		ignore = true;
		break;
	}

	if (!result->ignore && !ignore)
		return;

	/* Move to next test case */
	entry->idx++;
	entry->res_idx = 0;

	l_idle_oneshot(start_single_test, entry, NULL);
}

static void watch_data_free(void *data)
{
	struct test_watch *watch_data = data;

	l_debug("free test_watch [%s]", watch_data->pathname);

	l_free(watch_data->pathname);
	l_free(watch_data);
}

static void process_test_entry(void *user_data)
{
	struct test_entry *entry = user_data;
	int i;

	/* In case there is any leftovers */
	run_cleanup(entry->test_dirs, entry->test_files);

	/* Create the directories in use */
	for (i = 0; entry->test_dirs[i]; i++) {
		l_debug("mkdir(%s, 0700)", entry->test_dirs[i]);
		mkdir(entry->test_dirs[i], 0700);
	}

	for (i = 0; entry->watch_dirs[i]; i++) {
		struct test_watch *watch_data;
		struct l_dir_watch *watch;

		watch_data = l_new(struct test_watch, 1);
		watch_data->pathname = l_strdup(entry->watch_dirs[i]);
		watch_data->entry = entry;

		l_debug("new test_watch [%s]", watch_data->pathname);

		watch = l_dir_watch_new(watch_data->pathname, event_callback,
						watch_data, watch_data_free);

		l_debug("new l_dir_watch [%p]", watch);

		l_queue_push_tail(entry->watch_list, watch);
	}

	l_idle_oneshot(start_single_test, entry, NULL);
}

static void process_test(const void *data)
{
	const struct test_data *test_data = (const struct test_data *) data;
	struct test_entry *entry;
	int i, exit_status;

	assert(l_main_init());

	l_log_set_stderr();

	entry = l_new(struct test_entry, 1);
	entry->data = test_data;

	for (i = 0; test_data[i].op; i++) {
		char *file;
		int n;

		if (!l_strv_contains(entry->test_dirs, test_data[i].orig_dir))
			entry->test_dirs = l_strv_append(entry->test_dirs,
							test_data[i].orig_dir);

		if (test_data[i].orig_dir) {
			file = l_strdup_printf("%s/%s", test_data[i].orig_dir,
							test_data[i].orig_file);
			if (!l_strv_contains(entry->test_files, file))
				entry->test_files = l_strv_append(entry->test_files,
									file);
			l_free(file);
		}

		if (test_data[i].dest_dir) {
			file = l_strdup_printf("%s/%s", test_data[i].dest_dir,
							test_data[i].dest_file);
			if (!l_strv_contains(entry->test_files, file))
				entry->test_files = l_strv_append(entry->test_files,
									file);
			l_free(file);
		}

		for (n = 0; n < MAX_RESULTS; n++) {
			if (!test_data[i].results[n])
				break;
			if (l_strv_contains(entry->watch_dirs,
						test_data[i].results[n]->dir))
				continue;
			entry->watch_dirs = l_strv_append(entry->watch_dirs,
						test_data[i].results[n]->dir);
		}

	}

	entry->watch_list = l_queue_new();
	entry->failed = false;

	l_idle_oneshot(process_test_entry, entry, NULL);

	exit_status = l_main_run();
	assert(exit_status == EXIT_SUCCESS);

	assert(l_main_exit());
}

#define DIR_1	"/tmp/ell-test-dir-1"
#define DIR_2	"/tmp/ell-test-dir-2"
#define FILE_1	"file-1"
#define FILE_2	"file-2"
#define FILE_3	"file-3"
#define FILE_4	"file-4"

static const struct test_data test_data_1[] = {
	{
		test_creat(DIR_1, FILE_1, NULL),
		result_created(DIR_1, FILE_1),
	},
	{
		test_unlink(DIR_1, FILE_1),
		result_removed(DIR_1, FILE_1),
	},
	{
		test_creat(DIR_1, FILE_2, "File content"),
		result_created(DIR_1, FILE_2),
	},
	{
		test_rename(DIR_1, FILE_2, DIR_1, FILE_3),
		results(removed(DIR_1, FILE_2), created(DIR_1, FILE_3)),
	},
	{
		test_open(DIR_1, FILE_3, 4),
		result_accessed(DIR_1, FILE_3),
	},
	{
		test_truncate(DIR_1, FILE_3, 4),
		result_modified(DIR_1, FILE_3),
	},
	{
		test_unlink(DIR_1, FILE_3),
		result_removed(DIR_1, FILE_3),
	},
	{
		test_creat(DIR_2, FILE_4, NULL),
		result_ignore(),
	},
	{
		test_rename(DIR_2, FILE_4, DIR_1, FILE_4),
		result_created(DIR_1, FILE_4),
	},
	{
		test_rename(DIR_1, FILE_4, DIR_2, FILE_4),
		result_removed(DIR_1, FILE_4),
	},
	{
		test_unlink(DIR_2, FILE_4),
		result_ignore(),
	},
	{ }
};

static const struct test_data test_data_2[] = {
	{
		test_creat(DIR_1, FILE_1, NULL),
		result_created(DIR_1, FILE_1),
	},
	{
		test_rename(DIR_1, FILE_1, DIR_2, FILE_1),
		results(removed(DIR_1, FILE_1), created(DIR_2, FILE_1)),
	},
	{
		test_unlink(DIR_2, FILE_1),
		result_removed(DIR_2, FILE_1),
	},
	{ }
};

static const struct test_data test_data_3[] = {
	{
		test_creat(DIR_1, FILE_1, "X"),
		result_created(DIR_1, FILE_1),
	},
	{
		test_open(DIR_1, FILE_1, 1),
		result_accessed(DIR_1, FILE_1),
	},
	{
		test_unlink(DIR_1, FILE_1),
		result_removed(DIR_1, FILE_1),
	},
	{ }
};

static const struct test_data test_data_4[] = {
	{
		test_creat(DIR_1, FILE_1, "ABC"),
		result_created(DIR_1, FILE_1),
	},
	{
		test_creat(DIR_1, FILE_2, "XYZ"),
		result_created(DIR_1, FILE_2),
	},
	{
		test_rename(DIR_1, FILE_2, DIR_1, FILE_1),
		results(removed(DIR_1, FILE_2), created(DIR_1, FILE_1)),
	},
	{
		test_unlink(DIR_1, FILE_1),
		result_removed(DIR_1, FILE_1),
	},
	{ }
};

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add_data_func("Single directory test",
					test_data_1, process_test, 0);
	l_test_add_data_func("Move between directories",
					test_data_2, process_test, 0);
	l_test_add_data_func("Create and open file",
					test_data_3, process_test, 0);
	l_test_add_data_func("Replace existing file",
					test_data_4, process_test, 0);

	return l_test_run();
}
