/*
 * Copyright (c) 2024, Cisco and/or its affiliates.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/omnibor/bomsh/blob/main/LICENSE
 *
 * Bomsh config/init/log functions for bomtrace.
 * January 2024, Yongkui Han
 */

#include "defs.h"
#include <stdarg.h>
#include <getopt.h>
#include "config.h"
#include "bomsh_config.h"
#include "bomsh_hook.h"

// read all data from the file FILEPATH and malloc the required buffer.
// returned buffer needs to be freed by the caller
// if READ_LEN is not NULL, then file size is written to READ_LEN
char * bomsh_read_file(const char *filepath, long *read_len)
{
        char * buffer = 0;
        long length;
        FILE * f = fopen (filepath, "rb");

        if (f) {
                fseek(f, 0, SEEK_END);
                length = ftell(f);
                fseek (f, 0, SEEK_SET);
		if (read_len) {
			*read_len = length;
		}
		// allocate 1-byte more for NULL-terminated buffer
                buffer = malloc(length+1);
                if (buffer) {
                        if (fread(buffer, 1, length, f) > 0) {
                                buffer[length] = 0;
                        }
                        buffer[length] = 0;
                }
                fclose (f);
        }
        return buffer;
}

// this below function works for /proc/pid/cmdline file reading for file size
// read all data from the file FILEPATH and malloc the required buffer.
// returned buffer needs to be freed by the caller, also set the read_len
char * bomsh_read_proc_file(const char *filepath, long *read_len)
{
	char * buffer = 0;
	long length = 0;
	FILE * f = fopen (filepath, "rb");

	if (f) {
		char buf[512]; size_t read_bytes = 0;
		while ((read_bytes = fread(buf, 1, 512, f)) > 0) {
			length += read_bytes;
		}
		if (read_len) {
			*read_len = length;
		}
		fseek (f, 0, SEEK_SET);
		// allocate 1-byte more for NULL-terminated buffer
		buffer = malloc(length+1);
		if (buffer) {
			if (fread(buffer, 1, length, f) > 0) {
				buffer[length] = 0;
			}
			buffer[length] = 0;
		}
		fclose (f);
	}
	return buffer;
}

// global variables
struct bomsh_configs g_bomsh_config;
struct bomsh_globals g_bomsh_global;

// a special mode to trace openat/close syscalls and record checksums of interested files.
int bomsh_openat_mode = 0;
int bomsh_openat_fd = -1;
//static int bomsh_openat_fd_closed = 0;
int bomsh_openat_fd_pid = -1;

int bomsh_detach_on_pid = -5;

// the debugging verbose level for bomtrace
int bomsh_verbose = 0;

// 100 programs should be sufficient for most software builds
#define BOMSH_MAX_WATCHED_PROGRAMS 100
static char *bomsh_watched_programs_str = NULL;
static char **bomsh_pre_exec_programs = 0;
static int bomsh_num_pre_exec_programs = 0;
static char **bomsh_watched_programs = 0;
static char **bomsh_detach_on_pid_programs = 0;
static int bomsh_num_watched_programs = 0;
static int bomsh_num_detach_on_pid_programs = 0;
// umbrella pid feature to improve performance
// only the child processes of umbrella process are recorded and run hookup
static char **bomsh_umbrella_programs = 0;
static int bomsh_num_umbrella_programs = 0;
pid_t *bomsh_umbrella_pid_stack = 0;
int bomsh_umbrella_pid_top = -1;

// This list only contains the name (or basename) of the watched programs
static char **bomsh_watched_program_names = 0;
static int bomsh_num_watched_program_names = 0;
static char **bomsh_pre_exec_program_names = 0;
static int bomsh_num_pre_exec_program_names = 0;

//#define BOMSH_PRINT_CONFIGS
#ifdef BOMSH_PRINT_CONFIGS
static void bomsh_print_programs(char **progs, int num_progs, const char *which_progs)
{
	if (!progs) {
		return;
	}
	fprintf(stderr, "\n start printing %s programs:\n", which_progs);
	for (int i=0; i<num_progs; i++) {
		if (!progs[i]) {
			break;
		}
		fprintf(stderr, "%s\n", progs[i]);
	}
}
#endif

#if 0
// find the index of array element that equals path.
// return -1 if the element cannot be found
static int binary_search_program(char *array[], char *path, int low, int high) {
	// Repeat until the pointers low and high meet each other
	while (low <= high) {
		int mid = low + (high - low) / 2;
		if (strcmp(array[mid], path) == 0) {
			return mid;
		}
		if (strcmp(array[mid], path) < 0)
			low = mid + 1;
		else
			high = mid - 1;
	}
	return -1;
}
#endif

// return the basename of a path, pointing to the rightmost part of the original string.
char *
bomsh_basename(char *path)
{
	char *s = strrchr(path, '/');
	return s ? (s + 1) : path;
}

static int strcmp_comparator(const void *p, const void *q)
{
	return strcmp(* (char * const *) p, * (char * const *) q);
}

// check if a program is in the watched list.
static int bomsh_is_program_inlist(char *prog, char **prog_list, int num_progs)
{
	return bsearch(&prog, prog_list, num_progs, sizeof(char *), strcmp_comparator) != NULL;
	//return binary_search_program(prog_list, prog, 0, num_progs - 1) != -1;
}

// special programs that are usually named with some prefix
static const char *bomsh_special_progs[] = {"gcc", "cc", "g++", "clang", "clang++", "strip", "objcopy", "ld", "ld.gold", "ld.bfd", "ar", "ranlib"} ;
//static const char *bomsh_special_progs[] = {"gcc", "cc", "g++", "clang", "clang++", "strip", "objcopy", "ld", "ld.gold", "ld.bfd", "ar", "as", "ranlib"} ;
static const char *bomsh_special_pre_exec_progs[] = {"strip", "objcopy", "ranlib", "ar"} ;

// check if a path ends with a specific suffix, progs array must be sorted
int bomsh_path_endswith(const char *path, const char **progs, int num_progs)
{
	char *string = strrchr(path, '-');
	if (!string) {
		string = (char *)(path - 1);
	}
	return bomsh_is_program_inlist(string + 1, (char **)progs, num_progs);
}

// on some platforms, strip/objcopy/ranlib tool is named with some prefix,
// like x86_64-xr-linux-clang on Yocto,
// or /usr/bin/x86_64-mageia-linux-gnu-gcc on Mageia.
// Try to cover them as special watched program.
static int
bomsh_is_special_watched_pre_exec_program(const char *path)
{
	return bomsh_path_endswith(path, bomsh_special_pre_exec_progs,
			sizeof(bomsh_special_pre_exec_progs)/sizeof(*bomsh_special_pre_exec_progs));
}

// check if a program is in the pre-exec mode program list.
int bomsh_is_pre_exec_program(char *prog)
{
	if (!bomsh_pre_exec_programs) {  // there is no any watched program, so matching any program
		return 1;
	}
	if (g_bomsh_config.strict_prog_path) {
		return bomsh_is_program_inlist(prog, bomsh_pre_exec_programs, bomsh_num_pre_exec_programs);
	} else {
		char *name = bomsh_basename(prog);
		return bomsh_is_program_inlist(name, bomsh_pre_exec_program_names, bomsh_num_pre_exec_program_names)
			|| bomsh_is_special_watched_pre_exec_program(prog);
	}
}

// on some platforms, gcc compiler or ld tool is installed to non-standard location,
// like /usr/lib64/gcc/x86_64-suse-linux/7/../../../../x86_64-suse-linux/bin/ld on OpenSUSE,
// or /usr/bin/x86_64-mageia-linux-gnu-gcc on Mageia.
// or different versions of clang compilers.
// Try to cover them as special watched program.
static int
bomsh_is_special_watched_program(const char *path)
{
	/*int len = strlen(path);
	if (len < 4) return 0;
	if (path[len - 3] == '/' && path[len - 2] == 'l' && path[len - 1] == 'd') return 1;
	if (strcmp(path + len - 3, "-cc") == 0 || strcmp(path + len - 3, "/cc") == 0) return 1;
	if (strcmp(path + len - 4, "-gcc") == 0 || strcmp(path + len - 4, "/gcc") == 0) return 1;*/
	if (strncmp(bomsh_basename((char *)path), "clang", 5) == 0) return 1;
	return bomsh_path_endswith(path, bomsh_special_progs, sizeof(bomsh_special_progs)/sizeof(*bomsh_special_progs));
}

// check if a program is in the watched list.
int bomsh_is_watched_program(char *prog)
{
	if (!bomsh_watched_programs) {  // there is no any watched program, so matching any program
		return 1;
	}
	if (g_bomsh_config.strict_prog_path) {
		return bomsh_is_program_inlist(prog, bomsh_watched_programs, bomsh_num_watched_programs);
	} else {
		char *name = bomsh_basename(prog);
		return bomsh_is_program_inlist(name, bomsh_watched_program_names, bomsh_num_watched_program_names)
			|| bomsh_is_special_watched_program(prog);
	}
}

// check if a program is in the detach_on_pid list.
int bomsh_is_detach_on_pid_program(char *prog)
{
	if (!bomsh_detach_on_pid_programs) {  // there is no any detach_on_pid program, so matching none.
		return 0;
	}
	return bomsh_is_program_inlist(prog, bomsh_detach_on_pid_programs, bomsh_num_detach_on_pid_programs);
}

// check if a program is in the umbrella list.
int bomsh_is_umbrella_program(char *prog)
{
	if (!bomsh_umbrella_programs) {  // there is no any umbrella program, so matching none.
		return 0;
	}
	return bomsh_is_program_inlist(prog, bomsh_umbrella_programs, bomsh_num_umbrella_programs);
}

// Extract list of programs from the string and save them into an array of pointers.
// The programs_str contains the list of programs separated by newline character.
static char **
bomsh_get_watched_programs(char *programs_str, int *num_programs)
{
        char ** ret_watched_progs;
        char * watched_progs[BOMSH_MAX_WATCHED_PROGRAMS];
	char delim[] = "\n";

	int i = 0;
	char *ptr = strtok(programs_str, delim);
	while(ptr != NULL)
	{
		if (strlen(ptr) > 0 && ptr[0] != '#') {
			watched_progs[i] = ptr; i++;
			if (i >= BOMSH_MAX_WATCHED_PROGRAMS) {
				fprintf(stderr, "Maximum reached, only the first %d programs are read\n", BOMSH_MAX_WATCHED_PROGRAMS);
				goto ret_here;
			}
		}
		ptr = strtok(NULL, delim);
	}
	if (i == 0) {  // need at least one watched program
		//fprintf(stderr, "No watched program is read\n");
		return NULL;
	}
ret_here:
	ret_watched_progs = (char **)malloc( i * sizeof(char *) );
	//fprintf(stderr, "progs: %p num: %d\n", ret_watched_progs, i);
	if (!ret_watched_progs) {
		return NULL;
	}
	*num_programs = i;
	for(i=0; i < *num_programs; i++) {
		ret_watched_progs[i] = watched_progs[i];
	}
	// sort the array for binary search
	qsort(ret_watched_progs, i, sizeof(char *), strcmp_comparator);
	return ret_watched_progs;
}

/*
 * Each line is a program to watch, there should be no leading or trailing spaces.
 * Empty line or line starting with '#' character will be ignored.
 * pre-exec mode programs are also in this file, separated by an exact line of "---"
 * detach_on_pid programs are also in this file, separated by an exact line of "==="
 * umbrella programs are also in this file, separated by an exact line of "+++"
 */
static char **
bomsh_read_watched_programs(char *prog_file)
{
	bomsh_watched_programs_str = bomsh_read_file(prog_file, NULL);
	if (!bomsh_watched_programs_str) {
		fprintf(stderr, "Cannot open the watched program list file\n");
		return NULL;
	}
	// must search sep_line in reversed order, since we set NULL character
	char *plus_sep_line = strstr(bomsh_watched_programs_str, "+++");
        if (plus_sep_line) {
		*plus_sep_line = 0;
		plus_sep_line += 4;  // move to start of umbrella program list
	}
	char *equal_sep_line = strstr(bomsh_watched_programs_str, "===");
        if (equal_sep_line) {
		*equal_sep_line = 0;
		equal_sep_line += 4;  // move to start of detach-on-pid program list
	}
	char *minus_sep_line = strstr(bomsh_watched_programs_str, "---");
        if (minus_sep_line) {
		*minus_sep_line = 0;
		minus_sep_line += 4;  // move to start of pre-exec program list
	}
	char ** watched_progs;
	watched_progs = bomsh_get_watched_programs(bomsh_watched_programs_str, &bomsh_num_watched_programs);
	if (minus_sep_line) {
		bomsh_pre_exec_programs = bomsh_get_watched_programs(minus_sep_line, &bomsh_num_pre_exec_programs);
	}
	if (equal_sep_line) {
		bomsh_detach_on_pid_programs = bomsh_get_watched_programs(equal_sep_line, &bomsh_num_detach_on_pid_programs);
	}
	if (plus_sep_line) {
		bomsh_umbrella_programs = bomsh_get_watched_programs(plus_sep_line, &bomsh_num_umbrella_programs);
		if (bomsh_umbrella_programs) {
			bomsh_umbrella_pid_stack = malloc(sizeof(pid_t) * 64);
			//fprintf(stderr, "alloc umbrella_stack: %p pid_top: %d\n", bomsh_umbrella_pid_stack, bomsh_umbrella_pid_top);
			if (!bomsh_umbrella_pid_stack) {
				fprintf(stderr, "Failed to alloc memory.");
			}
		}
	}

	if (!watched_progs && !bomsh_detach_on_pid_programs && !bomsh_pre_exec_programs && !bomsh_umbrella_programs) {
		// only if there is no any programs, then we can delete this string
		free(bomsh_watched_programs_str);
		return NULL;
	}
#ifdef BOMSH_PRINT_CONFIGS
if (bomsh_verbose > 2) {
	bomsh_print_programs(watched_progs, bomsh_num_watched_programs, "watched_progs");
	bomsh_print_programs(bomsh_pre_exec_programs, bomsh_num_pre_exec_programs, "pre_exec_progs");
	bomsh_print_programs(bomsh_detach_on_pid_programs, bomsh_num_detach_on_pid_programs, "detach_on_pid");
	bomsh_print_programs(bomsh_umbrella_programs, bomsh_num_umbrella_programs, "umbrella_progs");
}
#endif
	// bomsh_watched_programs_str contains strings that are referenced by pointers of some progs
	// thus its memory must not be freed.
	return watched_progs;
}

static void
bomsh_log_configs(int level)
{
	bomsh_log_string(level, "\n---Printing bomtrace configs:\n");
	bomsh_log_printf(level, "hook_script_file: %s\n", g_bomsh_config.hook_script_file);
	bomsh_log_printf(level, "hook_script_cmdopt: %s\n", g_bomsh_config.hook_script_cmdopt);
	bomsh_log_printf(level, "shell_cmd_file: %s\n", g_bomsh_config.shell_cmd_file);
	bomsh_log_printf(level, "tmpdir: %s\n", g_bomsh_config.tmpdir);
	bomsh_log_printf(level, "logfile: %s\n", g_bomsh_config.logfile);
	bomsh_log_printf(level, "raw_logfile: %s\n", g_bomsh_config.raw_logfile);
	bomsh_log_printf(level, "syscalls: %s\n", g_bomsh_config.syscalls);
	bomsh_log_printf(level, "hash algorithm: %d\n", g_bomsh_config.hash_alg);
	//bomsh_log_printf(level, "metadata to record: %d\n", g_bomsh_config.metadata_to_record);
	bomsh_log_printf(level, "generate depfile: %d\n", g_bomsh_config.generate_depfile);
	bomsh_log_printf(level, "depfile stack offset: %d\n", g_bomsh_config.depfile_stack_offset);
	bomsh_log_printf(level, "handle CGO cc cmd: %d\n", g_bomsh_config.handle_cgo_cc_cmd);
	bomsh_log_printf(level, "handle conftest: %d\n", g_bomsh_config.handle_conftest);
	bomsh_log_printf(level, "handle GNU AS cmd: %d\n", g_bomsh_config.handle_gnu_as_cmd);
	bomsh_log_printf(level, "handle pkg build cmd: %d\n", g_bomsh_config.handle_pkg_build_cmd);
	bomsh_log_printf(level, "trace execve cmd only: %d\n", g_bomsh_config.trace_execve_cmd_only);
	bomsh_log_printf(level, "record raw info flags: 0x%x\n", g_bomsh_config.record_raw_info_flags);
	bomsh_log_printf(level, "skip_checking_prog_access: %d\n", g_bomsh_config.skip_checking_prog_access);
	bomsh_log_printf(level, "strict_prog_path: %d\n", g_bomsh_config.strict_prog_path);
	bomsh_log_string(level, "---End of printing bomtrace configs.\n");
}

#ifdef BOMSH_PRINT_CONFIGS
static void
bomsh_print_configs(void)
{
	fprintf(stderr, "\nPrinting bomtrace configs:\n");
	fprintf(stderr, "hook_script_file: %s\n", g_bomsh_config.hook_script_file);
	fprintf(stderr, "hook_script_cmdopt: %s\n", g_bomsh_config.hook_script_cmdopt);
	fprintf(stderr, "shell_cmd_file: %s\n", g_bomsh_config.shell_cmd_file);
	fprintf(stderr, "tmpdir: %s\n", g_bomsh_config.tmpdir);
	fprintf(stderr, "logfile: %s\n", g_bomsh_config.logfile);
	fprintf(stderr, "raw_logfile: %s\n", g_bomsh_config.raw_logfile);
	fprintf(stderr, "syscalls: %s\n", g_bomsh_config.syscalls);
	fprintf(stderr, "hash algorithm: %d\n", g_bomsh_config.hash_alg);
	//fprintf(stderr, "metadata to record: %d\n", g_bomsh_config.metadata_to_record);
	fprintf(stderr, "generate depfile: %d\n", g_bomsh_config.generate_depfile);
	fprintf(stderr, "depfile stack offset: %d\n", g_bomsh_config.depfile_stack_offset);
	fprintf(stderr, "handle CGO cc cmd: %d\n", g_bomsh_config.handle_cgo_cc_cmd);
	fprintf(stderr, "handle conftest: %d\n", g_bomsh_config.handle_conftest);
	fprintf(stderr, "handle GNU AS cmd: %d\n", g_bomsh_config.handle_gnu_as_cmd);
	fprintf(stderr, "handle pkg build cmd: %d\n", g_bomsh_config.handle_pkg_build_cmd);
	fprintf(stderr, "trace execve cmd only: %d\n", g_bomsh_config.trace_execve_cmd_only);
	fprintf(stderr, "record raw info flags: 0x%x\n", g_bomsh_config.record_raw_info_flags);
	fprintf(stderr, "skip_checking_prog_access: %d\n", g_bomsh_config.skip_checking_prog_access);
	fprintf(stderr, "strict_prog_path: %d\n", g_bomsh_config.strict_prog_path);
}
#endif

// Create a sorted array of pointers to the basename of watched programs.
static char **
create_watched_program_names(char **watched_programs, int num_watched_programs)
{
	int i;
	if (num_watched_programs == 0) {
		return NULL;
	}
	char ** ret_watched_progs = (char **)malloc( num_watched_programs * sizeof(char *) );
	for (i=0; i<num_watched_programs; i++) {
		ret_watched_progs[i] = bomsh_basename(watched_programs[i]);
	}
	// sort the array for binary search
	qsort(ret_watched_progs, num_watched_programs, sizeof(char *), strcmp_comparator);
	return ret_watched_progs;
}

// read the configuration key/value from the current key=value line
static void
bomsh_read_value_for_keys(char *line_start, char *value_equal, char *value_newline)
{
	char *hash_alg_str = NULL;
	char *generate_depfile_str = NULL;
	char *depfile_stack_offset_str = NULL;
	char *handle_cgo_cc_cmd_str = NULL;
	char *handle_conftest_str = NULL;
	char *handle_gnu_as_cmd_str = NULL;
	char *handle_pkg_build_cmd_str = NULL;
	char *trace_execve_cmd_only_str = NULL;
	char *record_raw_info_flags_str = NULL;
	char *skip_checking_prog_access_str = NULL;
	char *strict_prog_path_str = NULL;
	static const char *bomsh_config_keys[] = {"hook_script_file", "hook_script_cmdopt", "shell_cmd_file",
						"tmpdir", "logfile", "raw_logfile", "syscalls",
						"hash_alg", "generate_depfile", "depfile_stack_offset", "handle_cgo_cc_cmd",
						"handle_conftest", "handle_gnu_as_cmd", "handle_pkg_build_cmd",
						"trace_execve_cmd_only", "record_raw_info_flags",
						"skip_checking_prog_access", "strict_prog_path"};
	char ** bomsh_config_fields[] = {
		&g_bomsh_config.hook_script_file,
		&g_bomsh_config.hook_script_cmdopt,
		&g_bomsh_config.shell_cmd_file,
		&g_bomsh_config.tmpdir,
		&g_bomsh_config.logfile,
		&g_bomsh_config.raw_logfile,
		&g_bomsh_config.syscalls,
		&hash_alg_str,
		&generate_depfile_str,
		&depfile_stack_offset_str,
		&handle_cgo_cc_cmd_str,
		&handle_conftest_str,
		&handle_gnu_as_cmd_str,
		&handle_pkg_build_cmd_str,
		&trace_execve_cmd_only_str,
		&record_raw_info_flags_str,
		&skip_checking_prog_access_str,
		&strict_prog_path_str
	};
	int num_keys = sizeof(bomsh_config_keys)/sizeof(char *);
        const char *key; unsigned long len;
	for (int i=0; i < num_keys; i++) {
		key = bomsh_config_keys[i];
		if (strncmp(key, line_start, strlen(key)) == 0) {
			len = value_newline - value_equal ;  // this len includes NULL terminating character
			if (len >= PATH_MAX - sizeof(int) * 3) {
				continue;
			}
			char *buf = malloc(len);
			if (!buf) {
				fprintf(stderr, "Failed to alloc memory.");
				return;
			}
			strncpy(buf, value_equal + 1, len - 1);
			buf[len - 1] = 0;
			if (*(bomsh_config_fields[i])) {
				free(*(bomsh_config_fields[i]));
			}
			*(bomsh_config_fields[i]) = buf;
			//fprintf(stderr, "Read key: %s value: %s\n", key, buf);
			break;
		}
	}
	if (hash_alg_str) {
		g_bomsh_config.hash_alg = atoi(hash_alg_str);
		free(hash_alg_str);
	}
	if (generate_depfile_str) {
		g_bomsh_config.generate_depfile = atoi(generate_depfile_str);
		free(generate_depfile_str);
	}
	if (depfile_stack_offset_str) {
		g_bomsh_config.depfile_stack_offset = atoi(depfile_stack_offset_str);
		free(depfile_stack_offset_str);
	}
	if (handle_cgo_cc_cmd_str) {
		g_bomsh_config.handle_cgo_cc_cmd = atoi(handle_cgo_cc_cmd_str);
		free(handle_cgo_cc_cmd_str);
	}
	if (handle_conftest_str) {
		g_bomsh_config.handle_conftest = atoi(handle_conftest_str);
		free(handle_conftest_str);
	}
	if (handle_gnu_as_cmd_str) {
		g_bomsh_config.handle_gnu_as_cmd = atoi(handle_gnu_as_cmd_str);
		free(handle_gnu_as_cmd_str);
	}
	if (handle_pkg_build_cmd_str) {
		g_bomsh_config.handle_pkg_build_cmd = atoi(handle_pkg_build_cmd_str);
		free(handle_pkg_build_cmd_str);
	}
	if (trace_execve_cmd_only_str) {
		g_bomsh_config.trace_execve_cmd_only = atoi(trace_execve_cmd_only_str);
		free(trace_execve_cmd_only_str);
	}
	if (record_raw_info_flags_str) {
		g_bomsh_config.record_raw_info_flags = atoi(record_raw_info_flags_str);
		free(record_raw_info_flags_str);
	}
	if (skip_checking_prog_access_str) {
		if (strcmp(skip_checking_prog_access_str, "1") == 0) {
			g_bomsh_config.skip_checking_prog_access = 1;
		} else {
			g_bomsh_config.skip_checking_prog_access = 0;
		}
		free(skip_checking_prog_access_str);
	}
	if (strict_prog_path_str) {
		if (strcmp(strict_prog_path_str, "1") == 0) {
			g_bomsh_config.strict_prog_path = 1;
		} else {
			g_bomsh_config.strict_prog_path = 0;
		}
		free(strict_prog_path_str);
	}
}

// scan the config file and read all the configuration keys and values
static void
bomsh_read_configs(char *config_file)
{
	char *bomsh_configs_str = bomsh_read_file(config_file, NULL);
	if (!bomsh_configs_str) {
		fprintf(stderr, "Cannot open the config file %s\n", config_file);
		return;
	}
        char *p = bomsh_configs_str;  // pointing to current character
        char *q = bomsh_configs_str;  // pointing to the beginning of current line
        char *r = NULL;  // pointing to the first '=' character in the line
        while (*p) {
		if (*p == '=' && !r) {  // move to the first '=' character in the line
			r = p;
		}
		else if (*p == '\n') {
			if (*q != '#' && *q != '\n' && r > q && r < p) {  // found one valid line of key=value
				bomsh_read_value_for_keys(q, r, p);
			}
			q = p + 1;  // move to the beginning of next line
			r = NULL;  // set to NULL for next line
		}
		p++;
	}
}

// initialize 3 log files for later use
static int bomsh_init_logfiles(void)
{
	char buf[PATH_MAX];
	if (!g_bomsh_config.tmpdir) {
		g_bomsh_config.tmpdir = (char *)"/tmp";
	}
	// first one is for debug purpose
	if (g_bomsh_config.logfile && g_bomsh_config.logfile[0] == 0) {
		// logfile="", if user configures so, then there will be no debug logfile at all.
	} else {
		if (!g_bomsh_config.logfile) {
			sprintf(buf, "%s/bomsh_hook_bomtrace_logfile", g_bomsh_config.tmpdir);
			g_bomsh_config.logfile = strdup(buf);
			//g_bomsh_config.logfile = (char *)"/tmp/bomsh_hook_bomtrace_logfile";
		}
		g_bomsh_global.logfile = fopen(g_bomsh_config.logfile, "a");
		if (!g_bomsh_global.logfile) {
			fprintf(stderr, "Failed to open logfile: %s\n", g_bomsh_config.logfile);
			return -1;
		}
	}
	if (g_bomsh_config.hash_alg < 0) {
		// negative value means NO_HASH computation at all.
		return 0;
	}
	// The other two are for SHA1/SHA256 hash logging of ADF (Artifact Dependency Fragment)
	if (!g_bomsh_config.raw_logfile) {
		sprintf(buf, "%s/bomsh_hook_raw_logfile", g_bomsh_config.tmpdir);
		g_bomsh_config.raw_logfile = strdup(buf);
		//g_bomsh_config.raw_logfile = (char *)"/tmp/bomsh_hook_raw_logfile";
	}
	if (g_bomsh_config.hash_alg == 3) {
		sprintf(buf, "%s.sha1", g_bomsh_config.raw_logfile);
		g_bomsh_global.raw_logfile = fopen(buf, "a");
		bomsh_log_printf(0, "Logging SHA1 to %s\n", buf);
		sprintf(buf, "%s.sha256", g_bomsh_config.raw_logfile);
		g_bomsh_global.raw_logfile2 = fopen(buf, "a");
		bomsh_log_printf(0, "Logging SHA256 to %s\n", buf);
	} else if (g_bomsh_config.hash_alg == 2) {
		sprintf(buf, "%s.sha256", g_bomsh_config.raw_logfile);
		g_bomsh_global.raw_logfile = fopen(buf, "a");
		bomsh_log_printf(0, "Logging SHA256 to %s\n", buf);
	} else {
		sprintf(buf, "%s.sha1", g_bomsh_config.raw_logfile);
		g_bomsh_global.raw_logfile = fopen(buf, "a");
		bomsh_log_printf(0, "Logging SHA1 to %s\n", buf);
	}
	return 0;
}

static void
bomsh_usage(void)
{
	printf("Usage: bomtrace3 -h [-o FILE] [-c FILE] [-v level] [-w FILE] PROG [ARGS]\n");
	exit(0);
}

//static void ATTRIBUTE_NOINLINE
void bomsh_init(int argc, char *argv[])
{
	int i, c;
	static const char bomsh_optstring[] = "+hc:o:v:w:";

	static const struct option bomsh_longopts[] = {
		{ "help",		no_argument,	   0, 'h' },
		{ "config",		required_argument, 0, 'c' },
		{ "output",		required_argument, 0, 'o' },
		{ "verbose",		required_argument, 0, 'v' },
		{ "watch",		required_argument, 0, 'w' },
		{ 0, 0, 0, 0 }
	};
	char *argv0 = argv[0];
	static const char *bomsh_argv1[] = {"-f", "-s99999", "-e", "trace=execve", "-qqq"};
	static const char *bomsh_argv2[] = {"-f", "-s99999", "-e", "trace=execve", "--seccomp-bpf", "-qqq"};
	const char **bomsh_argv;
	int bomsh_argc;
	strace_set_outfname("/dev/null");
	memset(&g_bomsh_config, 0, sizeof(g_bomsh_config));

	while ((c = getopt_long(argc, argv, bomsh_optstring, bomsh_longopts, NULL)) != EOF) {

		switch (c) {
		case 'h':
			bomsh_usage();
			break;
		case 'o':
			strace_set_outfname(optarg);
			//fprintf(stderr, "set strace outfname: %s\n", optarg);
			break;
		case 'c':
			// read the configuration items from the file
			bomsh_read_configs(optarg);
#ifdef BOMSH_PRINT_CONFIGS
			fprintf(stderr, "reading bomsh config file: %s\n", optarg);
			bomsh_print_configs();
#endif
			break;
		case 'v':
			// set the verbose debugging level
			bomsh_verbose = atoi(optarg);
			break;
		case 'w':
			// read the list of programs from the file
			bomsh_watched_programs = bomsh_read_watched_programs(optarg);
			// sort the bomsh_special_progs array for binary search
			qsort(bomsh_special_progs, sizeof(bomsh_special_progs)/sizeof(*bomsh_special_progs), sizeof(char *), strcmp_comparator);
			qsort(bomsh_special_pre_exec_progs, sizeof(bomsh_special_pre_exec_progs)/sizeof(*bomsh_special_pre_exec_progs), sizeof(char *), strcmp_comparator);
			break;
		default:
			error_msg_and_help(NULL);
			break;
		}
	}

	if (bomsh_init_logfiles() < 0) {
		exit(0);
	}
	bomsh_log_printf(0, "successful with logfiles, verbose level: %d\n", bomsh_verbose);
	bomsh_log_configs(8);
	if (g_bomsh_global.logfile) fflush(g_bomsh_global.logfile);

	argv += optind;
	argc -= optind;
	if (argc <= 0) {
		error_msg_and_help("must have PROG [ARGS]");
	}
	if (!g_bomsh_config.depfile_stack_offset) {
		g_bomsh_config.depfile_stack_offset = 4096;
	}
	if (!g_bomsh_config.strict_prog_path) {
		bomsh_watched_program_names = create_watched_program_names(bomsh_watched_programs, bomsh_num_watched_programs);
		bomsh_num_watched_program_names = bomsh_num_watched_programs;
		bomsh_pre_exec_program_names = create_watched_program_names(bomsh_pre_exec_programs, bomsh_num_pre_exec_programs);
		bomsh_num_pre_exec_program_names = bomsh_num_pre_exec_programs;
#ifdef BOMSH_PRINT_CONFIGS
		bomsh_print_programs(bomsh_watched_program_names, bomsh_num_watched_program_names, "watched_prog_names");
		bomsh_print_programs(bomsh_pre_exec_program_names, bomsh_num_pre_exec_program_names, "pre_exec_prog_names");
		bomsh_print_configs();
#endif
	}
	if (bomsh_detach_on_pid_programs) {
		// cannot use both detach and --seccomp-bpf due to limitation
		bomsh_argv = bomsh_argv1;
		bomsh_argc = sizeof(bomsh_argv1)/sizeof(char *);
	} else {
		bomsh_argv = bomsh_argv2;
		bomsh_argc = sizeof(bomsh_argv2)/sizeof(char *);
	}
	char * trace_syscalls = NULL;
	if (g_bomsh_config.syscalls) {
		trace_syscalls = (char *) malloc(strlen(bomsh_argv[3]) + strlen(g_bomsh_config.syscalls) + 2);
		if (!trace_syscalls) {
			fprintf(stderr, "Failed to alloc memory.");
			exit(0);
		}
		sprintf(trace_syscalls, "%s,%s", bomsh_argv[3], g_bomsh_config.syscalls);
		bomsh_argv[3] = trace_syscalls;  // more syscalls will be traced
		if (strncmp(g_bomsh_config.syscalls, "openat,close", 12) == 0) {
			bomsh_openat_mode = 1;
		}
	}
	int new_argc = argc+bomsh_argc+1;
	char ** new_argv = (char **)malloc( (new_argc+1)* sizeof(char *));
	if (!new_argv) {
		fprintf(stderr, "Failed to alloc memory.");
		exit(0);
	}
	// Copy all options to the new_argv array to apply to strace in the end.
	new_argv[0] = argv0;
	for (i=0; i<bomsh_argc; i++) {
		new_argv[i + 1] = (char *)bomsh_argv[i];
	}
	for (i=0; i<argc; i++) {
		new_argv[bomsh_argc+1+i] = argv[i];
	}
	new_argv[new_argc] = NULL;

	// must reinitialize getopt() by resetting optind to 0
	optind = 0;
	strace_init(new_argc, new_argv);
	free(new_argv);
	if (trace_syscalls) free(trace_syscalls);
	bomsh_hook_init();
}

// bomsh logging functions
static FILE *
bomsh_convert_level_to_logfile(int log_level)
{
	FILE *output = NULL;
	if (log_level == -1) {
		output = g_bomsh_global.raw_logfile;
	} else if (log_level == -2) {
		output = g_bomsh_global.raw_logfile2;
	} else if (log_level <= bomsh_verbose) {
		output = g_bomsh_global.logfile;
	}
	return output;
}

// log_level of -1 means raw_logfile, and -2 means raw_logfile2.
// since there is no log level for raw_logfile/raw_logfile2.
void
bomsh_log_printf(int log_level, const char *fmt, ...)
{
	FILE *output = bomsh_convert_level_to_logfile(log_level);
	if (!output) {
		return;
	}
	va_list args;
	va_start(args, fmt);
	(void)vfprintf(output, fmt, args);
	va_end(args);
}

#ifndef HAVE_FPUTS_UNLOCKED
# define fputs_unlocked fputs
#endif

void
bomsh_log_string(int log_level, const char *str)
{
	FILE *output = bomsh_convert_level_to_logfile(log_level);
	if (!output) {
		return;
	}
	fputs_unlocked(str, output);
}

