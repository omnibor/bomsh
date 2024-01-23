/*
 * Copyright (c) 2024, Cisco and/or its affiliates.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/omnibor/bomsh/blob/main/LICENSE
 */

#ifndef BOMSH_CONFIG_H
#define BOMSH_CONFIG_H

struct bomsh_configs {
	char *hook_script_file;
	char *hook_script_cmdopt;
	char *shell_cmd_file;
	char *tmpdir;
	char *logfile;
	char *raw_logfile;
	char *syscalls;

	// SHA1/SHA256/both, default is 0, means SHA1 only.
	// if <0, no hash computation; if >3, same as default of 0
	// SHA1 = 1, SHA256 = 2, SHA1 + SHA256 = 3, DEFAULT=0
	int hash_alg;

	// what metadata to record? build_tool, dynlib, etc.
	//int metadata_to_record;
	//
	// generate dependency for C compilation? use separate subprocess or instrument same process with extra "-MD -MF depfile"?
	// 0 generates depfile with instrumentation, 1 generates with subprocess, and 2 not generating depfile
	int generate_depfile;

	// conftest/conftest.o/libconftest.a are output files during ./configure
	// these output files are ignored by default, since they are not very useful.
	int handle_conftest;

	// handle the GNU AS command, which is ignored by default.
	int handle_gnu_as_cmd;

	// handle the dpkg-deb and rpmbuild command, which is ignored by default.
	int handle_pkg_build_cmd;

	// trace EXECVE commands only, skip handling shell commands
	int trace_execve_cmd_only;

	// by default, we check prog R_OK|X_OK permission before recording a command.
	// the below flag will turn off/on this permission check
	int skip_checking_prog_access;

	// By default, we support non-standard install location of tools, for gcc/clang/ld/patch, etc.
	// The below flag turn on strict (or exact) prog path check/comparison,
	// which disables support of non-standard install location of tools.
	int strict_prog_path;
};
extern struct bomsh_configs g_bomsh_config;

// use below for verbosity log_level to indicate logging to raw_logfiles.
#define BOMSH_RAW_LOGFILE -1
#define BOMSH_RAW_LOGFILE2 -2

struct bomsh_globals {
	// output file for logging, with verbosity level support.
	FILE *logfile;

	// output file for OmniBOR raw logging of ADFs (Artifact Dependency Fragments).
	FILE *raw_logfile;

	// for sha256 logging if both SHA1 + SHA256 for g_bomsh_config.hash_alg = 3
	FILE *raw_logfile2;
};
extern struct bomsh_globals g_bomsh_global;

extern int bomsh_verbose;
extern int bomsh_detach_on_pid;
extern int bomsh_is_pre_exec_program(char *prog);
extern int bomsh_is_watched_program(char *prog);
extern int bomsh_is_detach_on_pid_program(char *prog);
extern pid_t *bomsh_umbrella_pid_stack;
extern int bomsh_umbrella_pid_top;
extern int bomsh_is_umbrella_program(char *prog);
extern char *bomsh_basename(char *path);

extern void bomsh_log_printf(int log_level, const char *fmt, ...);
extern void bomsh_log_string(int log_level, const char *str);

extern void strace_set_outfname(const char *fname);
extern void strace_init(int argc, char *argv[]);
extern void bomsh_init(int argc, char *argv[]);

// read file content, and save file_size to read_len if read_len is not NULL.
// read one-byte more than file size, and last byte is set to 0 for NULL-terminating string.
extern char * bomsh_read_file(const char *filepath, long *read_len);

// read /proc files like /proc/pid/stat, /proc/pid/cmdline, etc.
extern char * bomsh_read_proc_file(const char *filepath, long *read_len);

// check if a path ends with a specific suffix, progs array must be sorted
int bomsh_path_endswith(const char *path, const char **progs, int num_progs);

#endif /* !BOMSH_CONFIG_H */
