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

#ifndef BOMSH_HOOK_H
#define BOMSH_HOOK_H

typedef struct bomsh_cmddata {
	struct bomsh_cmddata *next;
	struct tcb *tcp;
	pid_t pid;
	int refcount; // reference count for this struct, for delaying memory free until the last one
	int skip_record_raw_info; // if non-zero, then skip recording raw info for this cmd

	int num_inputs; // number of input files
	char *pwd;  // current working directory
	char *root;  // root dir for chroot environment
	char *path;  // path of program binary
	char **argv;  // argv array, last array element is NULL pointer
	char *output_file; // the output file of this command
	char **input_files; // the input files of this command, array of pointers, last is NULL
	char **input_files2; // the unchanged input files of this command, array of pointers, last is NULL
	char **input_sha1; // the SHA1 hashes of input files, array of pointers, last is NULL
	char **input_sha256; // the SHA256 hashes of input files, array of pointers, last is NULL
	char *depend_file; // the created depend file for gcc compile
	char **dynlib_files; // the dynamic library files of gcc command, array of pointers, last is NULL

	char *stdin_file; // the stdin for the patch command, which can be a pipe
	char *stdout_file; // the stdout for the cat command, which can be a pipe
	struct bomsh_cmddata *cat_cmd; // the associated cat command for piped patch command
} bomsh_cmd_data_t;

// for the patch command, the input_files contains the list of files to apply the patch,
// and input_sha1 and input_sha256 are the hashes before applying the patch.
// and input_files2 contains the list of patch files themselves, which do not change before and after applying the patch.
// any additional input files that do not change will be put into this input_files2 list.

// record command and run some prehook before EXECVE syscall
extern int bomsh_record_command(struct tcb *tcp, const unsigned int index);

// run the analysis and record raw info after EXECVE syscall
extern void bomsh_hook_program(int pid);

// initialize function
extern void bomsh_hook_init(void);

#endif /* !BOMSH_HOOK_H */
