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
 * Bomsh hookup functions to record raw info of files during software build.
 * January 2024, Yongkui Han
 */

#include <sys/stat.h>
#include "defs.h"
#include "ptrace.h"
#include "bomsh_hook.h"
#include "bomsh_config.h"

static int strcmp_comparator(const void *p, const void *q)
{
	return strcmp(* (char * const *) p, * (char * const *) q);
}

/* token lists for command line parsing */
static const char *
gcc_skip_token_list[] = {"-MT", "-MF", "-x", "-I", "-B", "-D", "-L", "-isystem", "-iquote", "-idirafter", "-iprefix",
	"-isysroot", "-iwithprefix", "-iwithprefixbefore", "-imultilib", "-include",
	"-dumpdir", "-dumpbase", "-dumpbase-ext",
	"--param", "-main-file-name", "-internal-externc-isystem", "-internal-isystem",
	"-fdebug-compilation-dir", "-ferror-limit", "-fmessage-length",
	"-mrelocation-model", "-mthread-model", "-resource-dir", "-target-cpu"};

static const char *
linker_skip_tokens[] = {"-m", "-z", "-a", "-A", "-b", "-c", "-e", "-f", "-F", "-G", "-u", "-y", "-Y", "-soname", "--wrap",
	"--architecture", "--format", "--mri-script", "--entry", "--auxiliary", "--filter", "--gpsize", "--oformat",
	"--defsym", "--split-by-reloc", "-rpath", "-rpath-link", "--dynamic-linker", "-dynamic-linker", "-plugin"};

static const char *
gnu_as_skip_tokens[] = {"-G", "-I", "--MD", "--defsym", "--debug-prefix-map"};

// strip, eu-strip, dwz, rpmsign are both same input/output file, for a list of multiple files
static const char *
strip_skip_token_list[] = {"-F", "--target", "-I", "--input-target", "-O", "--output-target",
	"-K", "--keep-symbol", "-N", "--strip-symbol", "-R", "--remove-section",
	"--keep-section", "--remove-relocations"};

static const char *eu_strip_skip_token_list[] = {"-F", "-f", "-R", "--remove-section"};

static const char *
dwz_skip_token_list[] = {"-m", "--multifile", "-M", "--multifile-name", "-l", "--low-mem-die-limit", "-L", "--max-die-limit"};

static const char *rpmsign_skip_token_list[] = {"--macros", "--fskpath", "--certpath", "--verityalgo"};

// single file as both input and output
static const char *samefile_converter_list[] = {"ranlib", "objtool", "debugedit", "sortextable", "sorttable", "resolve_btfids"};

static const char *
rustc_skip_token_list[] = {"-C", "-F", "-L", "-W", "-A", "-D", "--out-dir", "--target", "--explain",
	"--crate-type", "--crate-name", "--edition", "--emit", "--print", "--extern", "--cfg", "--cap-lints"};

static void bomsh_token_init(void)
{
	qsort(gcc_skip_token_list, sizeof(gcc_skip_token_list)/sizeof(*gcc_skip_token_list), sizeof(char *), strcmp_comparator);
	qsort(linker_skip_tokens, sizeof(linker_skip_tokens)/sizeof(*linker_skip_tokens), sizeof(char *), strcmp_comparator);
	qsort(gnu_as_skip_tokens, sizeof(gnu_as_skip_tokens)/sizeof(*gnu_as_skip_tokens), sizeof(char *), strcmp_comparator);
	qsort(strip_skip_token_list, sizeof(strip_skip_token_list)/sizeof(*strip_skip_token_list), sizeof(char *), strcmp_comparator);
	qsort(eu_strip_skip_token_list, sizeof(eu_strip_skip_token_list)/sizeof(*eu_strip_skip_token_list), sizeof(char *), strcmp_comparator);
	qsort(dwz_skip_token_list, sizeof(dwz_skip_token_list)/sizeof(*dwz_skip_token_list), sizeof(char *), strcmp_comparator);
	qsort(rpmsign_skip_token_list, sizeof(rpmsign_skip_token_list)/sizeof(*rpmsign_skip_token_list), sizeof(char *), strcmp_comparator);
	qsort(samefile_converter_list, sizeof(samefile_converter_list)/sizeof(*samefile_converter_list), sizeof(char *), strcmp_comparator);
	qsort(rustc_skip_token_list, sizeof(rustc_skip_token_list)/sizeof(*rustc_skip_token_list), sizeof(char *), strcmp_comparator);
}

#if 0
static int bomsh_is_gcc_skip_token(char *token)
{
	int num_tokens = sizeof(gcc_skip_token_list)/sizeof(*gcc_skip_token_list);
	return bsearch(&token, gcc_skip_token_list, num_tokens, sizeof(char *), strcmp_comparator) != NULL;
}

static int bomsh_is_linker_skip_token(char *token)
{
	int num_tokens = sizeof(linker_skip_tokens)/sizeof(*linker_skip_tokens);
	return bsearch(&token, linker_skip_tokens, num_tokens, sizeof(char *), strcmp_comparator) != NULL;
}
#endif

/******** EXECVE instrumentation routines ********/

// create a new memory buffer to hold the argv pointer array and all argument strings
static char *bomsh_create_param_buf(bomsh_cmd_data_t *cmd, int *buf_size)
{
	int argc = cmd->num_argv;
	char buf[PATH_MAX];
	int len = 0;
	if (cmd->root[1]) {
		// inside chroot, we are forced to use /tmp directory
		len = sprintf(buf, "-MD -MF /tmp/bomsh_hook_target_dependency_pid%d.d", cmd->pid);
	} else {
		len = sprintf(buf, "-MD -MF %s/bomsh_hook_target_dependency_pid%d.d", g_bomsh_config.tmpdir, cmd->pid);
	}
	buf[3] = buf[7] = '\0';
	// there are 3 extra parameters for the argv array
	int array_size = (argc + 4) * sizeof(char *);
	int size = array_size + len + 1;
	char *new_param_buf = (char *)malloc(size);
	char **new_array = (char **)new_param_buf;
	new_array += argc;
	// the first argc pointers should be tracee process' memory address,
	// which is not known yet, so use 0x90 as place-holder
	memset(new_param_buf, 0x90, size);
	// initialize the 3 extra argv parameters
	char *q = new_param_buf + array_size;
	memcpy(q, buf, len + 1);
	new_array[0] = q;
	new_array[1] = q + 4;
	new_array[2] = q + 8;
	new_array[3] = NULL;
	if (buf_size) {
		*buf_size = size;
	}
	cmd->depend_file = strdup(buf + 8);
	return new_param_buf;
}

// modify the array pointers with new starting address and tracee_argv
static void bomsh_modify_param_buf(bomsh_cmd_data_t *cmd, char *param_buf, char *new_addr)
{
	char **params = (char **)param_buf;
	for (int i=0; i < cmd->num_argv; i++) {
		params[i] = cmd->tracee_argv[i];
	}
	params += cmd->num_argv; // it now points to the first arg of "-MD -MF depfile.d"
	ptrdiff_t diff = new_addr - param_buf;
	while (*params) {
		*params += diff;  // adjust with the same diff
		params++;
	}
}

static void dump_new_param_buf(char *param_buf, int buf_size)
{
	if (!g_bomsh_global.logfile) { return ; }
	int level = 9;
	bomsh_log_printf(level, "\nDump new param buf at %p size: %d\n", param_buf, buf_size);
	char **params = (char **)param_buf;
	while (*params) {
		bomsh_log_printf(level, "%p ", *params);
		params++;
	}
	bomsh_log_string(level, " ARGV: ");
	params ++ ;
	char *p = (char *)params;
	char *end = param_buf + buf_size;
	// should just contain the string "-MD -MF depfile.d"
	while (p < end) {
		bomsh_log_string(level, " ");
		bomsh_log_string(level, p);
		p += strlen(p) + 1;
	}
	bomsh_log_string(level, "\nDone dumping param buf\n");
}

#include <sys/user.h>
#include <sys/reg.h>

// modify/instrument argv of existing execve syscall, to obtain gcc dependency
static void bomsh_execve_instrument_for_dependency(bomsh_cmd_data_t * cmd)
{
	int level = 9;
	struct tcb *tcp = cmd->tcp;
	int buf_size = 0;
	char *new_param_buf = bomsh_create_param_buf(cmd, &buf_size);
	const unsigned int wordsize = current_wordsize;
	// on x86_64, RSP register has the stack address
	char *stack_addr = (char *) ptrace(PTRACE_PEEKUSER, tcp->pid, wordsize*RSP, 0);
	bomsh_log_printf(level, "PID %d original stack_addr: %p\n", cmd->pid, stack_addr);
	//int new_buf_size = buf_size;
	int new_buf_size = (buf_size/wordsize + 1) * wordsize; // do we need address alignment?
	dump_new_param_buf(new_param_buf, buf_size);

	/* Move further of 128 bytes red zone and make sure we have space for the new_param_buf */
	// 8192 is two memory pages, which should be sufficient for red zone
	//int adjustment = 4096;
	int adjustment = g_bomsh_config.depfile_stack_offset;
	stack_addr -= (adjustment + new_buf_size);
	//stack_addr -= PATH_MAX + new_buf_size; // PATH_MAX is 4096, is usually sufficient
	// 128 is insufficient for red zone, even 2048/2560 is insufficient, 4096 seems good for below behavior:
	// the upoken write is still successful, but the read-back has different content than write-out.
	// not sure why, but this does not impact the depfile generation, even if adjustment is 0 byte.
	bomsh_log_printf(level, "stack_addr: %p adjust: %d new_param_buf: %p buf_size: %d new_size: %d\n",
			stack_addr, adjustment, new_param_buf, buf_size, new_buf_size);

	//bomsh_log_string(4, "will now write new_param_buf to tracee stack\n");
	// before writing to tracee memory, modify array to point to correct stack address in tracee process
	bomsh_modify_param_buf(cmd, new_param_buf, stack_addr);
	dump_new_param_buf(new_param_buf, buf_size);

	// writing new_param_buf content to tracee process's stack memory
	unsigned int nwrite = upoken(tcp, (kernel_ulong_t)stack_addr, new_buf_size, new_param_buf);
	if (nwrite) {
		bomsh_log_printf(level, "Succeeded to write upoken for stack nwrite: %d\n", nwrite);
	} else {
		bomsh_log_string(level, "Failed to write upoken for stack\n");
	}
	if (bomsh_verbose > 20) {
		// read back to make sure correct content is written to tracee memory
		char *read_buf = malloc(new_buf_size);
		if (umoven(tcp, (kernel_ulong_t)stack_addr, new_buf_size, read_buf)) {
			bomsh_log_string(level, "Failed to read-back umoven for stack\n");
		} else {
			bomsh_log_string(level, "Succeeded to read-back umoven for stack\n");
		}
		// if insufficient to skip the stack red zone, then reading back does not work
		dump_new_param_buf(read_buf, buf_size);
		free(read_buf);
	}

	// on x86_64, for execve syscall, %rdi = pathname, %rsi = argv, %rdx = envp,
	// so writing the %rsi register will change the argv parameter of execve syscall.
	// Now write stack_addr value (which holds new_param_buf) to RSI register
	ptrace(PTRACE_POKEUSER, tcp->pid, wordsize*RSI, stack_addr);
	if (bomsh_verbose > 20) {
		// read back to make sure correct value is written to tracee memory
		char *myword5 = (char *)ptrace(PTRACE_PEEKUSER, tcp->pid, wordsize*RSI, NULL);
		bomsh_log_printf(level, "\n=====execve stack_addr changed RSI register value: %p expected: %p\n", myword5, stack_addr);
	}
	free(new_param_buf);
}

// modify/instrument argv of existing execve syscall, to obtain gcc dependency
// this GCC cmd has -M option, and we will replace -MMD with -MD.
// Note: this may cause functionality issue, so be cautious to use this function
static void bomsh_execve_instrument_for_dependency_with_m_opt(bomsh_cmd_data_t * cmd)
{
	int level = 9;
	struct tcb *tcp = cmd->tcp;
	int argc = cmd->num_argv;
	char **argv = cmd->argv;
	char *stack_addr = NULL;
	char new_param_buf[PATH_MAX];
	int new_buf_size = 0;
	for (int i=1; i<argc; i++) {
		if (strcmp(argv[i], "-MMD") == 0) {
			// replace -MMD with -MD
			stack_addr = cmd->tracee_argv[i];
			strcpy(new_param_buf, "-MD");
			new_buf_size = 4;
			break;
		} else if (strncmp(argv[i], "-Wp,-MMD,", 9) == 0) {
			stack_addr = cmd->tracee_argv[i];
			strcpy(new_param_buf, "-Wp,-MD,");
			strcpy(new_param_buf + 8, argv[i] + 9);
			new_buf_size = strlen(new_param_buf) + 1;
			break;
		}
	}
	if (!new_buf_size) {
		bomsh_log_string(level, "Info: there is no -MMD option to replace\n");
		return;
	}
	// writing new_param_buf content to tracee process's argv[i] memory
	unsigned int nwrite = upoken(tcp, (kernel_ulong_t)stack_addr, new_buf_size, new_param_buf);
	if (nwrite) {
		bomsh_log_printf(level, "Succeeded to write upoken for tracee_argv nwrite: %d\n", nwrite);
	} else {
		bomsh_log_string(level, "Failed to write upoken for stack\n");
	}
	if (bomsh_verbose > 20) {
		// read back to make sure correct content is written to tracee memory
		if (umoven(tcp, (kernel_ulong_t)stack_addr, new_buf_size, new_param_buf)) {
			bomsh_log_string(level, "Failed to read-back umoven for stack\n");
		} else {
			bomsh_log_string(level, "Succeeded to read-back umoven for stack\n");
		}
		// if insufficient to skip the stack red zone, then reading back does not work
		bomsh_log_printf(level, "read-back tracee argv: %s\n", new_param_buf);
	}
}

/******** end of EXECVE instrumentation routines ********/

/******** SHA1/SHA256 computation routines ********/

#include "sha1.h"
#include "sha256.h"

#define GITOID_LENGTH_SHA1 20
#define GITOID_LENGTH_SHA256 32

/* This length should be enough for everything up to 64B, which should cover long type. */
#define MAX_FILE_SIZE_STRING_LENGTH 256

static void
calculate_sha1_omnibor (char *afile, unsigned char resblock[])
{
	long file_size = 0;
	char *file_contents = bomsh_read_file(afile, &file_size);

	char init_data[MAX_FILE_SIZE_STRING_LENGTH + 5];
	int len = sprintf(init_data, "blob %ld", file_size);

	/* Calculate the hash */
	struct sha1_ctx ctx;
	sha1_init_ctx(&ctx);
	sha1_process_bytes(init_data, len + 1, &ctx);
	sha1_process_bytes(file_contents, file_size, &ctx);
	sha1_finish_ctx(&ctx, resblock);

	free(file_contents);
}

// get sha256 value of 32 bytes in resblock.
static void
calculate_sha256_omnibor (char *afile, unsigned char resblock[])
{
	long file_size = 0;
	char *file_contents = bomsh_read_file(afile, &file_size);

	char init_data[MAX_FILE_SIZE_STRING_LENGTH + 5];
	int len = sprintf(init_data, "blob %ld", file_size);

	/* Calculate the hash */
	struct sha256_ctx ctx;
	sha256_init_ctx(&ctx);
	sha256_process_bytes(init_data, len + 1, &ctx);
	sha256_process_bytes(file_contents, file_size, &ctx);
	sha256_finish_ctx(&ctx, resblock);

	free(file_contents);
}

// convert binary byte array to hex string array.
static void
bomsh_convert_omnibor_hash(char str_hash[], unsigned char *resblock, unsigned int length)
{
	static const char *const lut = "0123456789abcdef";
	for (unsigned i = 0; i < length; i++) {
		str_hash[2*i] = lut[resblock[i] >> 4];
		str_hash[2*i+1] = lut[resblock[i] & 15];
	}
}

// get the sha1 string of 40 bytes in str_hash.
static void
bomsh_get_omnibor_sha1_hash(char *afile, char str_hash[])
{
	unsigned char resblock[GITOID_LENGTH_SHA1];
	calculate_sha1_omnibor (afile, resblock);
	bomsh_convert_omnibor_hash(str_hash, resblock, GITOID_LENGTH_SHA1);
}

// get the sha256 string of 64 bytes in str_hash.
static void
bomsh_get_omnibor_sha256_hash(char *afile, char str_hash[])
{
	unsigned char resblock[GITOID_LENGTH_SHA256];
	calculate_sha256_omnibor (afile, resblock);
	bomsh_convert_omnibor_hash(str_hash, resblock, GITOID_LENGTH_SHA256);
}

/******** end of SHA1/SHA256 computation routines ********/

/******** shell command add/remove/log routines ********/

// 1024 buckets should be sufficient, my experiments show the max is close to 100 only.
#define BOMSH_CMDS_SIZE 1024
static bomsh_cmd_data_t **bomsh_cmds = NULL;

// allocate the cmd_data struct and initialize it
static bomsh_cmd_data_t *bomsh_new_cmd(struct tcb *tcp, char *pwd, char *root, char *path, char **argv_array)
{
	bomsh_cmd_data_t *cmd = (bomsh_cmd_data_t *)calloc(1, sizeof(bomsh_cmd_data_t));
	cmd->next = NULL;
	cmd->tcp = tcp;
	cmd->pid = tcp->pid;
	cmd->pwd = pwd;
	cmd->root = root;
	cmd->path = path;
	cmd->argv = argv_array;
	return cmd;
}

// free all the allocated memory for an array of strings, like argv
static void bomsh_free_string_array(char **array)
{
	if (array) {
		char **p = array;
		while (*p) {
			free(*p); p++;
		}
		free(array);
	}
}

// free the allocated memory for this command
static void bomsh_free_cmd(bomsh_cmd_data_t *cmd)
{
	if (cmd->refcount) {
		bomsh_log_printf(8, "\nCmd memory refcount-- from %d for pid %d\n", cmd->refcount, cmd->pid);
		cmd->refcount --;
		return;
	}
	bomsh_log_printf(8, "\nFreeing the cmd memory for pid %d\n", cmd->pid);
	if (cmd->cat_cmd) {
		bomsh_free_cmd(cmd->cat_cmd);
	}
	if (cmd->ld_cmd) {
		bomsh_free_cmd(cmd->ld_cmd);
	}
	// Usually there is no need to free output_file, since output_file is not allocated.
	// but for some commands like dpkg_deb, output_file is allocated memory thus needs to be freed
	if (cmd->flags & 1 && cmd->output_file) {
		free(cmd->output_file);
	}
	if (cmd->pwd) {
		free(cmd->pwd);
	}
	if (cmd->root) {
		free(cmd->root);
	}
	if (cmd->path) {
		free(cmd->path);
	}
	bomsh_free_string_array(cmd->input_files);
	bomsh_free_string_array(cmd->input_files2);
	bomsh_free_string_array(cmd->dynlib_files);
	bomsh_free_string_array(cmd->argv);
	if (cmd->tracee_argv) {
		free(cmd->tracee_argv); // a single allocated buffer to store tracee memory addresses
	}
	if (cmd->input_sha1) {
		free(cmd->input_sha1[0]); // all the hashes are in a single allocated buffer
		free(cmd->input_sha1);
	}
	if (cmd->input_sha256) {
		free(cmd->input_sha256[0]); // all the hashes are in a single allocated buffer
		free(cmd->input_sha256);
	}
	if (cmd->depend_file) {
		const char *prefix = "bomsh_hook_target_dependency_pid";
		//const char *prefix = "/tmp/bomsh_hook_target_dependency_pid";
		if (strncmp(bomsh_basename(cmd->depend_file), prefix, strlen(prefix)) == 0) {
			// delete bomsh-generated dependency files
			unlink(cmd->depend_file);
		}
		free(cmd->depend_file);
	}
	// cmd->depends_outfile is just a pointer, no need to free
	if (cmd->depends_array) {
		free(cmd->depends_array);
	}
	if (cmd->depends_buf) {
		free(cmd->depends_buf);
	}
	free(cmd);
}

// log an array of string pointers, like the argv array
static void bomsh_log_string_array(int level, char **array, char *sep, char *header, char *footer)
{
	if (array) {
		if (header) {
			bomsh_log_string(level, header);
		}
		char **p = array;
		while (*p) {
			bomsh_log_string(level, sep);
			bomsh_log_string(level, *p);
			p++;
		}
		if (footer) {
			bomsh_log_string(level, footer);
		}
	}
}

// for debugging purpose
static void bomsh_log_cmd_data(bomsh_cmd_data_t *cmd, int level)
{
	if (bomsh_verbose < level) return;
	bomsh_log_printf(level, "\nStart of cmd_data, pid: %d pwd: %s root: %s path: %s", cmd->pid, cmd->pwd, cmd->root, cmd->path);
	bomsh_log_string_array(level, cmd->argv, (char *)" ", (char *)"\nargv cmdline:", NULL);
	if (cmd->tracee_argv) {
		char **p = cmd->tracee_argv;
		bomsh_log_string(level, "\ntracee_argv:");
		while (*p) {
			bomsh_log_printf(level, " %p", *p);
			p++;
		}
	}
	bomsh_log_printf(level, "\nnum_argv: %d", cmd->num_argv);
	if (cmd->stdin_file) {
		bomsh_log_printf(level, "\nstdin_file: %s", cmd->stdin_file);
	}
	if (cmd->stdout_file) {
		bomsh_log_printf(level, "\nstdout_file: %s", cmd->stdout_file);
	}
	if (cmd->ppid) {
		bomsh_log_printf(level, "\nparent PID: %d", cmd->ppid);
	}
	if (cmd->depend_file) {
		bomsh_log_printf(level, "\ndepend_file: %s", cmd->depend_file);
	}
	bomsh_log_string_array(level, cmd->depends_array, (char *)"\n ", (char *)"\ndepends array:", NULL);
	if (cmd->depends_outfile) {
		bomsh_log_printf(level, "\ndepends_outfile: %s", cmd->depends_outfile);
		bomsh_log_printf(level, "\ndepends_outfile_exist: %d", cmd->depends_outfile_exist);
	}
	bomsh_log_printf(level, "\nrefcount: %d", cmd->refcount);
	bomsh_log_printf(level, "\nskip record raw info: %d", cmd->skip_record_raw_info);
	if (cmd->output_file) {
		bomsh_log_printf(level, "\noutput file: %s", cmd->output_file);
	}
	bomsh_log_printf(level, "\n#inputs: %d", cmd->num_inputs);
	bomsh_log_string_array(level, cmd->input_files, (char *)"\n ", (char *)"\ninput files:", NULL);
	bomsh_log_string_array(level, cmd->dynlib_files, (char *)"\n ", (char *)"\ndynamic libraries:", NULL);
	bomsh_log_string_array(level, cmd->input_sha1, (char *)"\n ", (char *)"\ninput file SHA1 hashes:", NULL);
	bomsh_log_string_array(level, cmd->input_sha256, (char *)"\n ", (char *)"\ninput file SHA256 hashes:", NULL);
	bomsh_log_string_array(level, cmd->input_files2, (char *)" ", (char *)"\ninput files2:", NULL);
	bomsh_log_string(level, "\nEnd of cmd_data\n");
	if (cmd->cat_cmd) {
		bomsh_log_string(level, "--Extra info: the associated cat cmd data:");
		bomsh_log_cmd_data(cmd->cat_cmd, level);
	}
	if (cmd->ld_cmd) {
		bomsh_log_string(level, "--Extra info: the child ld cmd data:");
		bomsh_log_cmd_data(cmd->ld_cmd, level);
	}
}

//static int bomsh_cmd_num = 0;  // useful to collect some stats about bomsh_cmds size

// Add a new node with pid and relevant info
static bomsh_cmd_data_t *
bomsh_add_cmd(struct tcb *tcp, char *pwd, char *root, char *path, char **argv_array)
{
	bomsh_cmd_data_t *cmd = bomsh_new_cmd(tcp, pwd, root, path, argv_array);
	int index = tcp->pid % BOMSH_CMDS_SIZE;
	bomsh_cmd_data_t *cmd2 = bomsh_cmds[index];
	if (cmd2 && cmd2->pid == tcp->pid) {
		// the head of the list has same PID as me, the old cmd should be a unsuccessful one,
		// like non-existent program path /usr/local/bin/as, but only /usr/bin/as exists.
		cmd->next = cmd2->next;
		bomsh_free_cmd(cmd2);
	} else {
		cmd->next = cmd2;
	}
	// insert the node at the head of the linked list
	bomsh_cmds[index] = cmd;
	//bomsh_log_printf(4, "\nADD bomsh_cmd_num: %d\n", bomsh_cmd_num++);
	return cmd;
}

// Remove a node of pid, return it if found
static bomsh_cmd_data_t *bomsh_remove_cmd(pid_t pid)
{
	if (!bomsh_cmds) {
		return NULL;
	}
	int index = pid % BOMSH_CMDS_SIZE;
	bomsh_cmd_data_t *cmd = bomsh_cmds[index];
	bomsh_cmd_data_t *prev = NULL;
	while (cmd) {
		// find the pid node and remove it from the linked list
		if (cmd->pid == pid) {
			if (prev) {
				prev->next = cmd->next;
			} else {
				bomsh_cmds[index] = cmd->next;
			}
			//bomsh_log_printf(4, "\nDEL bomsh_cmd_num: %d\n", bomsh_cmd_num--);
			return cmd;
		}
		prev = cmd;
		cmd = cmd->next;
	}
	return NULL;
}

// Find a node for pid
static bomsh_cmd_data_t *bomsh_get_cmd(pid_t pid)
{
	int index = pid % BOMSH_CMDS_SIZE;
	bomsh_cmd_data_t *cmd = bomsh_cmds[index];
	while (cmd) {
		if (cmd->pid == pid) {
			return cmd;
		}
		cmd = cmd->next;
	}
	return cmd;
}

/******** end of shell command add/remove/log routines ********/

/******** EXECVE cmd recording routines ********/

// Get number of argv in tracee's argv array
static unsigned int
get_argc(struct tcb *const tcp, kernel_ulong_t addr)
{
	if (!addr)
		return 0;

	const unsigned int wordsize = current_wordsize;
	kernel_ulong_t prev_addr = 0;
	unsigned int n;

	for (n = 0; addr > prev_addr; prev_addr = addr, addr += wordsize, ++n) {
		kernel_ulong_t word = 0;
		if (umoven(tcp, addr, wordsize, &word)) {
			if (n == 0)
				return 0;

			addr = 0;
			break;
		}
		if (word == 0)
			break;
	}
	return n;
}

// copy a single string from tracee process.
// return a new string allocated in tracer process
static char *
copy_single_str(struct tcb *const tcp, kernel_ulong_t addr)
{
	static char *str;
	unsigned int size;
	int rc;

	if (!addr) {
		return NULL;
	}
	/* Allocate static buffers if they are not allocated yet. */
	if (!str) {
		str = xmalloc(max_strlen + 1);
	}

	/* Fetch one byte more because string_quote may look one byte ahead. */
	size = max_strlen + 1;
	rc = umovestr(tcp, addr, size, str);

	if (rc < 0) {
		return NULL;
	}
	return(strdup(str));
}

// Copy the array of char * pointers of argv in tracee process.
// the new argv array in tracer's process is allocated and needs to be freed after use.
// if tracee_argv is not NULL, the tracee's argv array will be put there.
// tracee_argv is allocated memory and needs to be freed after use.
static char **
copy_argv_array(struct tcb *const tcp, kernel_ulong_t addr, int *num_argv, char ***tracee_argv)
{
	if (!addr) {
		return NULL;
	}

	const unsigned int wordsize = current_wordsize;
	kernel_ulong_t prev_addr = 0;
	unsigned int n = 0;

	unsigned int argc = get_argc(tcp, addr);
	if (num_argv) {
		*num_argv = argc;
	}
	char **array = (char **)xmalloc( (argc+1) * sizeof(char *));
	char **orig_array = NULL;
	if (tracee_argv) {
		orig_array = (char **)xmalloc( (argc+1) * sizeof(char *));
		*tracee_argv = orig_array;
	}

	for (;; prev_addr = addr, addr += wordsize, ++n) {
		union {
			unsigned int w32;
			kernel_ulong_t wl;
			char data[sizeof(kernel_ulong_t)];
		} cp;

		if (addr < prev_addr || umoven(tcp, addr, wordsize, cp.data)) {
			if (n == 0) {
				return NULL;
			}
			break;
		}

		const kernel_ulong_t word = (wordsize == sizeof(cp.w32))
					    ? (kernel_ulong_t) cp.w32 : cp.wl;
		if (word == 0)
			break;

		array[n] = copy_single_str(tcp, word);
		if (orig_array) {
			orig_array[n] = (char *)word;
		}
	}
	if (orig_array) orig_array[argc] = NULL;
        array[argc] = NULL;
	return array;
}

// copy the program path in tracee's process
static char *
copy_path(struct tcb *const tcp, const kernel_ulong_t addr)
{
	char path[PATH_MAX];
	int nul_seen;
	unsigned int n = PATH_MAX - 1;

	if (!addr) {
		return NULL;
	}

	/* Fetch one byte more to find out whether path length > n. */
	nul_seen = umovestr(tcp, addr, n + 1, path);
	if (nul_seen <= 0)
		return NULL;
	else {
		path[n] = 0;
	}

	return strdup(path);
}

// get root directory for a traced process.
static char * bomsh_get_rootdir(struct tcb *tcp)
{
	char cwd_file[32] = "";
	static char bomsh_rootdir[PATH_MAX] = "";
	sprintf(cwd_file, "/proc/%d/root", tcp->pid);
	int bytes = readlink(cwd_file, bomsh_rootdir, PATH_MAX);
	//if (bytes == -1 || (bytes == 1 && bomsh_rootdir[0] == '/')) {
	if (bytes == -1) {
		return NULL;
	}
	bomsh_rootdir[bytes] = 0;
	return strdup(bomsh_rootdir);
}

// get current working directory for a traced process.
// the returned pwd contains the /root part if in chroot environment
static char * bomsh_get_pwd(struct tcb *tcp)
{
	char cwd_file[32] = "";
	static char bomsh_pwddir[PATH_MAX] = "";
	sprintf(cwd_file, "/proc/%d/cwd", tcp->pid);
	int bytes = readlink(cwd_file, bomsh_pwddir, PATH_MAX);
	if (bytes == -1) {
		return NULL;
	}
	bomsh_pwddir[bytes] = 0;
	return strdup(bomsh_pwddir);
}

// get fd0/stdin file for a traced process (usually patch).
static char * bomsh_get_stdin_file(struct tcb *tcp)
{
	char cwd_file[32] = "";
	static char bomsh_stdin_file[PATH_MAX] = "";
	sprintf(cwd_file, "/proc/%d/fd/0", tcp->pid);
	int bytes = readlink(cwd_file, bomsh_stdin_file, PATH_MAX);
	if (bytes == -1) {
	       return NULL;
	}
	bomsh_stdin_file[bytes] = 0;
	if (strncmp(bomsh_stdin_file, "/dev/", 5) == 0) {
		return NULL;
	}
	return strdup(bomsh_stdin_file);
}

// get fd1/stdout file for a traced process (usually cat).
static char * bomsh_get_stdout_file(struct tcb *tcp)
{
	char cwd_file[32] = "";
	static char bomsh_stdout_file[PATH_MAX] = "";
	sprintf(cwd_file, "/proc/%d/fd/1", tcp->pid);
	int bytes = readlink(cwd_file, bomsh_stdout_file, PATH_MAX);
	if (bytes == -1) {
	       return NULL;
	}
	bomsh_stdout_file[bytes] = 0;
	if (strncmp(bomsh_stdout_file, "/dev/", 5) == 0) {
		return NULL;
	}
	return strdup(bomsh_stdout_file);
}

// get /proc/pid/stat content for a traced process.
static char * bomsh_get_pid_stat(pid_t pid)
{
	char stat_file[32] = "";
	sprintf(stat_file, "/proc/%d/stat", pid);
	return bomsh_read_proc_file(stat_file, NULL);
}

// print /proc/pid/maps content for a traced process.
static void bomsh_dump_pid_memory_maps(pid_t pid)
{
	char stat_file[32] = "";
	sprintf(stat_file, "/proc/%d/maps", pid);
	char *content = bomsh_read_proc_file(stat_file, NULL);
	if (!content) {
		bomsh_log_printf(8, "\nproc file does not exist: %s\n", stat_file);
		return;
	}
	bomsh_log_printf(8, "\nHere is the content of process memory maps file %s:\n", stat_file);
	bomsh_log_string(8, content);
	bomsh_log_string(8, "\nEnd of process memory maps file content\n");
	free(content);
}

// get parent PID for a traced process.
// /proc/pid/stat is space separated, and 4th field is ppid string
static pid_t bomsh_get_ppid(pid_t pid)
{
	char ppid[32];

	char *stat = bomsh_get_pid_stat(pid);
	if (!stat) return 0;

	char *p = stat;
	char *prev = p;
	int space_num = 0;
	while (*p) {
		if (*p == ' ') {
			space_num++;
			if (space_num == 4) { // found 4th string
				*p = 0;
				strcpy(ppid, prev);
				free(stat);
				return atoi(ppid);
			}
			prev = p + 1; // prev points to start of string
		}
		p++;
	}
	free(stat);
	return 0;
}

// Get the real path, or absolute path including /root/pwd/afile
// returns allocated buffer to hold the result, and user needs to free it.
static char *get_real_path(bomsh_cmd_data_t *cmd, char *afile)
{
	char path[PATH_MAX];
	if (afile[0] != '/') {
		strcpy(path, cmd->pwd);  // cmd->pwd contains cmd->root already
		strcat(path, "/");
		strcat(path, afile);
		return strdup(path);
	}
	// afile is absolute path, starting with '/' character.
	if (cmd->root[1]) {
		int len_root = strlen(cmd->root);
		if (strncmp(afile, cmd->root, len_root)) {
			// afile does not start with cmd->root, then concatenate root with afile
			strcpy(path, cmd->root);
			strcat(path, afile);
			return strdup(path);
		}
	}
	return strdup(afile);
}

// Get the real path, or absolute path including /root/pwd/afile
// The RESULT buffer should be big enough to hold the real path.
// returns the string pointer to the real path, without allocating buffer
static char *get_real_path22(char *afile, char *result, char *pwd, char *root)
{
	char *path = result;
	if (afile[0] != '/') {
		strcpy(path, pwd);  // pwd contains root already
		strcat(path, "/");
		strcat(path, afile);
		return path;
	}
	// afile is absolute path, starting with '/' character.
	if (root[1] && strncmp(afile, root, strlen(root))) {
		// afile does not start with root, then concatenate root with afile
		strcpy(path, root);
		strcat(path, afile);
		return path;
	}
	return afile;
}

// Get the real path, or absolute path including /root/pwd/afile
// The RESULT buffer should be big enough to hold the real path.
// returns the string pointer to the real path, without allocating buffer
static char *get_real_path2(bomsh_cmd_data_t *cmd, char *afile, char *result)
{
	return get_real_path22(afile, result, cmd->pwd, cmd->root);
}

// Get the real path, or absolute path including /root/pwd/afile
// The RESULT buffer should be big enough to hold the real path.
// returns the string pointer to the real path, without allocating buffer
// if noroot_path is not NULL, it will be set to point to /pwd/afile part, without /root prefix.
static char *get_real_path3(bomsh_cmd_data_t *cmd, char *afile, char *result, char **noroot_path)
{
	char *path = result;
	if (afile[0] != '/') {
		if (!path) {
			return NULL;
		}
		strcpy(path, cmd->pwd);  // cmd->pwd contains cmd->root already
		strcat(path, "/");
		strcat(path, afile);
		afile = path;
	}
	// afile is absolute path, starting with '/' character.
	else if (cmd->root[1] && strncmp(afile, cmd->root, strlen(cmd->root))) {
		if (!path) {
			return NULL;
		}
		// afile does not start with cmd->root, then concatenate root with afile
		strcpy(path, cmd->root);
		strcat(path, afile);
		afile = path;
	}
	if (noroot_path) {
		if (cmd->root[1]) {
			*noroot_path = afile + strlen(cmd->root);
		} else {
			*noroot_path = afile;
		}
	}
	return afile;
}

// check if the path is a regular file
static int is_regular_file(char *path) {
	struct stat path_stat;
	if (stat(path, &path_stat) == 0) {
		return S_ISREG(path_stat.st_mode);
	}
	return 0;
}

static int bomsh_is_regular_file(char *path, char *pwd, char *root)
{
	char buf[PATH_MAX];
	char *apath = get_real_path22(path, buf, pwd, root);
	return is_regular_file(apath);
}

// Check the access permission of a file or a directory
// return 1 for success, and 0 for failure
static int bomsh_check_permission(char *path, char *pwd, char *root, int amode)
{
	char buf[PATH_MAX];
	char *apath = get_real_path22(path, buf, pwd, root);
	if( access( apath, amode ) != 0 ) {
		bomsh_log_printf(8, "\nFailed to access path: %s\n", apath);
		return 0;
	}
	bomsh_log_printf(8, "\nSucceed to access path: %s\n", apath);
	return 1;
}

static void bomsh_prehook_program(bomsh_cmd_data_t *cmd);

// record the command data for the command to execute next: write it to bomsh_cmd_file for later use by bomsh_run_hook.
// returns 1 when record the command successfully and need to run pre-exec hookup
// returns 2 when record the command successfully and no need to run pre-exec hookup
// otherwise, recording fails, returns 0
// return value is ignored in Bomtrace3
int bomsh_record_command(struct tcb *tcp, const unsigned int index)
{
	if (g_bomsh_config.trace_execve_cmd_only == 1) {
		bomsh_log_printf(2, "\n====Tracing only, record_command pid %d before EXECVE syscall", tcp->pid);
		return 0;
	}
	char *path = copy_path(tcp, tcp->u_arg[index + 0]);
        if (!path) {
                return 0;
        }
	if (bomsh_is_detach_on_pid_program(path)) {
		// no need to record this command or follow its child processes
		bomsh_detach_on_pid = tcp->pid;
		bomsh_log_printf(4, "\n\nInfo: umbrella_top=%d bomsh detach pid %d\n", bomsh_umbrella_pid_top, tcp->pid);
		free(path);
		return 0;
	}
	if (bomsh_is_umbrella_program(path)) {
		bomsh_umbrella_pid_top ++;
		bomsh_umbrella_pid_stack[bomsh_umbrella_pid_top] = tcp->pid;
		bomsh_log_printf(4, "\n\nInfo: top=%d enter bomsh umbrella pid %d\n", bomsh_umbrella_pid_top, tcp->pid);
	}
	if (bomsh_umbrella_pid_stack && bomsh_umbrella_pid_top < 0) {
		// no need to record this command since there is no umbrella process
		free(path);
		return 0;
	}
	// Either strict_prog_path or not, it has been taken care in the bomsh_is_watched_program() function.
	if( !bomsh_is_watched_program(path) ) {
		// file is not watched
		free(path);
		return 0;
	}
	char *rootdir = bomsh_get_rootdir(tcp);
	if (!rootdir) {
		free(path);
		return 0;
	}
	char *pwd = bomsh_get_pwd(tcp);
	if (!pwd) {
                free(rootdir);
		free(path);
		return 0;
	}
	// When there are multiple levels of symlinks, below permission check fails on some platforms like Mageia for /usr/bin/cc
	// In such case, user can set skip_checking_prog_access=1 in bomtrace.conf file to make it work.
	//
	// Checking file permission can return early for non-existent programs, like /usr/local/bin/gcc, etc.
	// This avoids unnecessary writing of bomsh_cmd.pidXXXX file, which can also incur extra invocation of hook-up progs in pre-exec mode.
	if (!g_bomsh_config.skip_checking_prog_access && !bomsh_check_permission(path, pwd, rootdir, R_OK|X_OK)) {
		// file cannot read or execute
                free(rootdir);
		free(pwd);
		free(path);
		return 0;
	}
	// Add this shell command to global bomsh_cmds struct, for later hook analysis
	int num_argv = 0;
	char **tracee_argv = NULL;
	char ***p_tracee_argv = NULL;
	if (!(g_bomsh_config.generate_depfile & 3)) {
		// trace_argv is only needed for depfile instrumentation, which is 0 mode
		p_tracee_argv = &tracee_argv;
	}
	char **argv_array = copy_argv_array(tcp, tcp->u_arg[index + 1], &num_argv, p_tracee_argv);
	bomsh_cmd_data_t *cmd = bomsh_add_cmd(tcp, pwd, rootdir, path, argv_array);
	cmd->num_argv = num_argv;
	cmd->tracee_argv = tracee_argv;
	if (bomsh_verbose > 40) { // collect more info for debugging
		cmd->stdin_file = bomsh_get_stdin_file(tcp);
		cmd->stdout_file = bomsh_get_stdout_file(tcp);
		cmd->ppid = bomsh_get_ppid(tcp->pid);
	}
	// run hook program in pre-exec mode
	bomsh_prehook_program(cmd);
	return 1;
}

/******** end of EXECVE cmd recording routines ********/

// start of invoking child process functions
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

// run a program in child process, with potential chroot and chdir
static int bomsh_run_child_prog(char **args, char *root, char *pwd)
{
	pid_t pid;
	pid = fork();  // clone the process
	if (pid < 0) {
		bomsh_log_string(4, "Fork Failed\n");
		return 1;
	}
	else if (pid == 0) { /* Child process */
		/* close the stdout for the child process */
		// must open before chroot, since /dev/null may not exist after chroot
		int output_fd = open("/dev/null", O_WRONLY);

		if (root && strcmp(root, "/") && chroot(root) != 0) {
			bomsh_log_string(4, "chroot() Failed\n");
			exit(EXIT_FAILURE);
		}
		if (pwd && chdir(pwd) != 0) {
			bomsh_log_string(4, "chdir() Failed\n");
			exit(EXIT_FAILURE);
		}

		// below is a relative path to /root/pwd directory, thus open it after chroot/chdir.
		//int output_fd = open("yon-ofile.txt", O_WRONLY | O_CREAT | O_TRUNC);
		// Replace the child's stdout and stderr handles with the new file handle:
		if (dup2(output_fd, STDOUT_FILENO) < 0) {
			bomsh_log_string(4, "dup2(stdout) Failed\n");
			exit(EXIT_FAILURE);
		}
		if (dup2(output_fd, STDERR_FILENO) < 0) {
			bomsh_log_string(4, "dup2(stderr) Failed\n");
			exit(EXIT_FAILURE);
		}

		execvp(args[0], args);  // replace the current process image with a new one

		/* If execvp returns, it must have failed */
		bomsh_log_string(4, "Execvp Failed\n");
		exit(EXIT_FAILURE);
	}
	else { /* Parent process */
		/* The parent will wait for the child to complete */
		int status;
		if ( waitpid(pid, &status, 0) == -1 ) {
			bomsh_log_string(4, "waitpid Failed\n");
			return EXIT_FAILURE;
		}
		bomsh_log_string(4, "\nChild Complete\n");
	}

	return 0;
}
// end of invoking subprocess functions

/******** gcc dependency file processing routines ********/

// check if a string ends with a specific suffix.
// the sep character is usually '-' or '.'
static int bomsh_endswith(char *name, const char *suffix, char sep)
{
	char *p = strrchr(name, sep);
	if (p) {
		name = p + 1;
	}
	return strcmp(name, suffix) == 0;
}

// check if a string is all decimal digits
static int is_all_digits(char *p)
{
	while (*p) {
		if (*p < '0' || *p > '9') {
			return 0;
		}
		p++;
	}
	return 1;
}

/*
 * Check if it is gcc/cc installed at non-standard location.
 * like /usr/bin/x86_64-mageia-linux-gnu-gcc on Mageia
 * /sw/packages/gcc/c4.7.0-p5/x86_64-linux/bin/gcc
 * /auto/binos-tools/llvm11/llvm-11.0-p22/bin/clang-11
 */
static int is_special_cc_compiler(char *prog)
{
	int len = strlen(prog);
	return  (prog[len-1] == 'c' && prog[len-2] == 'c' &&
			(prog[len-3] == '/' || prog[len-3] == '-' ||
			 (prog[len-3] == 'g' && (prog[len-4] == '/' || prog[len-4] == '-'))))
		|| (prog[len-1] == '+' && prog[len-2] == '+' && prog[len-3] == 'g' &&
			(prog[len-4] == '/' || prog[len-4] == '-' ||
			 (prog[len-7] == 'c' && prog[len-6] == 'l' && prog[len-5] == 'a' && prog[len-4] == 'n')))
		// || (strncmp(prog + len - 7, "clang++", 7) == 0)
		|| (strncmp(prog + len - 5, "clang", 5) == 0)
		|| (strncmp(prog, "clang-", 6) == 0 && is_all_digits(prog + 6));
		//|| (strncmp(bomsh_basename(prog), "clang", 5) == 0);
	//return strncmp(prog + len - 3, "gcc") == 0;
}

static int is_cc_compiler(char *prog)
{
	return is_special_cc_compiler(prog);
}

// check if a token is in the watched list.
static int bomsh_is_token_inlist(char *prog, char **prog_list, int num_progs)
{
	return bsearch(&prog, prog_list, num_progs, sizeof(char *), strcmp_comparator) != NULL;
}

// sorted list of linker names
static const char *g_cc_linker_names[] = {"gold", "ld", "ld.bfd", "ld.gold", "ld.lld"};

static int is_cc_linker(char *name)
{
	return bomsh_path_endswith(name, g_cc_linker_names, sizeof(g_cc_linker_names)/sizeof(*g_cc_linker_names));
}

static int is_shared_library(char *afile)
{
	int len = strlen(afile);
	if (strncmp(afile + len - 3, ".so", 3) == 0) {
		return 1;
	}
	char *name = bomsh_basename(afile);
	if (strncmp(name, "lib", 3) == 0) {
		char *pos = strstr(name, ".so.");
		if (pos) {
			char *p = pos + 4;
			while (*p) {
				if (*p != '.' && *p < '0' && *p > '9') {
					return 0;
				}
				p++;
			}
			return 1;
		}
	}
	return 0;
}

// Get the output file in argv
static char * get_outfile_in_argv(char **argv)
{
	char **p = argv; p++; // start from argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already
		if (strncmp(token, "-o", 2) == 0) {
			int len = strlen(token);
			if (len > 2) {
				return token + 2;
			} else {
				return *p;
			}
		}
	}
	return NULL;
}

// Is there a token in argv which is exactly the given TOKEN
static int is_token_in_argv(char **argv, const char *token)
{
	char **p = argv; p++; // start from argv[1]
	while (*p) {
		if (strcmp(*p, token) == 0) {
			return 1;
		}
		p++;
	}
	return 0;
}

// Is there a token in argv which starts with a specific PREFIX
static int is_token_prefix_in_argv(char **argv, const char *prefix)
{
	char **p = argv; p++; // start from argv[1]
	int len = strlen(prefix);
	while (*p) {
		if (strncmp(*p, prefix, len) == 0) {
			return 1;
		}
		p++;
	}
	return 0;
}

// whether gcc generates dependency rule, that is, with some -M/-MM/-Mx option
static int gcc_generates_dependency_rule(char **argv)
{
	return is_token_prefix_in_argv(argv, "-M") || is_token_prefix_in_argv(argv, "-Wp,-M");
}

// Whether the gcc command compiles from C/C++ source files to intermediate .o/.s/.E only
static int gcc_is_compile_only(char **argv)
{
	if (is_token_in_argv(argv, "-c") ||
			//is_token_in_argv(argv, "-cc1") ||
			is_token_in_argv(argv, "-S") ||
			is_token_in_argv(argv, "-E")) {
		return 1;
	}
	return 0;
}

// read depend_file and put the list of depend files in the depends array.
// depend_buf contains the contents of depend_file, with NULL-terminated file paths.
// returns the number of depend files
// user needs to free the allocated depends array and depend_buf.
static int bomsh_read_depend_file(char *depend_file, char ***depends, char **depend_buf, char **output_file)
{
	char *depend_str = bomsh_read_file(depend_file, NULL);
	bomsh_log_printf(22, "\nReading depend_file: %s the whole depend_str:\n%s\n", depend_file, depend_str);
	if (!depend_str) {
		return 0;
	}
	char *p = strchr(depend_str, ':');
	if (!p) {
		return 0;
	}
	if (output_file) {  // save the output_file too
		*p = 0;
		*output_file = depend_str;
	}
	p++;
	char *prev = NULL;
	static char *bomsh_depend_array[4000]; // 4000 should be large enough
	char **arr = bomsh_depend_array;
	int num_depends = 0;
	while (*p) {
		////if (*p == '\n' && *(p+1) == '\n') { // # get the first part only, due to -MP option.
		if (*p == '\n' && *(p+1) != ' ') { // # get the first part only, due to -MP option.
			// for next continued line, it always starts with a space character
			if(prev) {  // found the end of a new depend file
				num_depends++;
				*arr = prev; arr++;
				*p = 0;
				bomsh_log_printf(22, "found a new depend: %s\n", prev);
				prev = NULL;
#if 0
				if (num_depends >= 2000) { // we will break anyway, no need to log this warning
					bomsh_log_string(3, "Warning: reached maximum of 2000 depend files\n");
					break;
				}
#endif
		        }
			*p = 0;
			break;
		}
		if (*p == ' ' || *p == '\n') {
			if(prev) {  // found the end of a new depend file
				num_depends++;
				*arr = prev; arr++;
				*p = 0;
				bomsh_log_printf(22, "found a new depend: %s\n", prev);
				prev = NULL;
				if (num_depends >= 4000) {
					bomsh_log_string(3, "Warning: reached maximum of 4000 depend files\n");
					break;
				}
		        }
			if (*(p+1) != ' ' && *(p+1) != '\n' && *(p+1) != '\\') {
				// found the beginning of a new depend file
				prev = p + 1;
			}
		}
		p++;
	}
	bomsh_log_printf(22, "\nDone parsing depend_str, num_depends: %d\n", num_depends);
	// adding one more entry for piggy object handling, which adds one more input file
	char **depend_array = (char **)malloc((num_depends + 2) * sizeof(char *));
	memcpy(depend_array, bomsh_depend_array, num_depends * sizeof(char *));
	depend_array[num_depends] = NULL;
	*depends = depend_array;
	*depend_buf = depend_str;
	return num_depends;
}

// read depend file and save results into cmd->depends_array, etc.
static void bomsh_cmd_read_depend_file(bomsh_cmd_data_t *cmd)
{
	char **depends_array = NULL;
	char *depends_buf = NULL;
	char *output_file = NULL;
	char *depend_file = cmd->depend_file;

	char buf[PATH_MAX];
	char *depend_file2 = get_real_path2(cmd, depend_file, buf);
	// need to get the real path of the depend file to read successfully
	bomsh_log_printf(7, "\nRead gcc dependency from depfile: %s real-path: %s\n", depend_file, depend_file2);
	int num_depends = bomsh_read_depend_file(depend_file2, &depends_array, &depends_buf, &output_file);

	cmd->depends_buf = depends_buf;
	cmd->depends_array = depends_array;
	cmd->depends_num = num_depends;
	cmd->depends_outfile = output_file;
	// outfile from depend file may not be correct path, so need to check if it exists
	if (bomsh_check_permission(output_file, cmd->pwd, cmd->root, F_OK)) {
		cmd->depends_outfile_exist = 1;
	} else {
		bomsh_log_printf(7, "WarnInfo: not-existent outfile %s from depfile: %s\n", output_file, depend_file);
	}
}

// run a child process to generate dependency for GCC compilation
// this GCC cmd has -M option, and we will replace -MMD with -MD.
static void bomsh_invoke_subprocess_for_dependency_with_m_opt(bomsh_cmd_data_t *cmd)
{
	int num_tokens = cmd->num_argv;
	char **args = malloc( (num_tokens + 5) * sizeof(char *) );
	memcpy(args, cmd->argv, (num_tokens + 1) * sizeof(char *));

	char buf[PATH_MAX];
	if (cmd->root[1]) {
		// -E should override the previous -c/-S option, to improve performance
		sprintf(buf, "-E -MD -MF /tmp/bomsh_hook_target_dependency_pid%d.d", cmd->pid);
	} else {
		sprintf(buf, "-E -MD -MF %s/bomsh_hook_target_dependency_pid%d.d", g_bomsh_config.tmpdir, cmd->pid);
	}
	buf[2] = buf[6] = buf[10] = '\0';
	char *md_str = buf + 3;
	char *mf_str = buf + 7;
	char *depend_file = buf + 11;

	int found_mmd_option = 0;
	int replace_mf_file = 0;
	char **p = args;
	while (*p) {
		if (strcmp(*p, "-MMD") == 0) {
			*p = md_str; // the -MD string
			found_mmd_option = 1;
		} else if (strcmp(*p, "-MF") == 0) {
			p++;
			if (*p) {
				*p = depend_file; // the depfile string
				replace_mf_file = 1;
			} else {
				bomsh_log_string(6, "\nWarning: bad gcc grammar, -MF option is the last gcc option\n");
				break;
			}
		} else if (strncmp(*p, "-Wp,-MMD,", 9) == 0) {
			char buf2[PATH_MAX];
			if (cmd->root[1]) {
				sprintf(buf2, "-Wp,-MD,/tmp/bomsh_hook_target_dependency_pid%d.d", cmd->pid);
			} else {
				sprintf(buf2, "-Wp,-MD,%s/bomsh_hook_target_dependency_pid%d.d", g_bomsh_config.tmpdir, cmd->pid);
			}
			*p = buf2; // replace with the new -Wp,-MD,depfile string
			found_mmd_option = 1;
			replace_mf_file = 1;
		}
		p++;
	}
	if (!found_mmd_option) {
		bomsh_log_string(6, "\nWarning: -MMD option is not replaced by -MD, not invoking subprocess for dependency\n");
		free(args);
		return;
	}
	if (!replace_mf_file) {
		bomsh_log_string(6, "\nInfo: There is no -MF option, will add it to gcc cmd\n");
		args[num_tokens++] = mf_str; // the -MF string
		args[num_tokens++] = depend_file; // the depfile string
	}
	// The -E option is always added to improve performance
	args[num_tokens++] = buf;
	args[num_tokens] = NULL;
	// since cmd->pwd contains cmd->root part, we need to adjust the pwd parameter of the below call.
	if (cmd->root[1]) {
		bomsh_run_child_prog(args, cmd->root, cmd->pwd + strlen(cmd->root));
	} else {
		bomsh_run_child_prog(args, cmd->root, cmd->pwd);
	}
	free(args);
	cmd->depend_file = strdup(depend_file);
}

// run a child process to generate dependency for GCC compilation
static void bomsh_invoke_subprocess_for_dependency(bomsh_cmd_data_t *cmd)
{
	int num_tokens = cmd->num_argv;
	char **args = malloc( (num_tokens + 5) * sizeof(char *) );
	memcpy(args, cmd->argv, num_tokens * sizeof(char *));
	char buf[PATH_MAX];
	if (cmd->root[1]) {
		// -E should override the previous -c/-S option, to improve performance
		sprintf(buf, "-E -MD -MF /tmp/bomsh_hook_target_dependency_pid%d.d", cmd->pid);
	} else {
		sprintf(buf, "-E -MD -MF %s/bomsh_hook_target_dependency_pid%d.d", g_bomsh_config.tmpdir, cmd->pid);
	}
	buf[2] = buf[6] = buf[10] = '\0';
	char *depend_file = buf + 11;
	args[num_tokens] = buf; // the -E string
	args[num_tokens+1] = buf+3; // the -MD string
	args[num_tokens+2] = buf+7; // the -MF string
	args[num_tokens+3] = depend_file;
	args[num_tokens+4] = NULL;
	// since cmd->pwd contains cmd->root part, we need to adjust the pwd parameter of the below call.
	if (cmd->root[1]) {
		bomsh_run_child_prog(args, cmd->root, cmd->pwd + strlen(cmd->root));
	} else {
		bomsh_run_child_prog(args, cmd->root, cmd->pwd);
	}
	free(args);
	cmd->depend_file = strdup(depend_file);
}

// find the depend_file from gcc argv string array
static char * extract_depend_file_from_cc_argv(bomsh_cmd_data_t *cmd)
{
	char *md_option = NULL;
	char **p = cmd->argv; p++; // start from argv[1]
	while (*p) {
		char *token = *p; p++;
		if (strncmp(token, "-Wp,-MD,", 8) == 0) {
			return strdup(token + 8);
		} else if (strncmp(token, "-Wp,-MMD,", 9) == 0) {
			return strdup(token + 9);
		}
		if (strcmp(token, "-MD") == 0 || strcmp(token, "-MMD") == 0) {
			md_option = token;
		} else if (strcmp(token, "-MF") == 0) {
			if (*p) {
				return strdup(*p);
			}
		}
	}
	if (md_option) {
		// The driver determines file based on whether an -o option is given.
		// If it is, the driver uses its argument but with a suffix of .d,
		// otherwise it takes the name of the input file, removes any directory
		// components and suffix, and applies a .d suffix.
		if (!cmd->output_file) {
			cmd->output_file = get_outfile_in_argv(cmd->argv);
		}
		char buf[PATH_MAX];
		// the outputfile is given, then depfile is determined based on outfile
		if (cmd->output_file) {
			char *end = stpcpy(buf, cmd->output_file);
			char *dot = strrchr(bomsh_basename(buf), '.');
			if (dot) {
				// replace outfile hello.o with hello.d
				dot[1] = 'd'; dot[2] = 0;
			} else {
				// append .d to hello to become hello.d
				end[0] = '.'; end[1] = 'd'; end[2] = 0;
			}
			return strdup(buf);
#if 0
		} else {
			// usually we don't process gcc/clang cmd without -o option,
			// thus this case will not run into.
			char *infile = NULL;
			p = cmd->argv; p++;
			while (*p) {
				char *dot = strrchr(*p, '.');
				//if (bomsh_endswith(*p, "c", '.') || bomsh_endswith(*p, "cpp", '.')) {
				if (dot && ((dot[1] == 'c' && dot[2] == 0) || (strcmp(dot + 1, "cpp") == 0))
					&& bomsh_is_regular_file(*p, cmd->pwd, cmd->root)) {
					infile = *p;
					bomsh_log_printf(6, "We will construct depfile based on this found input file: %s\n", infile);
					break;
				}
				p++;
			}
			if (infile) {
				// construct the depfile based on input file
				char *end = stpcpy(buf, cmd->pwd);
				*end = '/'; end[1] = 0;
				strcat(end + 1, bomsh_basename(infile));
				char *dot = strrchr(end, '.');
				dot[1] = 'd'; dot[2] = 0;
				return strdup(buf);
			}
#endif
		}

	}
	return NULL;
}

/******** end of gcc dependency file processing routines ********/

/******** recording ADF (Artifact Dependency Fragment) raw_info routines ********/

/*
 * afile must be real_path, including cmd->root
 * the computed hash is saved in ahash character array
 */
static void bomsh_get_hash(char *afile, int hash_alg, char *ahash)
{
	if (g_bomsh_config.hash_alg == 100) { // use empty hash for this special hash_alg of 100
		ahash[0] = 0;
		return;
	}
	if (hash_alg == 2) {
		bomsh_get_omnibor_sha256_hash(afile, ahash);
	} else {
		bomsh_get_omnibor_sha1_hash(afile, ahash);
	}
}

// get the hash for afile, which is usually relative path
static void bomsh_cmd_get_hash(bomsh_cmd_data_t *cmd, char *afile, int hash_alg, char *ahash)
{
	if (g_bomsh_config.hash_alg == 100) { // use empty hash for this special hash_alg of 100
		ahash[0] = 0;
		return;
	}
	char path[PATH_MAX];
	char *bfile = get_real_path2(cmd, afile, path);
	bomsh_get_hash(bfile, hash_alg, ahash);
}

// ahash should contain the pre-computed hash already, via the bomsh_cmd_get_hash() method
static void bomsh_record_afile2(bomsh_cmd_data_t *cmd, char *afile, const char *lead, int hash_alg, char *ahash, int level)
{
	char path[PATH_MAX];
	char *afile2 = afile;
	// Get the noroot_path for afile
	if (afile[0] != '/') {
		strcpy(path, cmd->pwd);
		strcat(path, "/");
		strcat(path, afile);
		afile2 = path;
		if (cmd->root[1]) {
			afile2 += strlen(cmd->root);
		}
	}
	bomsh_log_string(level, lead);
	bomsh_log_string(level, ahash);
	bomsh_log_string(level, " path: ");
	bomsh_log_string(level, afile2);
}

// record a raw_logfile line for a file, with its hash calculated by calling bomsh_get_hash.
// the recorded path is /pwd/afile, not including /root part, that is, noroot_path
static void bomsh_record_afile(bomsh_cmd_data_t *cmd, char *afile, const char *lead, int hash_alg, char *ahash, int level)
{
	char path[PATH_MAX];
	char *afile2 = NULL;
	char *bfile = get_real_path3(cmd, afile, path, &afile2);
	bomsh_get_hash(bfile, hash_alg, ahash);
	bomsh_log_string(level, lead);
	bomsh_log_string(level, ahash);
	bomsh_log_string(level, " path: ");
	bomsh_log_string(level, afile2);
}

// record a list of files, lead is the filetype, like infile or dynlib.
// array must not be NULL, so verify it before calling this function
static void bomsh_record_files_array(bomsh_cmd_data_t *cmd, char **array, const char *lead, int hash_alg, char *ahash, int level)
{
	char **p = array;
	while (*p) {
		bomsh_record_afile(cmd, *p, lead, hash_alg, ahash, level);
		p++;
	}
}

static void bomsh_record_infiles_array(bomsh_cmd_data_t *cmd, char **array, int hash_alg, char *ahash, int level)
{
	bomsh_record_files_array(cmd, array, "\ninfile: ", hash_alg, ahash, level);
}

static void bomsh_record_dynlibs(bomsh_cmd_data_t *cmd, int hash_alg, char *ahash, int level)
{
	if (cmd->ld_cmd) {
		bomsh_cmd_data_t *ld_cmd = cmd->ld_cmd;
		bomsh_log_printf(8, "GCC cmd pid %d will use LD cmd pid %d dynlibs instead\n", cmd->pid, ld_cmd->pid);
		if (ld_cmd->dynlib_files) { // use ld_cmd's dynlibs instead
			bomsh_record_files_array(ld_cmd, ld_cmd->dynlib_files, "\ndynlib: ", hash_alg, ahash, level);
			return;
		}
	}
	if (cmd->dynlib_files) {
		bomsh_record_files_array(cmd, cmd->dynlib_files, "\ndynlib: ", hash_alg, ahash, level);
	}
}

// record both outfile and infiles from the dependency file
static void bomsh_record_files_from_depfile(bomsh_cmd_data_t *cmd, int hash_alg, char *ahash, int level)
{
	char **depends_array = cmd->depends_array;
	if (cmd->depends_outfile_exist) {
		bomsh_record_afile(cmd, cmd->depends_outfile, "\noutfile: ", hash_alg, ahash, level);
	} else {
		// if the outfile path from depend file does not exist, then try the outfile from argv
		if (!cmd->output_file) {
			cmd->output_file = get_outfile_in_argv(cmd->argv);
		}
		if (cmd->output_file && bomsh_check_permission(cmd->output_file, cmd->pwd, cmd->root, F_OK)) {
			bomsh_record_afile(cmd, cmd->output_file, "\noutfile: ", hash_alg, ahash, level);
		} else {
			if (cmd->output_file) {
				bomsh_log_printf(7, "Warning: not-existent output file %s from argv\n", cmd->output_file);
			} else {
				bomsh_log_string(7, "Warning: no output file found from argv\n");
			}
			// anyway, let's log the outfile from the depend file
			bomsh_record_afile(cmd, cmd->depends_outfile, "\noutfile: ", hash_alg, ahash, level);
		}
	}
	for (int i=0; i < cmd->depends_num; i++) {
		bomsh_record_afile(cmd, depends_array[i], "\ninfile: ", hash_alg, ahash, level);
	}
}

static void bomsh_record_out_infiles(bomsh_cmd_data_t *cmd, int hash_alg, char *ahash, int level)
{
	// cmd->depend_file should have been verified to exist, when we are here, so no need to check permission again
	if (cmd->depend_file) {
		// if we have depend_file, then it must be gcc compilation
		bomsh_record_files_from_depfile(cmd, hash_alg, ahash, level);
		if (cmd->ld_cmd) {
			bomsh_cmd_data_t *ld_cmd = cmd->ld_cmd;
			bomsh_log_printf(8, "GCC cmd pid %d will add LD cmd pid %d inputs as extra inputs\n", cmd->pid, ld_cmd->pid);
			if (ld_cmd->input_files) { // record ld_cmd's inputs too
				bomsh_record_infiles_array(ld_cmd, ld_cmd->input_files, hash_alg, ahash, level);
				return;
			}
		}
	} else {
		bomsh_record_afile(cmd, cmd->output_file, "\noutfile: ", hash_alg, ahash, level);
		if (cmd->ld_cmd) {
			bomsh_cmd_data_t *ld_cmd = cmd->ld_cmd;
			bomsh_log_printf(8, "GCC cmd pid %d will use LD cmd pid %d inputs instead\n", cmd->pid, ld_cmd->pid);
			if (ld_cmd->input_files) { // use ld_cmd's inputs instead
				bomsh_record_infiles_array(ld_cmd, ld_cmd->input_files, hash_alg, ahash, level);
				return;
			}
		}
		if (cmd->input_files) {
			bomsh_record_infiles_array(cmd, cmd->input_files, hash_alg, ahash, level);
		}
	}
}

static void bomsh_record_cmdline(bomsh_cmd_data_t *cmd, int level)
{
	if (cmd->cat_cmd) {
		bomsh_log_string_array(level, cmd->cat_cmd->argv, (char *)" ", (char *)"\nbuild_cmd:", NULL);
		bomsh_log_string_array(level, cmd->argv, (char *)" ", (char *)" |", NULL);
	} else {
		bomsh_log_string_array(level, cmd->argv, (char *)" ", (char *)"\nbuild_cmd:", NULL);
		if (cmd->stdin_file) {
			bomsh_log_string(level, " < ");
			int len = 0;
			if (cmd->root[1]) {
				len = strlen(cmd->root);
			}
			bomsh_log_string(level, cmd->stdin_file + len);
		}
	}
}

// record ADF (Artifact Dependency Fragment) for a specific hash algorithm
static void bomsh_record_raw_info_hashalg(bomsh_cmd_data_t *cmd, int hash_alg, char *ahash, int level)
{
	bomsh_record_out_infiles(cmd, hash_alg, ahash, level);
	bomsh_record_dynlibs(cmd, hash_alg, ahash, level);
	if (cmd->skip_record_raw_info == 2) {
		bomsh_log_string(level, "\nignore_this_record: information only");
	}
	bomsh_record_cmdline(cmd, level);
	bomsh_log_printf(level, "\n==== End of raw info for PID %d process\n\n", cmd->pid);
	//bomsh_log_string(level, "\n==== End of raw info for this process\n\n");
}

// record raw_info (ADF) for a shell command
static void bomsh_record_raw_info(bomsh_cmd_data_t *cmd)
{
	if (!g_bomsh_global.raw_logfile) {
		return;
	}
	//if (!cmd->output_file && !cmd->depend_file) {
	if (!cmd->output_file) { // even with "-MF" option, we still get outfile from argv first
		// if -MF option already exists in "gcc -c" cmd, then output_file is NULL, while depend_file is not.
		return;
	}
	//if (cmd->output_file && !bomsh_check_permission(cmd->output_file, cmd->pwd, cmd->root, F_OK)) {
	if (!bomsh_check_permission(cmd->output_file, cmd->pwd, cmd->root, F_OK)) {
		bomsh_log_printf(8, "\nWarning: not-existent output file to record raw info: %s\n", cmd->output_file);
		return;
	}
	// a buffer used for both SHA1 and SHA256 computation
	char ahash[GITOID_LENGTH_SHA256 * 2 + 1];
	ahash[GITOID_LENGTH_SHA1 * 2] = 0;
	ahash[GITOID_LENGTH_SHA256 * 2] = 0;
	int level = -1;
	if (g_bomsh_config.hash_alg == 2) { // log sha256 to raw_logfile only
		bomsh_record_raw_info_hashalg(cmd, 2, ahash, level);
	} else { // must log sha1 to raw_logfile
		bomsh_record_raw_info_hashalg(cmd, 1, ahash, level);
	}
	if (g_bomsh_config.hash_alg == 3) { // log sha256 to raw_logfile2 too
		level = -2;
		bomsh_record_raw_info_hashalg(cmd, 2, ahash, level);
	}
}

// record raw info for a single file OUTFILE, which is both input file and output file.
static void bomsh_record_raw_info2_infile(bomsh_cmd_data_t *cmd, char *outfile, char *in_hash, char **extra_infiles, int hash_alg, char *ahash, int level)
{
	if (!bomsh_check_permission(outfile, cmd->pwd, cmd->root, F_OK)) {
		// when patching deletes a file, then this outfile does not exist after patching
		bomsh_log_printf(8, "\nWarning: not-existent output infile to record raw info: %s\n", outfile);
		return;
	}
	bomsh_cmd_get_hash(cmd, outfile, hash_alg, ahash);
	// if hash_alg=100, then always empty hash, thus ahash always equals in_hash, but we still want to record this raw info
	if (g_bomsh_config.hash_alg != 100 && strcmp(ahash, in_hash) == 0) {
		// no change in file content
		bomsh_log_printf(18, "\nSkip recording raw info, due to no content change for outfile %s\n", outfile);
		return;
	}
	bomsh_record_afile2(cmd, outfile, "\noutfile: ", hash_alg, ahash, level);
	if (g_bomsh_config.hash_alg == 100 || in_hash[0]) {
		// patch cmd may have /dev/null, then infile does not exist yet during pre-exec mode.
		// for this patch cmd case, in_hash is empty string, and we can skip it.
		bomsh_record_afile2(cmd, outfile, "\ninfile: ", hash_alg, in_hash, level);
	}
	if (extra_infiles) {
		bomsh_record_files_array(cmd, extra_infiles, "\ninfile: ", hash_alg, ahash, level);
	}
	bomsh_record_cmdline(cmd, level);
	bomsh_log_printf(level, "\n==== End of raw info for PID %d process\n\n", cmd->pid);
}

// record raw info for the list of input files
static void bomsh_record_raw_info2_infiles(bomsh_cmd_data_t *cmd, int hash_alg, char *ahash, int level)
{
	char **p = NULL;
	if (hash_alg == 2) {
		p = cmd->input_sha256;
	} else {
		p = cmd->input_sha1;
	}
	for (int i=0; i<cmd->num_inputs; i++, p++) {
		char *in_hash = *p;
		//const char *infiles[3] = {"/usr/bin/ls", "/usr/bin/cat", NULL};
		//bomsh_record_raw_info2_infile(cmd, cmd->input_files[i], in_hash, (char **)infiles, hash_alg, ahash, level);
		bomsh_record_raw_info2_infile(cmd, cmd->input_files[i], in_hash, cmd->input_files2, hash_alg, ahash, level);
	}
}

// mode 2 of recording raw info: each infile is also outfile, its pre-hash is recorded in input_shaN array.
static void bomsh_record_raw_info2(bomsh_cmd_data_t *cmd)
{
	if (!g_bomsh_global.raw_logfile) {
		return;
	}
	if (!cmd->input_files) {
		return;
	}
	char ahash[GITOID_LENGTH_SHA256 * 2 + 1];
	ahash[GITOID_LENGTH_SHA1 * 2] = 0;
	ahash[GITOID_LENGTH_SHA256 * 2] = 0;
	int level = -1;
	if (g_bomsh_config.hash_alg == 2) { // log sha256 to raw_logfile only
		bomsh_record_raw_info2_infiles(cmd, 2, ahash, level);
	} else { // must log sha1 to raw_logfile
		bomsh_record_raw_info2_infiles(cmd, 1, ahash, level);
	}
	if (g_bomsh_config.hash_alg == 3) { // log sha256 to raw_logfile2 too
		level = -2;
		bomsh_record_raw_info2_infiles(cmd, 2, ahash, level);
	}
}

// Record raw info for any command
static void bomsh_record_raw_info_for_command(bomsh_cmd_data_t *cmd)
{
	bomsh_log_printf(8, "record raw info for generic cmd pid %d\n", cmd->pid);
	if (cmd->input_sha1 || cmd->input_sha256) {
		bomsh_record_raw_info2(cmd);
	} else {
		bomsh_record_raw_info(cmd);
	}
}

/******** end of recording ADF (Artifact Dependency Fragment) raw_info routines ********/

// check if a library exists in a list of library paths
// if it exists, return allocated buffer to hold the path
static char * find_lib_in_libpaths(bomsh_cmd_data_t *cmd, char *libfile, char **library_paths, int num_lib_paths, char *suffix)
{
	char buf[PATH_MAX];
	for (int i=0; i<num_lib_paths; i++) {
		char *lib_path = library_paths[i];
		strcpy(buf, lib_path);
		strcat(buf, "/lib");
		strcat(buf, libfile);
		strcat(buf, suffix);
		if (bomsh_check_permission(buf, cmd->pwd, cmd->root, F_OK)) {
			return strdup(buf);
		}
	}
	return NULL;
}

// log a list of files for gcc
static void log_gcc_subfiles(int level, char **libs, int num_libs, const char *lead)
{
	bomsh_log_string(level, lead);
	for (int i=0; i<num_libs; i++) {
		bomsh_log_string(level, " ");
		bomsh_log_string(level, libs[i]);
	}
}

// Parse cmd->argv, and get all files from the command line
// handle both gcc and ld commands
static void bomsh_get_gcc_subfiles(bomsh_cmd_data_t *cmd, char **skip_token_list, int num_tokens)
{
	char *output_file = NULL;
	int level = 7;

	char *system_library_paths[] = {(char *)"/usr/lib64", NULL};
	int num_libpaths = 0;
	int libpaths_size = 100;
	char **library_paths = NULL;
	int num_libnames = 0;
	int libnames_size = 100;
	char **library_names = NULL;
	int subfiles_size = 100;
	int num_subfiles = 0;
	char **subfiles = malloc(subfiles_size * sizeof(char *));

	char **p = cmd->argv;
	p++; // start with argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already
#if 1
		// the -o option should have been handled earlier by get_outfile_in_argv, so save the check here
		// well, we still need to handle this -o option, otherwise, the outfile will be added to infiles
		if (strncmp(token, "-o", 2) == 0) {
			int len = strlen(token);
			if (len > 2) {
				output_file = token + 2;
			} else {
				// p already points to next token, which is output file
				output_file = *p;
				p++; // move to next token
			}
#if 0
			if (output_file && strcmp(output_file, "/dev/null") == 0) {
				// well, this case should have been handled earlier, so we should not reach here
				bomsh_log_string(3, "NULL outfile, no need to process gcc command\n");
				cmd->skip_record_raw_info = 1;
				free(subfiles);
				if (library_paths) free(library_paths);
				if (library_names) free(library_names);
				return;
			}
#endif
			bomsh_log_printf(level, "found output file %s\n", output_file);
			continue;
		}
#endif
		if (strncmp(token, "-L", 2) == 0) {
			if (!library_paths) {
				library_paths = malloc(libpaths_size * sizeof(char *));
			}
			if (num_libpaths >= libpaths_size) {
				libpaths_size *= 2;
				library_paths = realloc(library_paths, libpaths_size * sizeof(char *));
			}
			int len = strlen(token);
			if (len > 2) {
				bomsh_log_printf(level, "found library path %s\n", token + 2);
				library_paths[num_libpaths++] = token + 2;
			} else {
				bomsh_log_printf(level, "found library path %s\n", *p);
				// p already points to next token, which is output file
				library_paths[num_libpaths++] = *p;
				p++; // move to next token
			}
			continue;
		}
		if (strncmp(token, "-l", 2) == 0) {
			if (!library_names) {
				library_names = malloc(libnames_size * sizeof(char *));
			}
			if (num_libnames >= libnames_size) {
				libnames_size *= 2;
				library_names = realloc(library_names, libnames_size * sizeof(char *));
			}
			int len = strlen(token);
			if (len > 2) {
				bomsh_log_printf(level, "found library name %s\n", token + 2);
				library_names[num_libnames++] = token + 2;
			} else {
				bomsh_log_printf(level, "found library name %s\n", *p);
				// p already points to next token, which is output file
				library_names[num_libnames++] = *p;
				p++; // move to next token
			}
			continue;
		}
		if (bomsh_is_token_inlist(token, skip_token_list, num_tokens)) {
			p++; // move to next token
			continue;
		}
		if (token[0] == '-') {
			continue;
		}
		bomsh_log_printf(level, "found one gcc subfile: %s\n", token);
		// auto-grow the buffer to hold more subfiles
		if (num_subfiles >= subfiles_size) {
			subfiles_size *= 2;
			subfiles = realloc(subfiles, subfiles_size * sizeof(char *));
		}
		subfiles[num_subfiles++] = token;
	}

	// Handle dynamic and static libraries
	int num_dyn_libs = 0;
	// it is sufficient, since #dyn_libs < #subfiles + #libnames
	char **dyn_libs = malloc((num_subfiles + num_libnames + 1) * sizeof(char *));
	int num_infiles = 0;
	// it is sufficient, since #infiles <= #subfiles + #libnames, adding one more for piggy object handling
	char **infiles = malloc((num_subfiles + num_libnames + 2) * sizeof(char *));
	int i;
	log_gcc_subfiles(level, subfiles, num_subfiles, "\nList of subfiles:");
	// save dynamic libraries and add other subfiles to infiles
	bomsh_log_string(level, "\nChecking gcc subfiles\n");
	for (i=0; i<num_subfiles; i++) {
		if (!bomsh_is_regular_file(subfiles[i], cmd->pwd, cmd->root)) {
			bomsh_log_printf(level, "not regular file or not-existent subfile: %s\n", subfiles[i]);
			continue;
		}
		if (is_shared_library(subfiles[i])) {
			dyn_libs[num_dyn_libs++] = strdup(subfiles[i]);
		} else {
			infiles[num_infiles++] = strdup(subfiles[i]);
		}
	}

	// save dynamic libraries and add static libraries to infiles
	log_gcc_subfiles(level, library_paths, num_libpaths, "\nList of library paths:");
	log_gcc_subfiles(level, library_names, num_libnames, "\nList of library names:");
	for (i=0; i<num_libnames; i++) {
		char *libfile = NULL;
		if ((libfile = find_lib_in_libpaths(cmd, library_names[i], library_paths, num_libpaths, (char *)".so"))) {
			bomsh_log_printf(level, "\nAdding dynamic library %s\n", libfile);
			dyn_libs[num_dyn_libs++] = libfile;
		} else if ((libfile = find_lib_in_libpaths(cmd, library_names[i], library_paths, num_libpaths, (char *)".a"))) {
			// this is static library
			bomsh_log_printf(level, "\nAdding static library %s\n", libfile);
			infiles[num_infiles++] = libfile;
		} else if ((libfile = find_lib_in_libpaths(cmd, library_names[i], system_library_paths, 1, (char *)".so"))) {
			// try the system library search at the end
			bomsh_log_printf(level, "\nAdding system dynamic library %s\n", libfile);
			dyn_libs[num_dyn_libs++] = libfile;
		} else if ((libfile = find_lib_in_libpaths(cmd, library_names[i], system_library_paths, 1, (char *)".a"))) {
			// try the system library search at the end
			bomsh_log_printf(level, "\nAdding system static library %s\n", libfile);
			dyn_libs[num_dyn_libs++] = libfile;
		}
	}
	log_gcc_subfiles(level, infiles, num_infiles, "\nList of infiles:");
	log_gcc_subfiles(level, dyn_libs, num_dyn_libs, "\nList of dyn_libs:");

	// Save the results in cmd_data struct
	infiles[num_infiles] = NULL;
	cmd->num_inputs = num_infiles;
	cmd->input_files = infiles;
	if (num_dyn_libs) {
		dyn_libs[num_dyn_libs] = NULL;
		cmd->dynlib_files = dyn_libs;
	} else {
		free(dyn_libs);
	}
	if (output_file) cmd->output_file = output_file;
	free(subfiles);
	if (library_paths) free(library_paths);
	if (library_names) free(library_names);
}

static void bomsh_try_get_gcc_subfiles(bomsh_cmd_data_t *cmd)
{
	if (cmd->input_files) {
		// must have already run bomsh_get_gcc_subfiles().
		return;
	}
	int num_skip_tokens = sizeof(gcc_skip_token_list)/sizeof(*gcc_skip_token_list);
	bomsh_get_gcc_subfiles(cmd, (char **)gcc_skip_token_list, num_skip_tokens);
}

static void bomsh_try_get_ld_subfiles(bomsh_cmd_data_t *cmd)
{
	if (cmd->input_files) {
		// must have already run bomsh_get_gcc_subfiles().
		return;
	}
	int num_skip_tokens = sizeof(linker_skip_tokens)/sizeof(*linker_skip_tokens);
	bomsh_get_gcc_subfiles(cmd, (char **)linker_skip_tokens, num_skip_tokens);
}

// This is for OpenWRT kernel build, and the below should be the piggy_gzip_cmd_file content:
// echo 'cmd_arch/arm/boot/compressed/piggy.gzip := (cat arch/arm/boot/compressed/../Image | gzip -n -f -9 > arch/arm/boot/compressed/piggy.gzip) || (rm -f arch/arm/boot/compressed/piggy.gzip ; false)' > arch/arm/boot/compressed/.piggy.gzip.cmd"

// pigg_gzip_file is absolute path with /root/pwd/path/piggy.gzip format
static char *handle_piggy_gzip(char *piggy_gzip_file)
{
	char buf[PATH_MAX];
	bomsh_log_printf(6, "incbin piggy_gzip file: %s\n", piggy_gzip_file);
	char *end = stpcpy(buf, piggy_gzip_file);
	strcpy(end - strlen("piggy.gzip"), ".piggy.gzip.cmd");
	if (!is_regular_file(buf)) {
		return NULL;
	}
	bomsh_log_printf(6, "found piggy_gzip_cmd file: %s the whole gzip_cmd_str:\n", buf);
	char *content = bomsh_read_file(buf, NULL);
	bomsh_log_string(6, content);

	char *real_image = NULL;
	char delim[] = " ";
	char *ptr = strtok(content, delim);
	while(ptr != NULL)
	{
		if (strcmp(ptr, "(cat") == 0) {
			// the next token is the real image
			ptr = strtok(NULL, delim);
			real_image = strdup(ptr);
			bomsh_log_printf(6, "for piggy_gzip file, found real image: %s\n", real_image);
			break;
		}
		ptr = strtok(NULL, delim);
	}
	free(content);
	return real_image;
}

/*
 * Read the piggy.S file and return the included binary file vmlinux.bin
 *
[root@87e96394b5b5 linux]# cat ./arch/x86/boot/compressed/piggy.S
.section ".rodata..compressed","a",@progbits
.globl z_input_len
z_input_len = 12656291
.globl z_output_len
z_output_len = 43225848
.globl input_data, input_data_end
input_data:
.incbin "arch/x86/boot/compressed/vmlinux.bin.gz"
input_data_end:
.section ".rodata","a",@progbits
.globl input_len
input_len:
	.long 12656291
.globl output_len
output_len:
	.long 43225848
[root@87e96394b5b5 linux]# cat ./arch/arm/boot/compressed/piggy.S
	.section .piggydata, "a"
	.globl	input_data
input_data:
	.incbin	"arch/arm/boot/compressed/piggy_data"
	.globl	input_data_end
input_data_end:
[root@87e96394b5b5 linux]#
[root@rtp base]# cat kernel/linux-mvl-3.14/arch/arm/boot/compressed/piggy.gzip.S
	.section .piggydata,#alloc
	.globl	input_data
input_data:
	.incbin	"arch/arm/boot/compressed/piggy.gzip"
	.globl	input_data_end
input_data_end:
[root@rtp base]#
 *
 * Note, it can be either space character or tab character after ".incbin"
 */
static char * bomsh_read_piggy_S_file(bomsh_cmd_data_t *cmd, char *piggy_S_file)
{
	char buf[PATH_MAX];
	char *piggy_S_path = get_real_path2(cmd, piggy_S_file, buf);
	//bomsh_log_printf(6, "piggy_S file abspath: %s\n", piggy_S_path);
	char *content = bomsh_read_file(piggy_S_path, NULL);
	char *p = content;
	char *inc_bin_str = NULL;
	while (*p) {
		char *token = p; p++;
		if (strncmp(token, ".incbin", strlen(".incbin")) == 0) {
			char *start = strchr(token + strlen(".incbin"), '"');
			if (!start) break;
			char *end = strchr(start + 1, '"');
			if (!end) break;
			*end = 0;
			if (strcmp(end - 3, ".gz") == 0 || strcmp(end - 3, ".xz") == 0) {
				// remove the .gz to get the real vmlinux_bin file
				*(end - 3) = 0;
			}
			if (strcmp(bomsh_basename(start + 1), "piggy.gzip") == 0) {
				//bomsh_log_string(6, "found piggy.gzip incbin file, will read .piggy.gzip.cmd file for real image.\n");
				// start+1 points to "arch/arm/boot/compressed/piggy.gzip" string
				char *piggy_gzip_file = get_real_path2(cmd, start+1, buf);
				inc_bin_str = handle_piggy_gzip(piggy_gzip_file);
			}
			if (!inc_bin_str) {
				inc_bin_str = strdup(start + 1);
			}
			bomsh_log_printf(8, "\nFound real image vmlinux_bin: %s from piggy_S file: %s\n", inc_bin_str, piggy_S_file);
			break;
		}
	}
	free(content);
	return inc_bin_str;
}

// find the piggy.S file from the list of input files
static char * find_piggy_S_file(char *output_file, char **input_files)
{
	// output_file can be NULL, although input_files must not be NULL when reaching here
	if (!output_file) {
		return NULL;
	}
	char *outfile = bomsh_basename(output_file);
	if (strcmp(outfile, "piggy.o") && strcmp(outfile, "piggy.gzip.o")) {
		return NULL;
	}
	char **p = input_files;
	while (*p) {
		char *token = *p; p++;
		char *name = bomsh_basename(token);
		if (strcmp(name, "piggy.S") == 0 || strcmp(name, "piggy.gzip.S") == 0) {
			return token;
		}
	}
	return NULL;
}

static void handle_linux_kernel_piggy_object(bomsh_cmd_data_t *cmd)
{
	if (cmd->depend_file) {
		char *piggy_S_file = find_piggy_S_file(cmd->depends_outfile, cmd->depends_array);
		if (!piggy_S_file) return;
		bomsh_log_printf(8, "From depends_array input files, found piggy.S file: %s\n", piggy_S_file);
		char *vmlinux_bin = bomsh_read_piggy_S_file(cmd, piggy_S_file);
		if (vmlinux_bin) {
			bomsh_log_printf(8, "Found vmlinux.bin file: %s\n", vmlinux_bin);
			cmd->depends_array[cmd->depends_num++] = vmlinux_bin;
			cmd->depends_array[cmd->depends_num] = NULL;
		}
	} else {
		char *piggy_S_file = find_piggy_S_file(cmd->output_file, cmd->input_files);
		if (!piggy_S_file) return;
		bomsh_log_printf(8, "From argv input files, found piggy.S file: %s\n", piggy_S_file);
		char *vmlinux_bin = bomsh_read_piggy_S_file(cmd, piggy_S_file);
		if (vmlinux_bin) {
			bomsh_log_printf(8, "Found vmlinux.bin file: %s\n", vmlinux_bin);
			cmd->input_files[cmd->num_inputs++] = vmlinux_bin;
			cmd->input_files[cmd->num_inputs] = NULL;
		}
	}
}

static int gcc_md_option_exists_in_argv(char **argv)
{
	// only mode 0 and 1 handle -MMD option replacement with -MD option
	if (g_bomsh_config.generate_depfile < 2) { // -MMD without system header files is not ok
		// this covers all negative generate_depfile values
		//if ((is_token_in_argv(argv, "-MD") && is_token_in_argv(argv, "-MF")) ||
		if (is_token_in_argv(argv, "-MD") ||
			is_token_prefix_in_argv(argv, "-Wp,-MD,")) {
			return 1;
		}
	} else { // -MMD without system header files is ok
		if (is_token_in_argv(argv, "-MD") || is_token_in_argv(argv, "-MMD") ||
			is_token_prefix_in_argv(argv, "-Wp,-MD,") ||
			is_token_prefix_in_argv(argv, "-Wp,-MMD,")) {
			return 1;
		}
	}
	return 0;
}

static void bomsh_gcc_generate_depfile(bomsh_cmd_data_t *cmd)
{
	int level = 6;
	if (gcc_generates_dependency_rule(cmd->argv)) { // this cmd has -M option
		char *depend_file = extract_depend_file_from_cc_argv(cmd);
		if (depend_file && g_bomsh_config.generate_depfile == -100) { // -100 is hack mode
			// Invoke a child process to generate dependency file
			cmd->depend_file = depend_file;
			bomsh_log_string(level, "\npre-exec mode, with -M option, instrument gcc for dependency\n");
			bomsh_execve_instrument_for_dependency_with_m_opt(cmd);
			cmd->flags |= 2; // indicate this cmd is instrumented for gcc dependency
			return;
		} else if (g_bomsh_config.generate_depfile < 2) { // only for 0 and 1 mode
			// Invoke a child process to generate dependency file
			bomsh_log_string(level, "\npre-exec mode, with -M option, run child-process gcc for dependency\n");
			bomsh_invoke_subprocess_for_dependency_with_m_opt(cmd);
		}
		if (depend_file) free(depend_file);
		return;
	}
	// Let's try adding extra option to collect dependency list
	if ((g_bomsh_config.generate_depfile & 3) == 0) {
		// Add "-MD -MF depfile" option to existing argv to generate dependency file by default
		bomsh_log_string(level, "\npre-exec mode, instrument gcc command for dependency\n");
		bomsh_execve_instrument_for_dependency(cmd);
		cmd->flags |= 2; // indicate this cmd is instrumented for gcc dependency
	} else if ((g_bomsh_config.generate_depfile & 3) == 1) {
		// Invoke a child process to generate dependency file
		bomsh_log_string(level, "\npre-exec mode, run child-process gcc for dependency\n");
		bomsh_invoke_subprocess_for_dependency(cmd);
	}
	// mode 2 and 3 will not generate depfile
}

static void bomsh_gcc_try_generate_depfile(bomsh_cmd_data_t *cmd)
{
	// 100 and 101 are special, to skip is_compile_only() check, 100 will instrument, and 101 will invoke subprocess
	if (g_bomsh_config.generate_depfile == 100 || g_bomsh_config.generate_depfile == 101
			|| gcc_is_compile_only(cmd->argv)) {
		//if(!gcc_generates_dependency_rule(cmd->argv)) { // must not have -r/-M option
		//if (!is_token_in_argv(cmd->argv, "-r") && !gcc_generates_dependency_rule(cmd->argv)) { // must not have -r/-M option
		if (!is_token_in_argv(cmd->argv, "-r")) { // must not have -r option
			bomsh_try_get_gcc_subfiles(cmd);
			if (!cmd->num_inputs || (cmd->num_inputs == 1 && strcmp(cmd->input_files[0], "/dev/null") == 0)) {
				bomsh_log_string(6, "\nThere is no input file, or input is /dev/null, skip recording raw info\n");
				cmd->skip_record_raw_info = 1;
				return;
			}
			bomsh_gcc_generate_depfile(cmd);
		}
	}
}

static void bomsh_process_gcc_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	int level = 6;
	if (pre_exec_mode) {
		bomsh_log_printf(13, "\n== BEFORE EXEC we will now start handling CC command pid %d\n", cmd->pid);
		bomsh_log_cmd_data(cmd, 13);

		// always get outfile first, make it easier for later handling
		cmd->output_file = get_outfile_in_argv(cmd->argv);
		bomsh_log_printf(level, "gcc cmdline found output file %s\n", cmd->output_file);
		if (!cmd->output_file) {
			bomsh_log_string(21, "\ngcc/clang commands without -o option are not handled\n");
			cmd->skip_record_raw_info = 1;
			return;
		}
		// "clang -cc1" and "clang -cc1as" commands are not handled, since they are invoked by clang parent process
		if (is_token_in_argv(cmd->argv, "-cc1") || is_token_in_argv(cmd->argv, "-cc1as")) {
			bomsh_log_string(21, "\nclang -cc1 or -cc1as commands are not handled\n");
			cmd->skip_record_raw_info = 1;
			return;
		}
#if 0
		// commands with -pipe but without -o option are not handled
		if (is_token_in_argv(cmd->argv, "-pipe") && !cmd->output_file) {
			bomsh_log_string(21, "\ngcc/clang commands with -pipe option but without -o option are not handled\n");
			cmd->skip_record_raw_info = 1;
			return;
		}
#endif
		// check if we can skip some undesired outfile earlier
		//if (cmd->output_file) {
		if (1) {
			if (strcmp(cmd->output_file, "/dev/null") == 0) {
				// no need to do anything if output is /dev/null
				bomsh_log_string(level, "\nThe output file is /dev/null, skip recording raw info\n");
				cmd->skip_record_raw_info = 1;
				return;
			}
			// CC cmd invoked by CGO is handled only if the config value is 1
			// We observed that the outfile path always contains "tmp/go-build" substring.
			if (g_bomsh_config.handle_cgo_cc_cmd != 1 && strstr(cmd->output_file, "tmp/go-build")) {
                                // GCO CC command is not handled, because special CGO stack manipulation issue
				cmd->flags |= 4; // indicate this cmd is CGO invoked gcc/clang cmd, and we don't generate depfile for it
                                if (!g_bomsh_config.handle_cgo_cc_cmd) { // do not handle at all
					bomsh_log_printf(level, "\nThe output file %s is CGO go-build outfile, skip recording raw info\n", cmd->output_file);
					cmd->skip_record_raw_info = 1;
				} else { // info-only
					bomsh_log_printf(level, "\nThe output file %s is CGO go-build outfile, recording raw info as info-only\n", cmd->output_file);
					cmd->skip_record_raw_info = 2;
				}
                                return;
                        }
		}

		if (!g_bomsh_config.handle_conftest) {
			// outfiles are usually conftest/conftest.o/conftest2.o
			if (strncmp(bomsh_basename(cmd->output_file), "conftest", strlen("conftest")) == 0) {
				bomsh_log_string(level, "\nconftest outfile, will skip recording raw info\n");
				cmd->skip_record_raw_info = 1;
				return;
			}
			// CMakeFiles testing also just fails, so we can ignore these gcc cmd too
			// output file always starts with CMakeFiles/cmTC_
			if (strncmp(cmd->output_file, "cmTC_", strlen("cmTC_")) == 0 ||
					strncmp(cmd->output_file, "CMakeFiles/cmTC_", strlen("CMakeFiles/cmTC_")) == 0) {
				int pwd_len = strlen(cmd->pwd);
				const char *suffix = "CMakeFiles/CMakeTmp";
				int suffix_len = strlen(suffix);
				// pwd always ends with CMakeFiles/CMakeTmp
				if (pwd_len > suffix_len && strcmp(cmd->pwd + pwd_len - suffix_len, suffix) == 0) {
					bomsh_log_string(level, "\nCMakeFiles Tmp outfile, will skip recording raw info\n");
					cmd->skip_record_raw_info = 1;
					return;
				}
			}
			// Perl SDK always has try.o output file, which usually just fails, so we can ignore this gcc cmd
			if (strcmp(cmd->output_file, "try.o") == 0 && strstr(cmd->pwd, "/perl-")) {
				bomsh_log_string(level, "\nperl try.o outfile, will skip recording raw info\n");
				cmd->skip_record_raw_info = 1;
				return;
			}
			bomsh_try_get_gcc_subfiles(cmd);
			if (!cmd->num_inputs || (cmd->num_inputs == 1 && strncmp(bomsh_basename(cmd->input_files[0]), "conftest", strlen("conftest")) == 0)) {
				// infiles are usually conftest.c/conftest.cpp
				bomsh_log_string(level, "\nconftest infile, will skip recording raw info\n");
				cmd->skip_record_raw_info = 1;
				return;
			}
		}

		// gcc cmd may already generate dependency file, if so, use it directly
		if (gcc_md_option_exists_in_argv(cmd->argv)) {
			cmd->depend_file = extract_depend_file_from_cc_argv(cmd);
			bomsh_log_string(level, "pre-exec mode, found cc command with depend-file\n");
			if (cmd->depend_file) {
				if (strcmp(cmd->depend_file, "/dev/null")) { // not /dev/null file, valid depend_file
					return; // will read the depend_file and record depenency after EXECVE syscall
				} else {
					free(cmd->depend_file);
					cmd->depend_file = NULL;
				}
			}
		}

		// try to generate dependency file if needed.
		bomsh_gcc_try_generate_depfile(cmd);

		bomsh_log_printf(14, "\n== BEFORE EXEC we are now done handling CC command pid %d\n", cmd->pid);
		bomsh_log_cmd_data(cmd, 14);
		return;
	}

	bomsh_log_printf(14, "\n==  AFTER EXEC we will now start handling CC command pid %d\n", cmd->pid);
	bomsh_log_cmd_data(cmd, 14);

	// non-pre-exec mode, invoked after the execve syscall
	if (cmd->skip_record_raw_info == 1) return;
#if 0
	if (cmd->depend_file) {  // some debugging code for dependency file parsing
		char buf[500]; static int mydep_count = 0;
		char *path = get_real_path(cmd, cmd->depend_file);
		sprintf(buf, "mkdir -p /tmp/mydepend; cp %s /tmp/mydepend/%s.%d", path, bomsh_basename(cmd->depend_file), mydep_count++);
		bomsh_log_printf(3, "try to copy depend file: %s, copy cmd: %s\n", cmd->depend_file, buf);
		if (system(buf) == -1) {
			bomsh_log_string(3, "Failed to invoke system cp gcc_dep.d command\n");
		}
		free(path);
	}
#endif
	if (!cmd->depend_file || !bomsh_check_permission(cmd->depend_file, cmd->pwd, cmd->root, R_OK)) {
		bomsh_log_string(level, "\nAfter EXECVE syscall, no depfile or depfile does not exist, so let's get subfiles in gcc cmd\n");
		if (cmd->depend_file) {
			free(cmd->depend_file);
			cmd->depend_file = NULL;
		}
		bomsh_try_get_gcc_subfiles(cmd);
		bomsh_log_cmd_data(cmd, 7);
	}
	// when we are here, if cmd->depend_file is not NULL, then depend_file must exist;
	// or if cmd->denpend_file is NULL, then cmd->input_files must not be NULL.
	if (cmd->depend_file) {
		bomsh_log_printf(level, "Start reading depend file %s\n", cmd->depend_file);
		bomsh_cmd_read_depend_file(cmd);
		bomsh_log_cmd_data(cmd, 24);
		bomsh_log_printf(level, "After reading depend file %s\n", cmd->depend_file);
	}
	// check if ld_cmd has outfile but gcc cmd does not. This is the case for the default a.out file.
	if (!cmd->output_file && cmd->ld_cmd) {
		bomsh_cmd_data_t *ld_cmd = cmd->ld_cmd;
		if (ld_cmd->output_file) {
			cmd->output_file = strdup(ld_cmd->output_file);
			cmd->flags |= 1; // to indicate that output_file is allocated and needs to be freed
		}
	}
	// Check if it is special piggy object from Linux kernel build
	handle_linux_kernel_piggy_object(cmd);
	bomsh_record_raw_info(cmd);
	bomsh_log_printf(14, "\n==  AFTER EXEC we are now done handling CC command pid %d\n", cmd->pid);
	bomsh_log_cmd_data(cmd, 14);
}

// Allocate string pointer array of size 2, with first element of TOKEN string.
static char ** alloc_2element_array(char *token)
{
	char **array = malloc( 2 * sizeof(char *) );
	array[0] = strdup(token);
	array[1] = NULL;
	return array;
}

// get all hashes of input files and put them into cmd->input_shaN array
// this is for the mode 2 of recording ADF raw info.
static void get_hash_of_infiles(bomsh_cmd_data_t *cmd)
{
	if (g_bomsh_config.hash_alg < 0) {
		return;
	}
	if (!cmd->input_files) {
		return;
	}
	if (!cmd->num_inputs) { // calculate #inputs if not yet calculated
		char **p = cmd->input_files;
		while (*p) {
			p++;
		}
		cmd->num_inputs = (p - cmd->input_files)/sizeof(char *);
	}
	char *sha1_array = NULL;
	char *sha256_array = NULL;
	char **sha1 = NULL;
	char **sha256 = NULL;
	int num_inputs = cmd->num_inputs;
	int hash_alg = g_bomsh_config.hash_alg;
	if (hash_alg & 2) {
		cmd->input_sha256 = malloc((num_inputs + 1) * sizeof(char *));
		// allocate a single buffer to hold all hashes
		sha256_array = malloc(num_inputs * (GITOID_LENGTH_SHA256 * 2 + 1));
		sha256 = cmd->input_sha256;
		sha256[num_inputs] = NULL;
	}
	if (hash_alg != 2) {
		cmd->input_sha1 = malloc((num_inputs + 1) * sizeof(char *));
		sha1_array = malloc(num_inputs * (GITOID_LENGTH_SHA1 * 2 + 1));
		sha1 = cmd->input_sha1;
		sha1[num_inputs] = NULL;
	}
	for (int i=0; i<num_inputs; i++) {
		char buf[PATH_MAX];
		char *afile = cmd->input_files[i];
		char *path = get_real_path2(cmd, afile, buf);
		if( access( path, F_OK) != 0 ) {
			// use empty "" hash string for non-existent infile, which is not yet created at pre-exec time
			if (hash_alg & 2) {
				sha256[i] = sha256_array + i * (GITOID_LENGTH_SHA256 * 2 + 1);
				sha256[i][0] = 0;
			}
			if (hash_alg != 2) {
				sha1[i] = sha1_array + i * (GITOID_LENGTH_SHA1 * 2 + 1);
				sha1[i][0] = 0;
			}
			continue;
		}
		if (hash_alg & 2) {
			sha256[i] = sha256_array + i * (GITOID_LENGTH_SHA256 * 2 + 1);
			sha256[i][GITOID_LENGTH_SHA256 * 2] = 0;
			bomsh_get_omnibor_sha256_hash(path, sha256[i]);
		}
		if (hash_alg != 2) {
			sha1[i] = sha1_array + i * (GITOID_LENGTH_SHA1 * 2 + 1);
			sha1[i][GITOID_LENGTH_SHA1 * 2] = 0;
			if (g_bomsh_config.hash_alg == 100) { // use empty hash for this special hash_alg of 100
				// Note 100 & 2 = 0, so it won't affect the above sha256 array
				sha1[i][0] = 0;
			} else {
				bomsh_get_omnibor_sha1_hash(path, sha1[i]);
			}
		}
	}
}

static int is_ar_command(char *name)
{
	return strcmp(name, "ar") == 0 || strcmp(name + strlen(name) - 3, "-ar") == 0;
}

// read list of ar input files from a text file, each line is an input file
static void ar_read_infiles_from_file(bomsh_cmd_data_t *cmd, char *afile)
{
	int array_size = 100;
	char **array = malloc( array_size * sizeof(char *) );
	int num_array = 0;
	char buf[PATH_MAX];
	char *bfile = get_real_path2(cmd, afile, buf);
	char *content_file = bomsh_read_file(bfile, NULL);
	char *p = content_file;
	char *prev = p;
	while (*p) {
		if (*p == '\n') {
			bomsh_log_printf(4, "found one AR infile: %s\n", prev);
			*p = 0;
			array[num_array++] = strdup(prev);
			if (num_array >= array_size) {
				array_size *= 2;
				array = realloc(array, array_size * sizeof(char *));
			}
			prev = p+1;
		}
		p++;
	}
	array[num_array] = NULL;
	cmd->num_inputs = num_array;
	cmd->input_files = array;
	free(content_file);
	return;
}

// Parse cmd->argv, and get all files from the command line
static void get_all_subfiles_in_ar_cmdline(bomsh_cmd_data_t *cmd)
{
	char *token1 = NULL;
	char *token2 = NULL;
	char **ptoken3 = NULL;
	char **p = cmd->argv;
	int num_tokens = 1; p++; // start from argv[1]
	while (*p) {
		if (strcmp(*p, "--plugin") == 0) {
			p += 2;  // skip "--plugin name" part
			continue;
		}
		if (num_tokens == 1) token1 = *p;
		else if (num_tokens == 2) token2 = *p;
		else if (num_tokens == 3) ptoken3 = p;
		p++; num_tokens++;
	}
	if (num_tokens < 3) return;
	if (! ((num_tokens > 3 && (strchr(token1, 'c') || strchr(token1, 'r')))
		|| (num_tokens == 3 && strchr(token1, 's'))) ) {
		// # Only "ar -c archive file1...fileN", "ar -c archive @filelist", and "ar -s archive" are supported
		// # also support "ar rvs archive file1...fileN" format
		return;
	}
	if (!g_bomsh_config.handle_conftest && (strcmp(token2, "libconftest.a") == 0 || strcmp(token2, "conftest.a") == 0)) {
		cmd->skip_record_raw_info = 1;
		return;
	}
	cmd->output_file = token2;
	if (num_tokens == 3) {  // should be "ar -s archive"
		char **array = alloc_2element_array(token2);
		cmd->num_inputs = 1;
		cmd->input_files = array;
		get_hash_of_infiles(cmd);
		return;
	}
	if (num_tokens > 3) {
		if ((*ptoken3)[0] == '@') { // "ar -c archive @filelist"
			ar_read_infiles_from_file(cmd, *ptoken3 + 1);
			return;
		}
		p = ptoken3; // first input file
	}
	char **array = malloc( (num_tokens - 2) * sizeof(char *) );
	int i;
	for (i=0; i<num_tokens - 3; i++, p++) {
		array[i] = get_real_path(cmd, *p);
	}
	array[i] = NULL;
	cmd->num_inputs = i;
	cmd->input_files = array;
}

/*
 * Only "ar -c archive file1 file2", "ar -c archive @filelist", and "ar -s archive" are supported
 */
static void bomsh_process_ar_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for ar command\n");
		get_all_subfiles_in_ar_cmdline(cmd);
		return;
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for ar command after EXECVE syscall\n");
		bomsh_record_raw_info_for_command(cmd);
	}
}

/******** GNU assembler/linker as/ld command handling routines ********/

// Parse cmd->argv, and get all files from the command line
static void bomsh_get_gnu_as_subfiles(bomsh_cmd_data_t *cmd, char **skip_token_list, int num_tokens)
{
	char *output_file = NULL;
	int subfiles_size = 100;
	int num_subfiles = 0;
	char **subfiles = malloc(subfiles_size * sizeof(char *));

	char **p = cmd->argv;
	p++; // start with argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already

		// well, we still need to handle this -o option, otherwise, the outfile will be added to infiles
		if (strncmp(token, "-o", 2) == 0) {
			int len = strlen(token);
			if (len > 2) {
				output_file = token + 2;
			} else {
				// p already points to next token, which is output file
				output_file = *p;
				p++; // move to next token
			}
			if (output_file && strcmp(output_file, "/dev/null") == 0) {
				bomsh_log_string(3, "NULL outfile, no need to process GNU AS command\n");
				cmd->skip_record_raw_info = 1;
				free(subfiles);
				return;
			}
			bomsh_log_printf(4, "found output file %s\n", output_file);
			continue;
		}

		if (bomsh_is_token_inlist(token, skip_token_list, num_tokens)) {
			p++; // move to next token
			continue;
		}
		if (token[0] == '-') {
			continue;
		}
		bomsh_log_printf(4, "found one GNU AS subfile: %s\n", token);
		// auto-grow the buffer to hold more subfiles
		if (num_subfiles >= subfiles_size) {
			subfiles_size *= 2;
			subfiles = realloc(subfiles, subfiles_size * sizeof(char *));
		}
		subfiles[num_subfiles++] = token;
	}

	int num_infiles = 0;
	// it is sufficient, since #infiles <= #subfiles
	char **infiles = malloc((num_subfiles + 1) * sizeof(char *));
	log_gcc_subfiles(4, subfiles, num_subfiles, "\nList of subfiles:");
	bomsh_log_string(4, "\nChecking GNU AS subfiles\n");
	for (int i=0; i<num_subfiles; i++) {
		if (!bomsh_is_regular_file(subfiles[i], cmd->pwd, cmd->root)) {
			bomsh_log_printf(4, "not regular file or not-existent subfile: %s\n", subfiles[i]);
			continue;
		}
		infiles[num_infiles++] = strdup(subfiles[i]);
	}
	log_gcc_subfiles(4, infiles, num_infiles, "\nList of infiles:");

	// Save the results in cmd_data struct
	infiles[num_infiles] = NULL;
	cmd->num_inputs = num_infiles;
	cmd->input_files = infiles;
	if (output_file) cmd->output_file = output_file;
	free(subfiles);
}

static void bomsh_process_as_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for GNU AS command\n");
		cmd->ppid = bomsh_get_ppid(cmd->pid);
		bomsh_cmd_data_t *parent_cmd = bomsh_get_cmd(cmd->ppid);
		if (parent_cmd && is_cc_compiler( bomsh_basename(parent_cmd->path) )) {
			// invoked by GCC
			bomsh_log_printf(8, "Skip recording raw info, GNU AS command parent PID: %d prog: %s\n", cmd->ppid, parent_cmd->path);
			cmd->skip_record_raw_info = 1;
			return;
		}
		int num_skip_tokens = sizeof(gnu_as_skip_tokens)/sizeof(*gnu_as_skip_tokens);
		bomsh_get_gnu_as_subfiles(cmd, (char **)gnu_as_skip_tokens, num_skip_tokens);
		return;
	} else {
		if (cmd->skip_record_raw_info == 1) return;
		bomsh_log_string(3, "\nrecord raw_info for GNU AS command after EXECVE syscall\n");
		bomsh_record_raw_info(cmd);
	}
}

static void bomsh_link_ld_with_gcc_cmd(bomsh_cmd_data_t *cmd, bomsh_cmd_data_t *gcc_cmd)
{
	bomsh_log_printf(8, "\nLinking the child ld pid %d and parent cc pid %d\n", cmd->pid, gcc_cmd->pid);
	gcc_cmd->ld_cmd = cmd; // link this ld cmd to its parent GCC CMD
	cmd->refcount ++; // delay the memory free of this ld cmd
	bomsh_log_printf(8, "\nCmd memory refcount++ to %d for ld cmd pid %d\n", cmd->refcount, cmd->pid);
	if (g_bomsh_config.record_raw_info_flags & 1) { // this flag means info-only ADG is recorded
		// do we really need to check this flag? yes, this is useful to get rid of some noise for CGO.
		if (gcc_cmd->flags & 0x4 && !g_bomsh_config.handle_cgo_cc_cmd) {
			// gcc cmd is invoked by CGO, no need to record this ld cmd
			cmd->skip_record_raw_info = 1; // skip recording for this ld cmd
		} else {
			cmd->skip_record_raw_info = 2; // info only for this ld cmd
		}
	} else {
		cmd->skip_record_raw_info = 1; // skip recording for this ld cmd
	}
}

static void bomsh_process_ld_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for LD command\n");
		bomsh_try_get_ld_subfiles(cmd);
		if (!g_bomsh_config.handle_conftest) {
			// outfiles are usually conftest/conftest.o/conftest2.o
			if (cmd->output_file && strncmp(bomsh_basename(cmd->output_file), "conftest", strlen("conftest")) == 0) {
				bomsh_log_string(3, "\nconftest outfile, will skip recording raw info\n");
				cmd->skip_record_raw_info = 1;
				return;
			}
			if (!cmd->num_inputs || (cmd->num_inputs == 1 && strncmp(bomsh_basename(cmd->input_files[0]), "conftest", strlen("conftest")) == 0)) {
				// infiles are usually conftest.c/conftest.cpp
				bomsh_log_string(3, "\nconftest infile, will skip recording raw info\n");
				cmd->skip_record_raw_info = 1;
				return;
			}
		}

		// try finding its parent gcc/clang command
		cmd->ppid = bomsh_get_ppid(cmd->pid);
		bomsh_cmd_data_t *parent_cmd = bomsh_get_cmd(cmd->ppid);
		if (parent_cmd) {
			bomsh_log_printf(8, "ld command's parent PID: %d prog: %s\n", cmd->ppid, parent_cmd->path);
		}
		if (parent_cmd && is_cc_compiler(bomsh_basename(parent_cmd->path))) {
			bomsh_link_ld_with_gcc_cmd(cmd, parent_cmd);
		} else {
			pid_t grand_parent_pid = bomsh_get_ppid(cmd->ppid);
			bomsh_cmd_data_t *grand_parent_cmd = bomsh_get_cmd(grand_parent_pid);
			if (grand_parent_cmd) {
				char *path = grand_parent_cmd->path;
				bomsh_log_printf(8, "ld command's grand parent PID: %d prog: %s\n", grand_parent_pid, path);
				if (is_cc_compiler(bomsh_basename(path))) {
					bomsh_link_ld_with_gcc_cmd(cmd, grand_parent_cmd);
				}
			}
		}

		return;
	} else {
		if (cmd->skip_record_raw_info == 1) return;
		bomsh_log_string(3, "\nrecord raw_info for LD command after EXECVE syscall\n");
		bomsh_record_raw_info(cmd);
	}
}

/******** end of GNU assembler/linker as/ld command handling routines ********/

static int is_eu_strip_command(char *name)
{
	return strcmp(name + strlen(name) - 8, "eu-strip") == 0;
}

static int is_strip_command(char *name)
{
	return strcmp(name, "strip") == 0 || strcmp(name + strlen(name) - 6, "-strip") == 0;
}

// Parse cmd->argv, and get all files from the command line
static void get_all_subfiles_in_strip_like_cmdline(bomsh_cmd_data_t *cmd, char **skip_token_list, int num_tokens)
{
	int array_size = 100;
	int num_array = 0;
	char **array = malloc(array_size * sizeof(char *));
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already
		if (bomsh_is_token_inlist(token, skip_token_list, num_tokens)) {
			p++;  // move to next token
			bomsh_log_printf(4, "found strip-like skip token: %s\n", token);
			continue;
		}
		// need to handle -o option
		if (strncmp(token, "-o", 2) == 0) {
			int len = strlen(token);
			if (len > 2) {
				cmd->output_file = token + 2;
			} else {
				cmd->output_file = *p; p++;
			}
		}
		if (token[0] == '-') {
			// should we reset num_array to 0 here?
			continue;
		}
		bomsh_log_printf(4, "found strip-like infile: %s\n", token);
		array[num_array++] = strdup(token);
		if (num_array >= array_size) {
			array_size *= 2;
			array = realloc(array, array_size * sizeof(char *));
		}
	}
	array[num_array] = NULL;
	cmd->input_files = array;
	cmd->num_inputs = num_array;
	if (!cmd->output_file && num_array) {
		cmd->output_file = array[0]; // need to set it because record_raw_info checks output_file
	}
}

/*
 * Process a generic strip-like shell command like strip/eu-strip/dwz/rpmsign
 * generic command format: dwz [OPTION...] [FILES]
 *   strip --strip-debug -o drivers/firmware/efi/libstub/x86-stub.stub.o drivers/firmware/efi/libstub/x86-stub.o
 *   dwz -mdebian/libssl1.1/usr/lib/debug/.dwz/x86_64-linux-gnu/libssl1.1.debug -- debian/libcrypto1.1-udeb/usr/lib/libcrypto.so.1.1 debian/libssl1.1/usr/lib/x86_64-linux-gnu/libssl.so.1.1
 *   rpm --addsign|--resign [rpmsign-options] PACKAGE_FILE ..
 *   rpmsign --addsign|--delsign [rpmsign-options] PACKAGE_FILE ..
 *   which: strip=0, eu-strip=1, dwz=2, rpmsign=3
 */
static void bomsh_process_strip_like_command(bomsh_cmd_data_t *cmd, int pre_exec_mode, int which)
{
	if (!pre_exec_mode) {
		if (!cmd->output_file) return;
		bomsh_log_string(3, "\nrecord raw_info for strip-like command after EXECVE syscall\n");
		if (strcmp(cmd->output_file, cmd->input_files[0])) {
			// "-o FILE" option exists, and outfile is different from infile
			bomsh_record_raw_info(cmd);
		} else {
			bomsh_record_raw_info2(cmd);
		}
		return;
	}
	bomsh_log_string(3, "\npre-exec mode, get subfiles for strip-like command\n");
	char **skip_token_list = NULL;
	int num_skip_tokens = 0;
	switch (which) {
		case 0: // strip
			skip_token_list = (char **)strip_skip_token_list;
			num_skip_tokens = sizeof(strip_skip_token_list)/sizeof(*strip_skip_token_list);
			break;
		case 1: // eu-strip
			skip_token_list = (char **)eu_strip_skip_token_list;
			num_skip_tokens = sizeof(eu_strip_skip_token_list)/sizeof(*eu_strip_skip_token_list);
			break;
		case 2: // dwz
			skip_token_list = (char **)dwz_skip_token_list;
			num_skip_tokens = sizeof(dwz_skip_token_list)/sizeof(*dwz_skip_token_list);
			break;
		case 3: // rpmsign
			skip_token_list = (char **)rpmsign_skip_token_list;
			num_skip_tokens = sizeof(rpmsign_skip_token_list)/sizeof(*rpmsign_skip_token_list);
			break;
		default:
			bomsh_log_string(18, "Not supported program for process_strip_like_command\n");
			break;
	}
	get_all_subfiles_in_strip_like_cmdline(cmd, skip_token_list, num_skip_tokens);
	if (!cmd->output_file) {
		bomsh_log_string(8, "Empty output/input file, do nothing\n");
		return;
	}
	if (strcmp(cmd->output_file, cmd->input_files[0]) == 0) {
		get_hash_of_infiles(cmd);
	}
}

/******** cat/patch command handling routines ********/

#define BOMSH_PIPE_CMDS_SIZE 20

// list of cmds with active pipes
static bomsh_cmd_data_t *bomsh_pipe_cmds[2][BOMSH_PIPE_CMDS_SIZE];

// add a new cmd to list of active pipes, IN_OR_OUT can only be 0 or 1, 0 means IN and 1 means OUT.
// for cat cmd, its stdout is pipe, thus IN_OR_OUT is 1 for cat
// for patch cmd, its stdin is pipe, thus IN_OR_OUT is 0 for patch
static void bomsh_add_pipe_cmd(bomsh_cmd_data_t *cmd, int in_or_out)
{
	bomsh_cmd_data_t **cmds = bomsh_pipe_cmds[in_or_out];
	for (int i=0; i < BOMSH_PIPE_CMDS_SIZE; i++) {
		if (!cmds[i]) {
			cmds[i] = cmd;
			bomsh_log_printf(8, "\nSucceed to add pid %d to %s PIPE cmds slot %d\n",
					cmd->pid, in_or_out ? "OUT" : "IN", i);
			return;
		}
	}
	bomsh_log_printf(8, "\nFailed to add pid %d to %s PIPE cmds\n", cmd->pid, in_or_out ? "OUT" : "IN");
}

static void bomsh_remove_pipe_cmd(bomsh_cmd_data_t *cmd, int in_or_out)
{
	bomsh_cmd_data_t **cmds = bomsh_pipe_cmds[in_or_out];
	for (int i=0; i < BOMSH_PIPE_CMDS_SIZE; i++) {
		if (cmds[i] == cmd) {
			cmds[i] = NULL;
			bomsh_log_printf(8, "\nSucceed to remove pid %d from %s PIPE cmds slot %d\n",
					cmd->pid, in_or_out ? "OUT" : "IN", i);
			return;
		}
	}
	bomsh_log_printf(8, "\nFailed to remove pid %d from %s PIPE cmds\n", cmd->pid, in_or_out ? "OUT" : "IN");
}

// find the other cmd with matching IN_OR_OUT pipe
// for patch CMD, in_or_out should be 1, since we are finding a matching pipe from cat, which has OUT PIPE.
// for cat CMD, in_or_out should be 0, since we are finding a matching pipe from patch, which has IN PIPE.
static bomsh_cmd_data_t *bomsh_find_match_pipe_cmd(bomsh_cmd_data_t *cmd, int in_or_out)
{
	bomsh_cmd_data_t **cmds = bomsh_pipe_cmds[in_or_out];
	for (int i=0; i < BOMSH_PIPE_CMDS_SIZE; i++) {
		if (cmds[i]) {
			if ((in_or_out && strcmp(cmd->stdin_file, cmds[i]->stdout_file) == 0) ||
				(!in_or_out && strcmp(cmd->stdout_file, cmds[i]->stdin_file) == 0)) {
				bomsh_log_printf(8, "\nSuccessfully find matching cmd with pid %d from %s PIPE cmds slot %d for my PID %d\n",
					cmds[i]->pid, in_or_out ? "OUT" : "IN", i, cmd->pid);
				return cmds[i];
			}
		}
	}
	bomsh_log_printf(8, "\nFailed to find matching cmd from %s PIPE cmds for my PID %d\n", in_or_out ? "OUT" : "IN", cmd->pid);
	return NULL;
}

// is it the start of a patch line that contains the file name to patch?
static int is_leading_token_for_patch_file_line(char *p)
{
	return ((*p == '-' && *(p+1) == '-' && *(p+2) == '-') ||
		 (*p == '+' && *(p+1) == '+' && *(p+2) == '+') ||
		 (*p == '*' && *(p+1) == '*' && *(p+2) == '*')) && *(p+3) == ' ';
}

// is it the ending string for the patch file line?
// The end string is supposed to be "date timestamp timezone" format, like
// --- hostname/hostname.1.rh   2013-11-03 15:24:23.000000000 +0100
// +++ squashfs4.2/squashfs-tools/unsquashfs.h     Tue Mar  5 16:25:57 2013
// --- libusal/CMakeLists.txt     (Revision 579)
static int is_ending_date_timestamp(char *ending)
{
	char *new_str = strdup(ending);
	char delim[] = " \t"; // both space and tab characters are valid separators
	char *saveptr = NULL;
	char *ptr = strtok_r(new_str, delim, &saveptr);
	int num_tokens = 0;
	while(ptr != NULL) {
		if (num_tokens > 2) { // do not check the first two tokens
			char *p = ptr;
			while (*p) {
				// the rest must be date/timestamp/timezone, check it
				if ((*p < '0' || *p > '9') && *p != '-' && *p != '+' && *p != '.' && *p != ':') {
					bomsh_log_printf(10, "found invalid character '%c' in date/timestamp token '%s' for line: %s\n", *p, ptr, ending);
					free(new_str);
					return 0;
				}
				p++;
			}
		}
		ptr = strtok_r(NULL, delim, &saveptr);
		num_tokens++;
	}
	if (num_tokens > 6) { // too many tokens
		free(new_str);
		return 0;
	}
	free(new_str);
	return 1;
}

// the line for old/new file has the format of:
// --- path/to/file date timestamp timezone
// +++ path/to/file
//
// that is, either 5 tokens or 2 tokens, the field separater can be space or tab character
// *** abc.txt    2023-05-07 05:53:03.507745185 +0000
// --- /dev/null	2023-03-12 07:26:45.840592285 +0000
//
// --- hostname/hostname.1.rh	2013-11-03 15:24:23.000000000 +0100
// +++ abc2.txt

// parse the line and return the file path, and its length.
static char * parse_patch_file_line(char *line, int *length, int strip_num)
{
	char *ptr = line + 4;
	char *p = ptr;
	int strips = strip_num;
	if (strncmp(ptr, "/dev/null", strlen("/dev/null")) == 0) { // "/dev/null" is special
		strips = 0;  // no stripping, even if -p1 or -p2 in patch cmd
	}
	bomsh_log_printf(10, "\nparse patch file line: %s\n", line);
	while (1) {
		char c = *p;
		if (c == '\t' || c == ' ' || !c) {
			if (p == ptr) return NULL; // empty file
			int len = (int)(p - ptr);
			if (length) *length = len;
			if (!is_ending_date_timestamp(p)) { // additional check on valid date/timestamp ending
				return NULL;
			}
			bomsh_log_printf(10, "found valid file with length %d to patch: %s\n", len, ptr);
			return ptr;
		} else if (c == ',') { // if there is comma character, then this is invalid file
			// *** 2768,2771 ****
			// --- 2768,2773 ----
			bomsh_log_printf(10, "found comma in invalid file: %s\n", ptr);
			return NULL;
		} else if (c == '/') {
			strips --;
			if (!strips) {
				ptr = p + 1; // found the start of the file
				bomsh_log_printf(10, "found start of the file: %s\n", ptr);
			}
		}
		p++;
	}
	return NULL;
}

// read patch file and return the list of files to patch.
// return the number of files to patch in the patch file.
// if FILES is not NULL, then the list of files will be put there.
static int bomsh_read_patch_file(bomsh_cmd_data_t *cmd, char *patch_file, int strip_num, char *change_dir, char ***files)
{
	char *patch_str = bomsh_read_file(patch_file, NULL);
	bomsh_log_printf(22, "\nReading patch_file: %s the whole patch_str:\n%s\n", patch_file, patch_str);
	if (!patch_str) {
		return 0;
	}
	// the -d option of patch cmd may specify a different change_dir than cmd->pwd
	char *patch_file_pwd = change_dir ? change_dir : (cmd->pwd);

	int num_files = 0;
	// record the start position and length of each file
	char *afiles[200]; int alens[200];

	char delim[] = "\n";
	char *saveptr = NULL;
	char *ptr = strtok_r(patch_str, delim, &saveptr);
	while(ptr != NULL)
	{
		if (is_leading_token_for_patch_file_line(ptr)) {
			int length = 0;
			char *afile = parse_patch_file_line(ptr, &length, strip_num);
			if (afile) {
				afiles[num_files] = afile;  // start position of the file
				alens[num_files] = length; // the string length of the file
				num_files ++;
				if (num_files >= 200) {
					bomsh_log_printf(8, "Warning: reached maximum of 200 files to patch in patch file: %s\n", patch_file);
					break;
				}
			}
		}
		ptr = strtok_r(NULL, delim, &saveptr);
	}
	bomsh_log_printf(8, "\nfind %d files from the patch_str\n", num_files);
	if (!num_files || num_files % 2 != 0) {
		bomsh_log_printf(8, "\nWarning: odd number %d of files found in patch file: %s\n", num_files, patch_file);
		return 0;
	}
	int num_files2 = num_files/2;

	char buf[1024]; // should be enough to hold file to patch
	char **bfiles = malloc( (num_files2 + 1) * sizeof(char *) );
	char *cfile; int clen;
	// select the files to patch from two candidates
	for (int i=0; i < num_files2 ; i++) {
		char *afile = afiles[i * 2]; int alen = alens[i * 2];
		char *bfile = afiles[i * 2 + 1]; int blen = alens[i * 2 + 1];
		// The file with shorter length is preferred if it exists.
		if (alen == blen && strncmp(afile, bfile, alen) == 0) {
			cfile = afile; clen = alen;
		} else if (alen == strlen("/dev/null") && strncmp(afile, "/dev/null", strlen("/dev/null")) == 0) {
			cfile = bfile; clen = blen;
		} else if (blen == strlen("/dev/null") && strncmp(bfile, "/dev/null", strlen("/dev/null")) == 0) {
			cfile = afile; clen = alen;
		} else if (alen <= blen) {
			memcpy(buf, afile, alen); buf[alen] = 0;
			if (bomsh_check_permission(buf, patch_file_pwd, cmd->root, F_OK)) {
				cfile = afile; clen = alen;
			} else {
				cfile = bfile; clen = blen;
			}
		} else {
			memcpy(buf, bfile, blen); buf[blen] = 0;
			if (bomsh_check_permission(buf, patch_file_pwd, cmd->root, F_OK)) {
				cfile = bfile; clen = blen;
			} else {
				cfile = afile; clen = alen;
			}
		}
		char *end = buf;
		if (cfile[0] != '/') {
			// either use absolute path to avoid cmd->pwd mis-use later during record_raw_info()
			// or use the new correct relative path, with patch_file_pwd prefix already.
			end = stpcpy(buf, patch_file_pwd); *(end++) = '/';
		}
		memcpy(end, cfile, clen); end[clen] = 0;
#if 0
		// if afile is /dev/null, then bfile does not exist yet before applying the patch
		if (!bomsh_check_permission(buf, patch_file_pwd, cmd->root, F_OK)) {
			bomsh_log_printf(3, "Warning: the %d-th file to patch does not exist: %s\n", i, buf);
			// free all allocated strings
			for (int j=0; j<i; j++) {
				free(bfiles[j]);
			}
			free(bfiles);
			return 0;
		}
#endif
		bfiles[i] = strdup(buf);
		bomsh_log_printf(8, "selected file to patch: %s\n", buf);
	}
	bfiles[num_files2] = NULL;
	if (files) *files = bfiles;
	bomsh_log_printf(8, "Found %d files to patch\n", num_files2);
	return num_files2;
}

// Parse cmd->argv, and get all files from the command line
static void get_all_subfiles_in_cat_cmdline(bomsh_cmd_data_t *cmd)
{
	int array_size = 10;
	int num_array = 0;
	char **array = malloc(array_size * sizeof(char *));
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already
		if (token[0] == '-') {
			continue;
		}
		bomsh_log_printf(4, "found cat infile: %s\n", token);
		array[num_array++] = strdup(token);
		if (num_array >= array_size) {
			array_size *= 2;
			array = realloc(array, array_size * sizeof(char *));
		}
	}
	array[num_array] = NULL;
	cmd->input_files = array;
	cmd->num_inputs = num_array;
	if (!cmd->output_file && num_array) {
		cmd->output_file = array[0]; // need to set it because record_raw_info checks output_file
	}
}

// Get the -pNUM option value for the patch command
static int get_strip_num_of_patch_command(bomsh_cmd_data_t *cmd)
{
	char *strip_num_str = NULL;
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already
		if (strncmp(token, "-p", 2) == 0) {
			int len = strlen(token);
			if (len > 2) {
				strip_num_str = token + 2;
			} else {
				strip_num_str = *p;
			}
			break;
		}
		if (strcmp(token, "--strip") == 0) {
			strip_num_str = *p;
			break;
		}
		if (strncmp(token, "--strip=", 8) == 0) {
			strip_num_str = token + 8;
			break;
		}
	}
	if (strip_num_str) {
		return atoi(strip_num_str);
	}
	return 0;
}

// Get the "-d dir" option value for the patch command
static char *get_change_dir_of_patch_command(bomsh_cmd_data_t *cmd)
{
	char *change_dir = NULL;
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already
		if (strncmp(token, "-d", 2) == 0) {
			int len = strlen(token);
			if (len > 2) {
				change_dir = token + 2;
			} else {
				change_dir = *p;
			}
			break;
		}
		if (strcmp(token, "--directory") == 0) {
			change_dir = *p;
			break;
		}
		if (strncmp(token, "--directory=", 12) == 0) {
			change_dir = token + 12;
			break;
		}
	}
	return change_dir;
}

// Get the --input=PATCHFILE for the patch command
static char * get_input_patch_file_of_patch_command(bomsh_cmd_data_t *cmd)
{
	char *input_patch = NULL;
	char *token = NULL;
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		token = *p; p++; // p points to next token already
		if (strncmp(token, "-i", 2) == 0) {
			int len = strlen(token);
			if (len > 2) {
				input_patch = token + 2;
			} else {
				input_patch = *p; p++;
			}
			break;
		}
		if (strcmp(token, "--input") == 0) {
			input_patch = *p; p++;
			break;
		}
		if (strncmp(token, "--input=", 8) == 0) {
			input_patch = token + 8;
			break;
		}
	}
	if (input_patch) {
		return input_patch;
	} else { // must be form: patch [options] [originalfile [patchfile]]
		if (token && token[0] != '-') {
			return token; // last token is the patchfile
		}
		return NULL;
	}
}

// Get all infiles from patch files and get hash of all infiles
static void bomsh_prehook_patch_cmd(bomsh_cmd_data_t *patch_cmd)
{
	// list of patch files may not be ready yet for "cat file | patch -p1" case
	if (!patch_cmd->input_files2) return;

	int strip_num = get_strip_num_of_patch_command(patch_cmd);
	bomsh_log_printf(8, "Get strip num of %d for patch cmd\n", strip_num);
	char *change_dir = get_change_dir_of_patch_command(patch_cmd);
	if (change_dir) {
		bomsh_log_printf(8, "Get patch cmd change dir: %s\n", change_dir);
	}

	char **afiles = NULL;
	int array_size = 100;
	int num_array = 0;
	char **array = malloc( array_size * sizeof(char *) );
	char **p = patch_cmd->input_files2; // the list of patch files
	while (*p) {
		char *token = *p; p++;
		char *patch_file = get_real_path(patch_cmd, token);
		// need to get the real path of the patch file to read successfully
		bomsh_log_printf(7, "\nRead patch file: %s real-path: %s\n", token, patch_file);
		int num_files = bomsh_read_patch_file(patch_cmd, patch_file, strip_num, change_dir, &afiles);
		free(patch_file);
		for (int j = 0; j< num_files; j++) {
			array[num_array++] = afiles[j];
			if (num_array >= array_size) {
				array_size *= 2;
				array = realloc(array, num_array * sizeof(char *));
			}
		}
		free(afiles);
	}
	array[num_array] = NULL;
	patch_cmd->num_inputs = num_array;
	patch_cmd->input_files = array;
	if (array) {
		patch_cmd->output_file = array[0];  // need to set it because record_raw_info checks output_file
	}
	// now get hash of all infiles for patch command
	get_hash_of_infiles(patch_cmd);
}

// process the associated cat/patch command in pre-exec mode
static void bomsh_prehook_cat_patch_cmd(bomsh_cmd_data_t *cat_cmd, bomsh_cmd_data_t *patch_cmd)
{
	bomsh_log_printf(8, "\nPrehook the matching cat pid %d and patch pid %d\n", cat_cmd->pid, patch_cmd->pid);
	get_all_subfiles_in_cat_cmdline(cat_cmd);
	patch_cmd->input_files2 = malloc((cat_cmd->num_inputs + 1) * sizeof(char *));
	int i;
	for (i=0; i < cat_cmd->num_inputs; i++) {
		patch_cmd->input_files2[i] = strdup(cat_cmd->input_files[i]);
	}
	patch_cmd->input_files2[i] = NULL;
	patch_cmd->cat_cmd = cat_cmd;  // link cat cmd to the matching patch cmd
	cat_cmd->refcount ++;  // delay the memory free of the cat cmd
	bomsh_log_printf(8, "\nCmd memory refcount++ to %d for cat pid %d\n", cat_cmd->refcount, cat_cmd->pid);
}

// we only support the basic form of "cat 1.patch ... N.patch | patch -p1" command with pipes.
// the list of patch files will be put into cat_cmd->input_files as well as patch_cmd->input_files2
static void bomsh_process_cat_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get stdout for cat command\n");
		char *stdout_file = bomsh_get_stdout_file(cmd->tcp);
		if (!stdout_file || strncmp(stdout_file, "pipe:[", 6) != 0) {
			cmd->skip_record_raw_info = 1;
			return;
		}
		cmd->stdout_file = stdout_file;
		bomsh_cmd_data_t *match_cmd = bomsh_find_match_pipe_cmd(cmd, 0);
		if (match_cmd) {
			bomsh_prehook_cat_patch_cmd(cmd, match_cmd);
			// Now patch files are known, will get infiles from the patch files
			bomsh_prehook_patch_cmd(match_cmd);
		}
		bomsh_add_pipe_cmd(cmd, 1);
		return;
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for cat command after EXECVE syscall\n");
		bomsh_remove_pipe_cmd(cmd, 1);
	}
}

static void bomsh_process_patch_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for patch command\n");
		char *stdin_file = bomsh_get_stdin_file(cmd->tcp);
		cmd->stdin_file = stdin_file;
		if (stdin_file) {
			if (strncmp(stdin_file, "pipe:[", 6) == 0) {
				bomsh_cmd_data_t *match_cmd = bomsh_find_match_pipe_cmd(cmd, 1);
				if (match_cmd) { // link the cat_cmd and patch_cmd
					bomsh_prehook_cat_patch_cmd(match_cmd, cmd);
				}
				bomsh_add_pipe_cmd(cmd, 0);
			} else {
				bomsh_log_printf(8, "non-pipe patch cmd with stdin input %s\n", cmd->stdin_file);
				cmd->input_files2 = alloc_2element_array(cmd->stdin_file);
			}
		} else {
			char *patch_file = get_input_patch_file_of_patch_command(cmd);
			bomsh_log_printf(8, "input patch file is %s from patch cmd\n", patch_file);
			if (!patch_file) {
				cmd->skip_record_raw_info = 1;
				return;
			}
			cmd->input_files2 = alloc_2element_array(patch_file);
		}
		// Now patch files are known, will get infiles from the patch files
		bomsh_prehook_patch_cmd(cmd);
		return;
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for patch command after EXECVE syscall\n");
		if (cmd->stdin_file && strncmp(cmd->stdin_file, "pipe:[", 6) == 0) bomsh_remove_pipe_cmd(cmd, 0);
		bomsh_record_raw_info_for_command(cmd);
	}
}

/******** end of cat/patch command handling routines ********/

/******** objcopy/chrpath, ... command handling routines ********/

// cmdline format: objcopy [options] infile [outfile]
static void get_all_subfiles_in_objcopy_cmdline(bomsh_cmd_data_t *cmd)
{
	char *last_token = NULL;
	char *last2nd_token = NULL;
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		last2nd_token = last_token; last_token = *p; p++;
	}
	if (last2nd_token && (last2nd_token[0] == '-' || strchr(last2nd_token, '=') ||
				!bomsh_is_regular_file(last2nd_token, cmd->pwd, cmd->root))) {
		// the last token must be both input and output file
		cmd->input_files = alloc_2element_array(last_token);
		cmd->num_inputs = 1;
		get_hash_of_infiles(cmd);
		return;
	}
	char *infile = last2nd_token;
	char *outfile = last_token;
	// if infile is not NULL, then it must be regular file since we have checked it earlier
	//if ( ! (outfile && infile && bomsh_is_regular_file(infile, cmd->pwd, cmd->root))) {
	if ( ! (outfile && infile) ) {
		bomsh_log_string(18, "Warning: not valid objcopy command\n");
		cmd->skip_record_raw_info = 1;
		return;
	}
	if (strcmp(infile, outfile) == 0) {
		// outfile is same as infile
		cmd->input_files = alloc_2element_array(last_token);
		cmd->num_inputs = 1;
		get_hash_of_infiles(cmd);
		return;
	}
	// outfile and infile must be different
	cmd->output_file = outfile;
	cmd->input_files = alloc_2element_array(infile);
	cmd->num_inputs = 1;
}

static void bomsh_process_objcopy_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for objcopy command\n");
		get_all_subfiles_in_objcopy_cmdline(cmd);
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for objcopy command after EXECVE syscall\n");
		bomsh_record_raw_info_for_command(cmd);
	}
}

// Parse cmd->argv, and get all files from the command line
// chrpath [ -v | --version ] [ -d | --delete ] [ -r <path> | --replace <path> ] [ -c | --convert ] [ -l | --list ] [ -h | --help ] <program> [ <program> ... ]
static void get_all_subfiles_in_chrpath_cmdline(bomsh_cmd_data_t *cmd)
{
	int array_size = 10;
	int num_array = 0;
	char **array = malloc(array_size * sizeof(char *));
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already
		if (strcmp(token, "-r") == 0 || strcmp(token, "--replace") == 0) {
			p++; // move to next token
			continue;
		}
		if (token[0] == '-') {
			num_array = 0; // discard all the tokens in the array
			continue;
		}
		bomsh_log_printf(4, "found chrpath infile: %s\n", token);
		array[num_array++] = token;
		if (num_array >= array_size) {
			array_size *= 2;
			array = realloc(array, array_size * sizeof(char *));
		}
	}
	if (!num_array) {
		bomsh_log_string(18, "No infiles found for chrpath cmd\n");
		cmd->skip_record_raw_info = 1;
		free(array);
		return;
	}
	for (int i=0; i<num_array; i++) {
		array[i] = strdup(array[i]); // allocate memory
	}
	array[num_array] = NULL;
	cmd->input_files = array;
	cmd->num_inputs = num_array;
	cmd->output_file = array[0]; // need to set it because record_raw_info checks output_file
	// now get hash of all infiles for chrpath command
	get_hash_of_infiles(cmd);
}

static void bomsh_process_chrpath_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for chrpath command\n");
		get_all_subfiles_in_chrpath_cmdline(cmd);
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for chrpath command after EXECVE syscall\n");
		bomsh_record_raw_info2(cmd);
	}
}

// Parse cmd->argv, and get all files from the command line
static void bomsh_get_rustc_subfiles(bomsh_cmd_data_t *cmd)
{
	int num_skip_tokens = sizeof(rustc_skip_token_list)/sizeof(*rustc_skip_token_list);
	char **skip_token_list = (char **)rustc_skip_token_list;
	char *output_file = NULL;
	int subfiles_size = 100;
	int num_subfiles = 0;
	char **subfiles = malloc(subfiles_size * sizeof(char *));

	char *crate_name = NULL;
	char *output_dir = NULL;
	char *crate_prefix = NULL;
	char *crate_suffix = NULL;
	char *extra_filename = NULL;

	char **p = cmd->argv;
	p++; // start with argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already

		// well, we still need to handle this -o option, otherwise, the outfile will be added to infiles
		if (strncmp(token, "-o", 2) == 0) {
			int len = strlen(token);
			if (len > 2) {
				output_file = token + 2;
			} else {
				// p already points to next token, which is output file
				output_file = *p;
				p++; // move to next token
			}
			if (output_file && strcmp(output_file, "/dev/null") == 0) {
				bomsh_log_string(3, "NULL outfile, no need to process rustc command\n");
				cmd->skip_record_raw_info = 1;
				free(subfiles);
				return;
			}
			bomsh_log_printf(4, "found output file %s\n", output_file);
			continue;
		}

		if (bomsh_is_token_inlist(token, skip_token_list, num_skip_tokens)) {
			if (strcmp(token, "--crate-name") == 0) {
				crate_name = *p;
			} else if (strcmp(token, "--out-dir") == 0) {
				output_dir = *p;
			} else if (strcmp(token, "--crate-type") == 0) {
				if (strcmp(*p, "lib") == 0) {
					crate_prefix = (char *)"lib";
					crate_suffix = (char *)".rlib";
				} else if (strcmp(*p, "cdylib") == 0) {
					crate_prefix = (char *)"lib";
					crate_suffix = (char *)".so";
				}
			} else if (strncmp(*p, "extra-filename=", 15) == 0) {
				extra_filename = (*p) + 15;
			}
			p++; // move to next token
			continue;
		}
		if (token[0] == '-') {
			continue;
		}
		bomsh_log_printf(4, "found one rustc subfile: %s\n", token);
		// auto-grow the buffer to hold more subfiles
		if (num_subfiles >= subfiles_size) {
			subfiles_size *= 2;
			subfiles = realloc(subfiles, subfiles_size * sizeof(char *));
		}
		subfiles[num_subfiles++] = token;
	}

	// find out the output_file
	char buf[PATH_MAX];
	if (crate_name) {
		if (!output_dir) {
			output_dir = cmd->pwd;
		}
		strcpy(buf, output_dir); strcat(buf, "/");
		if (crate_prefix) strcat(buf, crate_prefix);
		strcat(buf, crate_name);
		if (extra_filename) strcat(buf, extra_filename);
		if (crate_suffix) strcat(buf, crate_suffix);
		output_file = strdup(buf);
		cmd->flags |= 1; // to indicate that output_file is allocated and needs to be freed
	} else if (num_subfiles == 1 && !output_file) {
		strcpy(buf, subfiles[0]);
		char *dot_pos = strrchr(buf, '.');
		if (strcmp(dot_pos, ".rs") == 0) {
			*dot_pos = 0;
		}
		output_file = strdup(buf);
		cmd->flags |= 1; // to indicate that output_file is allocated and needs to be freed
	}
	/*
	if (output_file) { // well, output_file does not exist yet before EXECVE syscall
		if (!bomsh_is_regular_file(output_file, cmd->pwd, cmd->root)) {
			bomsh_log_printf(4, "not regular file or not-existent outfile: %s\n", output_file);
			if (cmd->flags & 1) free(output_file);
			cmd->skip_record_raw_info = 1;
			return;
		}
	}*/

	int num_infiles = 0;
	// it is sufficient, since #infiles <= #subfiles
	char **infiles = malloc((num_subfiles + 1) * sizeof(char *));
	log_gcc_subfiles(4, subfiles, num_subfiles, "\nList of subfiles:");
	bomsh_log_string(4, "\nChecking rustc subfiles\n");
	for (int i=0; i<num_subfiles; i++) {
		if (!bomsh_is_regular_file(subfiles[i], cmd->pwd, cmd->root)) {
			bomsh_log_printf(4, "not regular file or not-existent subfile: %s\n", subfiles[i]);
			continue;
		}
		infiles[num_infiles++] = strdup(subfiles[i]);
	}
	log_gcc_subfiles(4, infiles, num_infiles, "\nList of infiles:");

	// Save the results in cmd_data struct
	infiles[num_infiles] = NULL;
	cmd->num_inputs = num_infiles;
	cmd->input_files = infiles;
	if (output_file) cmd->output_file = output_file;
	free(subfiles);
}

static void bomsh_process_rustc_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for rustc command\n");
		bomsh_get_rustc_subfiles(cmd);
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for rustc command after EXECVE syscall\n");
		bomsh_record_raw_info(cmd);
	}
}

// cmdline format: sepdebugcrcfix DEBUG_DIR FILEs
static void get_all_subfiles_in_sepdebugcrcfix_cmdline(bomsh_cmd_data_t *cmd)
{
	int argc = cmd->num_argv;
	if (argc < 2) {
		return;
	}
	char **array = malloc( (argc - 1) * sizeof(char *) );
	char **p = &(cmd->argv[2]); // start from argv[2]
	int i;
	for (i=0; i < argc-2; i++, p++) {
		array[i] = strdup(*p);
	}
	array[i] = NULL;
	cmd->num_inputs = i;
	cmd->input_files = array;
	get_hash_of_infiles(cmd);
	cmd->output_file = array[0]; // need to set it because record_raw_info checks output_file
}

static void bomsh_process_sepdebugcrcfix_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for sepdebugcrcfix command\n");
		get_all_subfiles_in_sepdebugcrcfix_cmdline(cmd);
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for sepdebugcrcfix command after EXECVE syscall\n");
		bomsh_record_raw_info2(cmd);
	}
}

static int is_samefile_converter_command(char *name)
{
	int num_tokens = sizeof(samefile_converter_list)/sizeof(*samefile_converter_list);
	if (bomsh_is_token_inlist(name, (char **)samefile_converter_list, num_tokens)) {
		return 1;
	}
	int len = strlen(name);
	return strcmp(name + len - 7, "-ranlib") == 0;
}

// The shell command update single file, like objtool/sorttable/ranlib. the last token is the file to update.
static void get_all_subfiles_in_samefile_converter_cmdline(bomsh_cmd_data_t *cmd)
{
	char *token = NULL;
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		token = *p; p++; // p points to next token already
	}
	if (!token || token[0] == '-') { // cmd like "ranlib" or "ranlib --version"
		cmd->skip_record_raw_info = 1;
		return;
	}
	cmd->output_file = token;
	char **array = alloc_2element_array(token);
	cmd->num_inputs = 1;
	cmd->input_files = array;
	get_hash_of_infiles(cmd);
}

/*
 *  Process the samefile converter command like strip/ranlib, etc.
 *  For example, the below commands in Linux kernel build or rpm build.
 *   ./tools/objtool/objtool orc generate --no-fp --retpoline kernel/fork.o
 *   ./scripts/sortextable vmlinux
 *   ./scripts/sorttable vmlinux
 *   ./tools/bpf/resolve_btfids/resolve_btfids vmlinux
 *   /usr/lib/rpm/debugedit -b /home/OpenOSC/rpmbuild/BUILD/openosc-1.0.5 -d /usr/src/debug/openosc-1.0.5-1.el8.x86_64 -i --build-id-seed=1.0.5-1.el8 -l /home/OpenOSC/rpmbuild/BUILD/openosc-1.0.5/debugsources.list /home/OpenOSC/rpmbuild/BUILDROOT/openosc-1.0.5-1.el8.x86_64/usr/lib64/libopenosc.so.0.0.0
 *   chrpath -r $ORIGIN/.:$ORIGIN/../../lib work/x86_64-linux/curl-native/7.69.1-r0/recipe-sysroot-native/usr/lib/libcurl.so.4.6.0
 */

static void bomsh_process_samefile_converter_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for samefile converter command\n");
		get_all_subfiles_in_samefile_converter_cmdline(cmd);
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for samefile converter command after EXECVE syscall\n");
		bomsh_record_raw_info2(cmd);
	}
}

// cmdline format: Usage: build setup system zoffset.h image
// example: arch/x86/boot/tools/build arch/x86/boot/setup.bin arch/x86/boot/vmlinux.bin arch/x86/boot/zoffset.h arch/x86/boot/bzImage
static void get_all_subfiles_in_bzimage_build_cmdline(bomsh_cmd_data_t *cmd)
{
	int argc = cmd->num_argv;
	if (argc < 5) {
		return;
	}
	cmd->output_file = cmd->argv[4];
	char **array = malloc( (argc - 1) * sizeof(char *) );
	char **p = &(cmd->argv[1]); // start from argv[1]
	int i;
	for (i=0; i < argc-2; i++, p++) {
		array[i] = strdup(*p);
	}
	array[i] = NULL;
	cmd->num_inputs = i;
	cmd->input_files = array;
}

// Process the bzImage build command in Linux kernel build.
static void bomsh_process_bzimage_build_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for bzimage-build command\n");
		get_all_subfiles_in_bzimage_build_cmdline(cmd);
	} else {
		if (cmd->skip_record_raw_info) return;
		bomsh_log_string(3, "\nrecord raw_info for bzimage-build command after EXECVE syscall\n");
		bomsh_record_raw_info(cmd);
	}
}

static int is_rpmsign_command(bomsh_cmd_data_t *cmd, char *name)
{
	if (strcmp(name, "rpmsign") == 0) {
		return 1;
	}
	if (strcmp(name, "rpm") != 0) {
		return 0;
	}
	char **p = cmd->argv;
	p++; // start from argv[1]
	while (*p) {
		char *token = *p; p++; // p points to next token already
		if (strcmp(token, "--addsign") == 0 || strcmp(token, "--delsign") == 0
				|| strcmp(token, "--resign") == 0) {
			return 1;
		}
	}
	return 0;
}

/******** end of objcopy/chrpath, ... command handling routines ********/

/******** dpkg-deb command handling routines ********/

#include <dirent.h>

// find all regular files in a directory ADIR.
// FILELIST must be allocated with some initial size of LIST_SIZE, and
// NUM_FILES must keep track of the number of found files.
static void find_all_files_in_dir(char *adir, char ***filelist, int *list_size, int *num_files)
{
	char path[1000];
	struct dirent *dp;
	DIR *dir = opendir(adir);
	while ((dp = readdir(dir)) != NULL) {
		if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
			sprintf(path, "%s/%s", adir, dp->d_name);
			if(dp->d_type == DT_DIR) { // a directory, recursively find files
				find_all_files_in_dir(path, filelist, list_size, num_files);
			} else if (dp->d_type == DT_REG) { // a regular file, save it to file list
				char **afiles = *filelist;
				afiles[*num_files] = strdup(path);
				(*num_files) ++;
				if (*num_files >= *list_size) { // auto grow memory if necessary
					(*list_size) *= 2;
					*filelist = realloc(*filelist, (*list_size) * sizeof(char *));
				}
			} // other entries, like symbolic files are ignored
		}
	}
	closedir(dir);
}

// read the control file and extract (name, version, arch) info
static void read_name_ver_arch_from_deb_control(char *control_file, char **name, char **version, char **arch)
{
	char *content = bomsh_read_file(control_file, NULL);
	bomsh_log_printf(22, "\nReading DEBIAN control_file: %s the whole control_str:\n%s\n", control_file, content);
	if (!content) return;

	char delim[] = "\n";
	char *p = NULL;
	char *ptr = strtok(content, delim);
	while(ptr != NULL)
	{
		if (strncmp(ptr, "Package:", strlen("Package:")) == 0) {
			p = strrchr(ptr, ' ');
			if (p && name) {
				*name = strdup(p+1);
			}
		} else if (strncmp(ptr, "Version:", strlen("Version:")) == 0) {
			p = strrchr(ptr, ' ');
			if (p && version) {
				*version = strdup(p+1);
			}
		} else if (strncmp(ptr, "Architecture:", strlen("Architecture:")) == 0) {
			p = strrchr(ptr, ' ');
			if (p && arch) {
				*arch = strdup(p+1);
			}
		}
		ptr = strtok(NULL, delim);
	}
	free(content);
}

// cmdline format: dpkg-deb -b binary-directory [archive|directory]
// example: dpkg-deb --build debian/openosc ..
// Only the simple "dpkg-deb --build debian/openosc" or "dpkg-deb -b debian/openosc .." format is supported.
static void get_all_subfiles_in_dpkg_deb_cmdline(bomsh_cmd_data_t *cmd)
{
	int found_build_opt = 0;
	int new_token_num = 0;
	char *debdir = NULL; // the debian directory which contains all the input files
	char *output = NULL; // either the output archive file or the output directory
	char **p = cmd->argv; p++; // start from argv[1]
	while (*p) { // Parse argv to find the build option and the debian-dir
		char *token = *p; p++;
		if (strcmp(token, "-b") == 0 || strcmp(token, "--build") == 0) {
			found_build_opt = 1;
		} else if (token[0] != '-') {
			new_token_num++;
			if (new_token_num == 1) {
				debdir = token;
			} else if (new_token_num == 2) {
				output = token;
			}
		}
	}
	if (!found_build_opt || !debdir) { // not dpkg-deb build command, do nothing
		return;
	}

	char buf[PATH_MAX];
	// the debian control file is located at the fixed location inside debdir
	strcpy(buf, debdir);
	strcat(buf, "/DEBIAN/control");
	if (!bomsh_check_permission(buf, cmd->pwd, cmd->root, F_OK)) {
		bomsh_log_printf(8, " For dpkg-deb, not-existent debian control file: %s\n", buf);
		return;
	}
	if (!output) { // this is "dpkg-deb --build debian/openosc" cmd
		// the ouput archive is debdir.deb
		strcpy(buf, debdir);
		strcat(buf, ".deb");
		// should we check existence of output_file? No, since it does not exist yet in pre-exec mode
		cmd->output_file = strdup(buf);
	} else { // this is "dpkg-deb -b debian/openosc .." cmd
		if (bomsh_is_regular_file(output, cmd->pwd, cmd->root)) { // this is a file, then it will be the output archive
			cmd->output_file = strdup(output);
		} else { // this is a dir, then it will be dir/name_version_arch.deb output archive
			char buf2[PATH_MAX];
			char *control_file = get_real_path2(cmd, buf, buf2);
			char *name = NULL;
			char *version = NULL;
			char *arch = NULL;
			read_name_ver_arch_from_deb_control(control_file, &name, &version, &arch);
			if (!(name && version && arch)) {
				// not well-formated control file, ignore it
				bomsh_log_printf(7, "Warning: failed to read (name, version, arch) from control file: %s\n", buf);
				return;
			}
			// output_file = os.path.join(output_file, name + "_" + version + "_" + arch + ".deb")
			sprintf(buf, "%s/%s_%s_%s.deb", output, name, version, arch);
			cmd->output_file = strdup(buf);
			free(name); free(version); free(arch);
		}
	}

	// Find all the input files from debian directory
	int array_num = 0;
	int array_size = 100;
	char **array = malloc( array_size * sizeof(char *) );
	char *adir = get_real_path2(cmd, debdir, buf);
	find_all_files_in_dir(adir, &array, &array_size, &array_num);
	cmd->num_inputs = array_num;
	array[array_num] = NULL;
	cmd->input_files = array;
	cmd->flags = 1; // to indicate that output_file is allocated and needs to be freed
}

// Process the debian package build command
static void bomsh_process_dpkg_deb_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (pre_exec_mode) {
		bomsh_log_string(3, "\npre-exec mode, get subfiles for dpkg_deb command\n");
		get_all_subfiles_in_dpkg_deb_cmdline(cmd);
	} else {
		if (cmd->skip_record_raw_info == 1) return;
		bomsh_log_string(3, "\nrecord raw_info for dpkg_deb command after EXECVE syscall\n");
		bomsh_record_raw_info(cmd);
	}
}

/******** end of dpkg-deb command handling routines ********/

/******** top level command handling routines ********/

// main routine to handle all recorded shell commands.
// if pre_exec_mode is 1, it means before the EXECVE syscall
// if pre_exec_mode is 0, it means after  the EXECVE syscall
static void bomsh_process_shell_command(bomsh_cmd_data_t *cmd, int pre_exec_mode)
{
	if (g_bomsh_config.trace_execve_cmd_only == 2) {
		bomsh_log_printf(2, "\n*** Tracing only, pre_exec: %d PID %d shell command: %s\n", pre_exec_mode, cmd->pid, cmd->path);
		return;
	}

	// cmd->path can be relative, like "scripts/sign-file" or "./scripts/sorttable" during kernel build
	char *prog = cmd->path;
	char *name = bomsh_basename(prog);
	bomsh_log_printf(8, "\n*** Processing pre_exec: %d PID %d shell command: %s\n", pre_exec_mode, cmd->pid, prog);

	if (is_cc_compiler(name)) {
		bomsh_process_gcc_command(cmd, pre_exec_mode);
	} else if (is_cc_linker(name)) {
		bomsh_process_ld_command(cmd, pre_exec_mode);
	} else if (strcmp(name, "as") == 0) {
		if (g_bomsh_config.handle_gnu_as_cmd) {
			bomsh_process_as_command(cmd, pre_exec_mode);
		} else {
			bomsh_log_printf(15, "\nNot-supported shell command: %s\n", prog);
		}
	} else if (bomsh_endswith(name, "objcopy", '-')) {
		bomsh_process_objcopy_command(cmd, pre_exec_mode);
	} else if (is_ar_command(name)) {
		bomsh_process_ar_command(cmd, pre_exec_mode);
	} else if (is_strip_command(name)) {
		bomsh_process_strip_like_command(cmd, pre_exec_mode, 0);
	} else if (is_eu_strip_command(name)) {
		bomsh_process_strip_like_command(cmd, pre_exec_mode, 1);
	} else if (strcmp(name, "cat") == 0) {
		bomsh_process_cat_command(cmd, pre_exec_mode);
	} else if (strcmp(name, "patch") == 0) {
		bomsh_process_patch_command(cmd, pre_exec_mode);
	} else if (is_samefile_converter_command(name)) {
		bomsh_process_samefile_converter_command(cmd, pre_exec_mode);
	} else if (strcmp(name, "dwz") == 0) {
		bomsh_process_strip_like_command(cmd, pre_exec_mode, 2);
	} else if (strcmp(name, "sepdebugcrcfix") == 0) {
		bomsh_process_sepdebugcrcfix_command(cmd, pre_exec_mode);
	} else if (strcmp(name, "dpkg-deb") == 0) {
		if (g_bomsh_config.handle_pkg_build_cmd) {
			bomsh_process_dpkg_deb_command(cmd, pre_exec_mode);
		} else {
			bomsh_log_printf(15, "\nNot-supported shell command: %s\n", prog);
		}
	} else if (strcmp(prog, "arch/x86/boot/tools/build") == 0) {
		bomsh_process_bzimage_build_command(cmd, pre_exec_mode);
	} else if (is_rpmsign_command(cmd, name)) {
		bomsh_process_strip_like_command(cmd, pre_exec_mode, 3);
	} else if (strcmp(name, "chrpath") == 0) {
		bomsh_process_chrpath_command(cmd, pre_exec_mode);
	} else if (strcmp(name, "rustc") == 0) {
		bomsh_process_rustc_command(cmd, pre_exec_mode);
	} else {
		bomsh_log_printf(15, "\nNot-supported shell command: %s\n", prog);
	}
}

// hook the program in pre-exec mode, that is, before the execve syscall
static void bomsh_prehook_program(bomsh_cmd_data_t *cmd)
{
	bomsh_log_printf(4, "\n---start prehook pid %d befor EXECVE syscall", cmd->pid);
	bomsh_log_cmd_data(cmd, 6);
	if (bomsh_verbose > 50) bomsh_dump_pid_memory_maps(cmd->pid);
	bomsh_process_shell_command(cmd, 1);
	bomsh_log_cmd_data(cmd, 5);
	bomsh_log_printf(4, "\n----done prehook pid %d befor execve syscall\n", cmd->pid);
}

// invoked after the execve syscall and after it
void bomsh_hook_program(int pid, int status)
{
	if (g_bomsh_config.trace_execve_cmd_only == 1) {
		bomsh_log_printf(2, "\n====Tracing only, hook_program   pid %d after  EXECVE syscall status: %d", pid, status);
		return;
	}
	bomsh_log_printf(3, "\n====hook_program pid %d after EXECVE syscall status: %d", pid, status);
	bomsh_cmd_data_t *cmd = bomsh_remove_cmd(pid);
	if (!cmd) {
		bomsh_log_printf(3, "\n===No pid %d cmd_data found\n", pid);
		return;
	}
	if (status && (cmd->flags & 2)) { // non-zero status and this cmd is instrumented
		bomsh_log_printf(8, "\nWarning: non-zero exit status %d %d for instrumented PID %d prog: %s\n", status>>8, status, pid, cmd->path);
	}
	bomsh_log_cmd_data(cmd, 4);
	bomsh_process_shell_command(cmd, 0);
	bomsh_free_cmd(cmd);
	bomsh_log_printf(3, "\n====hook_program deleting pid %d cmd, DONE==\n", pid);
}

void bomsh_hook_init(void)
{
	bomsh_token_init();
	if (!bomsh_cmds) {
		bomsh_cmds = (bomsh_cmd_data_t **)malloc(BOMSH_CMDS_SIZE * sizeof(char *));
		memset(bomsh_cmds, 0, BOMSH_CMDS_SIZE * sizeof(char *));
	}
}

