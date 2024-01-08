#! /usr/bin/env python3
# Copyright (c) 2023 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Bomsh script to analyze and show pstree for strace %process log file.
The strace logfile should be generated with below command:
    strace -f -e trace=%process -qqq -o strace.log your-build-cmd
    Or with larger string size:
    strace -s9999 -f -e trace=%process -qqq -o strace.log your-build-cmd

April 2023, Yongkui Han
"""

import argparse
import sys
import os
import json

TOOL_VERSION = '0.0.1'
VERSION = '%(prog)s ' + TOOL_VERSION

LEVEL_0 = 0
LEVEL_1 = 1
LEVEL_2 = 2
LEVEL_3 = 3
LEVEL_4 = 4

args = None
g_indent_per_level = 4
g_pid_progs = {}
g_pid_argvs = {}
g_clone_fork_syscall_seen = False
# the {pid => list of PID@LINENO} mappings
g_pid_lineno = {}


#
# Helper routines
#########################
def verbose(string, level=1, logfile=None):
    """
    Prints information to stdout depending on the verbose level.
    :param string: String to be printed
    :param level: Unsigned Integer, listing the verbose level
    :param logfile: file to write, if not provided, g_logfile is used
    """
    if args.verbose >= level:
        '''
        afile = g_logfile
        if logfile:
            afile = logfile
        if afile:
            append_text_file(afile, string + "\n")
        '''
        # also print to stdout
        print(string)


def save_json_db(db_file, db, indentation=4):
    """ Save the dictionary data to a JSON file

    :param db_file: the JSON database file
    :param db: the python dict struct
    :returns None
    """
    if not db:
        return
    print ("save_json_db: db file is " + db_file)
    try:
        f = open(db_file, 'w')
    except IOError as e:
        print ("I/O error({0}): {1}".format(e.errno, e.strerror))
        print ("Error in save_json_db, skipping it.")
    else:
        with f:
            json.dump(db, f, indent=indentation, sort_keys=True)


def get_or_create_dir(destdir):
    """
    Create a directory if it does not exist. otherwise, return it directly
    return absolute path of destdir
    """
    if destdir and os.path.exists(destdir):
        return os.path.abspath(destdir)
    os.makedirs(destdir)
    return os.path.abspath(destdir)


def get_pid_from_strace_logfile_line(line):
    """
    Get the PID of a line from the strace log file

    :param line: a line from the strace log file
    returns pid
    """
    tokens = line.split()
    return tokens[0]


def get_argv_from_execve_line(line):
    """
    Get the argv of an execve line from the strace log file.
    The argv array can be like:
    ["cc", "-L/usr/lib/gcc/x86_64-redhat-lin"..., "hostname.o", "-z", "relro", ...],

    :param line: a line from the strace log file
    returns the argv command string
    """
    pos1 = line.find('", ["')
    if pos1 < 0:
        return ''
    pos2 = line.find('], ')
    if pos2 < 0:
        return ''
    tokens = line[pos1+4 : pos2].strip('"').split(', ')
    new_tokens = []
    for token in tokens:
        if token[-3:] == '...':
            token2 = token[:-4].strip('"') + '...'
        else:
            token2 = token.strip('"')
        new_tokens.append(token2)
    return ' '.join(new_tokens)


def process_strace_logfile_line(line):
    """
    Process a line from the strace process log file

    :param line: a line from the strace log file
    returns (pid, child_pid, prog, argv)
    """
    global g_clone_fork_syscall_seen
    child_pid = ''
    tokens = line.split()
    pid = tokens[0]
    token1 = tokens[1]
    argv = ''
    if token1.startswith('execve("'):  # execve call
        prog = token1[8:-2]
        if args.use_command_as_key:
            argv = get_argv_from_execve_line(line)
        return (pid, '', prog, argv)
    elif token1.startswith('clone') or (token1 == "<..." and tokens[2] == "clone"):  # clone call
        if tokens[-2] == "=":
            child_pid = tokens[-1]
            g_clone_fork_syscall_seen = True
    elif token1.startswith('vfork') or (token1 == "<..." and tokens[2] == "vfork"):  # vfork call
        if tokens[-2] == "=" and tokens[-1] != '0':
            child_pid = tokens[-1]
            g_clone_fork_syscall_seen = True
    elif args.sig_chld and token1 == "---" and tokens[2] == "SIGCHLD":  # child process exit
        # if there are clone/vfork syscalls, then no need to parse SIGCHLD line
        for token in tokens[3:]:
            if token.startswith("si_pid="):  # child pid
                child_pid = token[7:-1]
                break
    return (pid, child_pid, '', argv)


def get_latest_pid(d_pid, pid):
    """
    Get the latest PID@LINENO from d_pid dict.

    :param d_pid: the dict to search
    :param pid: the PID, which is the key of the dict
    returns the latest PID@LINENO from d_pid dict. If not in d_pid, returns empty string.
    """
    if pid not in d_pid:
        return ''
    return d_pid[pid][-1]


def get_closest_pid(d_pid, pid, lineno):
    """
    Get the closest PID@LINENO from d_pid dict.

    :param d_pid: the dict to search
    :param pid: the PID, which is the key of the dict
    :param lineno: the line number in the strace log file
    returns the matched PID@LINE, otherwise, return emptry string
    """
    closest_pid = ''
    if pid not in d_pid:
        return closest_pid
    pid_values = d_pid[pid]
    for value in pid_values:
        orig_pid, line = value.split("@")
        diff = int(lineno) - int(line)
        if diff < 0:  # this pid_line must be the next wrap-around PID already.
            # the previous pid_line must be the closest
            return closest_pid
        closest_pid = value
    return closest_pid


def try_add_pid_to_pid_lineno_list(d_pid, pid, lineno):
    """
    Try to add a new pid seen on a new line to the PID list.
    The first line to see this PID is appended as PID@LINENO, and added to the list.

    :param d_pid: the dict to update
    :param pid: the PID, which is the key of the dict
    :param lineno: the line number in the strace log file
    returns the latest PID@LINENO, otherwise, return the new added PID@LINENO value.
    """
    if not pid or pid[0] == '?':
        return pid
    pid_value = pid + "@" + str(lineno)
    if pid not in d_pid:  # must be the first time to see this PID
        d_pid[pid] = [pid_value, ]
        return pid_value
    # this PID has been seen, must be the last pid_line added.
    return get_latest_pid(d_pid, pid)


def add_pid_to_pid_lineno_list(d_pid, pid, lineno):
    """
    Add a new pid_value to the PID list.

    :param d_pid: the dict to update
    :param pid: the original PID, which is the key of the dict
    :param pid_value: the PID value to add to the list, which is usually PID@LINENO format
    """
    pid_value = pid + "@" + str(lineno)
    if pid in d_pid:
        d_pid[pid].append(pid_value)
    else:
        d_pid[pid] = [pid_value, ]
    return pid_value


def read_strace_logfile(strace_logfile):
    """
    Read and process the recorded strace info from strace logfile

    :param strace_logfile: the log file that contains the strace recorded info
    returns the pid_parents dict of {pid => its-pid-parent}
    also it updates the global g_pid_progs dict of {pid => program-path}
    """
    verbose("==== Reading and processing strace logfile: " + strace_logfile, LEVEL_1)
    pid_parents = {}
    lineno = 0
    with open(strace_logfile, 'r') as f:
        for line in f:
            lineno += 1
            if " = -1 ENO" in line or not (' execve("' in line or ' clone' in line or
                    ' vfork' in line or (args.sig_chld and " --- SIGCHLD " in line)):
                continue
            pid, child_pid, prog, argv = process_strace_logfile_line(line)
            #print(line)
            #print("line " + str(lineno) + " (pid, child_pid, prog, argv) = " + str((pid, child_pid, prog, argv)))
            if args.not_use_pid_at_line:
                parent_pid_line = pid
                child_pid_line = child_pid
            else:
                # always try to add the parent and child PID to g_pid_lineno dict
                # this makes sure that a PID is recorded at the first line it is seen
                parent_pid_line = try_add_pid_to_pid_lineno_list(g_pid_lineno, pid, lineno)
                child_pid_line = try_add_pid_to_pid_lineno_list(g_pid_lineno, child_pid, lineno)
            if child_pid_line and child_pid_line[0] != '?':
                if child_pid_line in pid_parents and pid_parents[child_pid_line] and pid_parents[child_pid_line] != parent_pid_line:
                    verbose("Info at line " + str(lineno) + " this child PID " + child_pid +
                            " already has a different old parent " + pid_parents[child_pid_line] +
                            " and now a new parent " + parent_pid_line, LEVEL_3)
                    # this must be a new PID@LINE, which is due to PID wrap-around or recycling.
                    child_pid_line = add_pid_to_pid_lineno_list(g_pid_lineno, child_pid, lineno)
                if child_pid_line not in pid_parents or not pid_parents[child_pid_line]:
                    pid_parents[child_pid_line] = parent_pid_line
            if parent_pid_line not in pid_parents:
                # These are top-level PIDs, or later found to be child PIDs (then whose parent PID is updated later).
                pid_parents[parent_pid_line] = 0
            if prog:
                g_pid_progs[parent_pid_line] = prog
            if argv:
                g_pid_argvs[parent_pid_line] = argv
    if not g_clone_fork_syscall_seen:
        verbose("Warning: no clone/fork syscall in the strace logfile, your pstree may be inaccurate: some PIDs may not find its parent PID", LEVEL_0)
    verbose("There are " + str(len(pid_parents)) + " PIDs totally", LEVEL_1)
    verbose("There are " + str(len(g_pid_progs)) + " PIDs with non-empty program", LEVEL_1)
    verbose("There are " + str(len(pid_parents) - len(g_pid_progs)) + " PIDs with empty program", LEVEL_1)
    return pid_parents


def indent_strace_logfile(strace_logfile, pid_depth, output_file=''):
    """
    Read and indent the recorded strace lines of strace logfile

    :param strace_logfile: the log file that contains the strace recorded info
    :param pid_depth: {pid => depth} dict
    """
    verbose("==== Reading logfile " + strace_logfile + " and generating the indented strace lines ====", LEVEL_1)
    outf = ''
    if output_file:
        verbose("save the indented strace logfile to: " + output_file, LEVEL_0)
        outf = open(output_file, 'w')
    else:
        verbose("Below is the indented strace lines:\n", LEVEL_0)
    lineno = 0
    with open(strace_logfile, 'r') as f:
        for line in f:
            lineno += 1
            if not args.indent_all_strace_lines and (" = -1 ENO" in line or " execve" not in line):
                continue
            pid = get_pid_from_strace_logfile_line(line)
            if args.not_use_pid_at_line:
                pid_line = pid
            else:  # need to convert to closest pid_line
                pid_line = get_closest_pid(g_pid_lineno, pid, lineno)
            if pid_line in pid_depth:
                depth = pid_depth[pid_line]
            else:  # can only assume this is a topmost PID
                depth = 0
            if outf:
                outf.write(depth * g_indent_per_level * ' ' + line)
            else:
                print(depth * g_indent_per_level * ' ' + line, end='')
    if outf:
        outf.close()


def get_pid_children(pid_parents):
    """
    Get the children of each PID from the pid_parents dict.

    :param pid_parents: {pid => its-parent-pid} dict
    returns the pid_children dict
    """
    pid_children = {}
    for pid in pid_parents:
        parent_pid = pid_parents[pid]
        if pid not in pid_children:
            pid_children[pid] = []
        if parent_pid in pid_children:
            pid_children[parent_pid].append(pid)
        elif parent_pid:
            pid_children[parent_pid] = [pid,]
    verbose("There are " + str(len(pid_children)) + " PIDs in the pid_children dict", LEVEL_1)
    return pid_children


def get_pid_key_for_pstree(pid):
    """
    Get the pid key used for the pid_pstree dict.

    :param pid: the PID
    returns the pid_key string
    """
    pid_key = pid
    if args.use_command_as_key:
        if pid in g_pid_argvs:
            pid_key = pid + ' ' + g_pid_argvs[pid]
    else:
        if pid in g_pid_progs:
            pid_key = pid + ' ' + g_pid_progs[pid]
    return pid_key


def assign_pid_depth(pid_depth, pid_children, root):
    """
    Assign depth value for each child PID of root PID.
    It also creates the pid_pstree dict for the root PID

    :param pid_parents: {pid => its-parent-pid} dict
    returns the pid_pstree dict of {pid_prg => its_children_pstree}
    """
    ret = {}
    depth = pid_depth[root]
    for pid in pid_children[root]:
        pid_depth[pid] = depth + 1
        pid_key = get_pid_key_for_pstree(pid)
        ret[pid_key] = assign_pid_depth(pid_depth, pid_children, pid)
    return ret


def assign_pid_depths(pid_parents, pid_children):
    """
    Assign depth values for all PIDs: topmost PID depth is 0.
    It also creates the pid_pstree dict for all the PIDs

    :param pid_parents: {pid => its-parent-pid} dict
    returns the pid_depth dict of {pid => its_depth}
        and the pid_pstree dict of {pid_prog => its_children_pstree}
    """
    pid_pstree = {}
    pid_depth = {}
    top_pids = [pid for pid in pid_parents if pid_parents[pid] == 0]
    verbose("There are " + str(len(top_pids)) + " topmost PIDs", LEVEL_1)
    for pid in top_pids:
        # topmost level PID's depth is 0, whose children is 1, and so on
        pid_depth[pid] = 0
        pid_key = get_pid_key_for_pstree(pid)
        pid_pstree[pid_key] = assign_pid_depth(pid_depth, pid_children, pid)
    max_depth = max(pid_depth.values())
    verbose("Max depth is " + str(max_depth) + " for all PIDs", LEVEL_1)
    verbose("There are " + str(len(pid_depth)) + " PIDs in the pid_depth struct", LEVEL_1)
    #verbose("The diff between pid_children and pid_parents is: " + str(pid_parents.keys() - pid_children.keys()), LEVEL_1)
    #verbose("The diff between pid_depth and pid_parents is: " + str(pid_parents.keys() - pid_depth.keys()), LEVEL_1)
    return (pid_depth, pid_pstree)


############################################################
#### End of hash/checksum routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool reads strace logfile and show its pstree")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-s', '--strace_logfile',
                    help = "the strace logfile to read")
    parser.add_argument('-i', '--indentation',
                    help = "how many space characters of indentation for each level deeper, the default is 4")
    parser.add_argument('-o', '--output_dir',
                    help = "the output directory for various JSON files and indented strace logfile")
    parser.add_argument("--sig_chld",
                    action = "store_true",
                    help = "handle SIGCHLD lines in strace logfile")
    parser.add_argument("-n", "--not_use_pid_at_line",
                    action = "store_true",
                    help = "do not use pid@line as key, which will not support PID wrap_around/recycling")
    parser.add_argument("-u", "--use_command_as_key",
                    action = "store_true",
                    help = "use command instead of program-binary as key for pstree")
    parser.add_argument("-a", "--indent_all_strace_lines",
                    action = "store_true",
                    help = "indent all lines in the strace logfile, the default is to indent execve lines only")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not (args.strace_logfile):
        print ("Please specify the strace logfile with -f option!")
        print ("")
        parser.print_help()
        sys.exit()

    global g_indent_per_level
    if args.indentation:
        g_indent_per_level = int(args.indentation)

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    pid_parents = read_strace_logfile(args.strace_logfile)
    pid_children = get_pid_children(pid_parents)
    pid_depth, pid_pstree = assign_pid_depths(pid_parents, pid_children)
    if args.output_dir:
        output_dir = get_or_create_dir(args.output_dir)
        save_json_db(os.path.join(output_dir, "bomsh_pid_programs.json"), g_pid_progs)
        save_json_db(os.path.join(output_dir, "bomsh_pid_commands.json"), g_pid_argvs)
        save_json_db(os.path.join(output_dir, "bomsh_pid_parents.json"), pid_parents)
        save_json_db(os.path.join(output_dir, "bomsh_pid_lineno.json"), g_pid_lineno)
        save_json_db(os.path.join(output_dir, "bomsh_pid_children.json"), pid_children)
        save_json_db(os.path.join(output_dir, "bomsh_pid_depth.json"), pid_depth)
        save_json_db(os.path.join(output_dir, "bomsh_pid_pstree.json"), pid_pstree)
        output_file = os.path.join(output_dir, "bomsh_pstree_indented_strace_log")
        indent_strace_logfile(args.strace_logfile, pid_depth, output_file)
        return

    verbose("pid_programs:\n" + json.dumps(g_pid_progs, indent=4, sort_keys=True), LEVEL_2)
    verbose("pid_commands:\n" + json.dumps(g_pid_argvs, indent=4, sort_keys=True), LEVEL_2)
    verbose("pid_parents:\n" + json.dumps(pid_parents, indent=4, sort_keys=True), LEVEL_2)
    verbose("pid_lineno:\n" + json.dumps(g_pid_lineno, indent=4, sort_keys=True), LEVEL_2)
    verbose("pid_children:\n" + json.dumps(pid_children, indent=4, sort_keys=True), LEVEL_2)
    verbose("pid_depth:\n" + json.dumps(pid_depth, indent=4, sort_keys=True), LEVEL_2)
    verbose("pid_pstree:\n" + json.dumps(pid_pstree, indent=4, sort_keys=True), LEVEL_2)
    indent_strace_logfile(args.strace_logfile, pid_depth)


if __name__ == '__main__':
    main()
