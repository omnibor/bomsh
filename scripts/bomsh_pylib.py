#! /usr/bin/env python3
# Copyright (c) 2022 Cisco and/or its affiliates.
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
Bomsh script to create raw_logfile of runtime-dependency fragments for Python scripts.
Other Bomsh scripts can then generate snapshot OmniBOR artifact trees based on raw_logfile.
It also creates snapshot runtime-dependency trees for Python scripts as its JSON output.

September 2023, Yongkui Han
"""

import argparse
import sys
import os
import subprocess
import json
import ast
import importlib

# for special filename handling with shell
try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote

TOOL_VERSION = '0.0.1'
VERSION = '%(prog)s ' + TOOL_VERSION

LEVEL_0 = 0
LEVEL_1 = 1
LEVEL_2 = 2
LEVEL_3 = 3
LEVEL_4 = 4
LEVEL_5 = 5

args = None
g_tmpdir = "/tmp"
g_jsonfile = "/tmp/bomsh_pylib_jsonfile"
g_raw_logfile = "/tmp/bomsh_pylib_raw_logfile"
g_hashtypes = []

#
# Helper routines
#########################
def verbose(string, level=1, logfile=None):
    """
    Prints information to stdout depending on the verbose level.
    :param string: String to be printed
    :param level: Unsigned Integer, listing the verbose level
    :param logfile: file to write
    """
    if args.verbose >= level:
        if logfile:
            append_text_file(logfile, string + "\n")
        # also print to stdout
        print(string)


def get_or_create_dir(destdir):
    """
    Create a directory if it does not exist. otherwise, return it directly
    return absolute path of destdir
    """
    if destdir and os.path.exists(destdir):
        return os.path.abspath(destdir)
    os.makedirs(destdir)
    return os.path.abspath(destdir)


def write_text_file(afile, text):
    '''
    Write a string to a text file.

    :param afile: the text file to write
    '''
    with open(afile, 'w') as f:
         return f.write(text)


def append_text_file(afile, text):
    '''
    Append a string to a text file.

    :param afile: the text file to write
    '''
    with open(afile, 'a+') as f:
         return f.write(text)


def read_text_file(afile):
    '''
    Read a text file as a string.

    :param afile: the text file to read
    '''
    with open(afile, 'r', encoding="utf-8", errors='ignore') as f:
         return (f.read())


def get_shell_cmd_output(cmd):
    """
    Returns the output of the shell command "cmd".

    :param cmd: the shell command to execute
    """
    #print (cmd)
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    return output


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


def find_all_suffix_files(builddir, suffix):
    """
    Find all files with the specified suffix in the build dir.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :param suffix: the suffix of files to find
    :returns a list that contains all the file names with the suffix.
    """
    print ("entering find_all_suffix_files: the build dir is " + builddir)
    if builddir[0] != "/":
        builddir = os.path.abspath(builddir)
    findcmd = "find " + cmd_quote(builddir) + ' -type f -name "*' + suffix + '" -print || true'
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    return files


def get_empty_init_py_hash(afile, hash_alg="sha1", use_cache=True):
    '''
    Get the hash value for an empty __init__.py file, which represents a Python package.
    Instead of using the empty __init__.py file, all .py files under the dirpath are
    sorted and concatenated to a temporary file, and then calculate the hash.
    :param afile: the __init__.py file to calculate the git hash or digest.
    :param hash_alg: the hashing algorithm, either SHA1 or SHA256
    '''
    pyfiles = []
    dirname = os.path.dirname(afile)
    for dirpath, dirs, files in os.walk(dirname):
        for f in files:
            if os.path.basename(f).endswith(".py"):
                pyfiles.append(f)
        break
    # Concatenate all pyfiles to a tmp file and calculate its hash
    outfile = os.path.join(g_tmpdir, "bomsh_pylib_initpy_concat")
    with open(outfile, 'w') as outf:
        for pyfile in sorted(pyfiles):
            outf.write(read_text_file(os.path.join(dirpath, pyfile)))
    ahash = get_file_hash(outfile, hash_alg, False)
    os.remove(outfile)
    return ahash


# a dict to cache the computed hash of files
g_git_file_hash_cache = {}

def get_file_hash(afile, hash_alg="sha1", use_cache=True):
    '''
    Get the git object hash value of a file.
    :param afile: the file to calculate the git hash or digest.
    :param hash_alg: the hashing algorithm, either SHA1 or SHA256
    '''
    if use_cache:
        afile_key = afile + "." + hash_alg
        if afile_key in g_git_file_hash_cache:
            return g_git_file_hash_cache[afile_key]
    if os.path.basename(afile) == "__init__.py" and os.path.getsize(afile) < 100:
        # special handling for an empty __init__.py file, use 100 as the threshold
        return get_empty_init_py_hash(afile, hash_alg, use_cache)
    if hash_alg == "sha256":
        cmd = 'printf "blob $(wc -c < ' + afile + ')\\0" | cat - ' + afile + ' 2>/dev/null | sha256sum | head --bytes=-4 || true'
    else:
        cmd = 'git hash-object ' + cmd_quote(afile) + ' 2>/dev/null || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd).strip()
    #verbose("output of get_file_hash:\n" + output, LEVEL_3)
    if output:
        if use_cache:
            g_git_file_hash_cache[afile_key] = output
        return output
    return ''

############################################################
#### End of helper routines ####
############################################################

def create_dependency_fragment(afile, depfiles, hash_alg='sha1'):
    '''
    Create the dependency fragment to write to raw_logfile for a specific outfile.
    :param afile: the out file that depends on depfiles
    :param depfiles: a list of dependency files
    :param hash_alg: either sha1 or sha256
    returns a string for the dependency fragment.
    '''
    lines = []
    checksum = get_file_hash(afile, hash_alg)
    lines.append("outfile: " + checksum + " path: " + afile)
    for depfile in depfiles:
        checksum = get_file_hash(depfile, hash_alg)
        lines.append("infile: " + checksum + " path: " + depfile)
    lines.append("build_cmd: bomsh_py_deps " + afile)
    lines.append("==== End of raw info for this process")
    text = "\n" + '\n'.join(lines) + "\n\n"
    return text


# a set of files to record if a pyfile has been visited
g_dynlib_visited = set()

def get_import_libfiles(pyfile):
    '''
    returns a list of pylib files that this pyfile imports.
    '''
    if not pyfile.endswith(".py"):
        verbose(pyfile + " is not python source file", LEVEL_2)
        return []
    visitor = PyImportVisitor(pyfile)
    try:
        ast_tree = ast.parse(read_text_file(pyfile))
    except Exception as e:
        verbose(" ".join(['Failed to parse file', pyfile, type(e).__name__, 'error message:', str(e)]))
        return {}
    visitor.visit(ast_tree)
    # exclude built-in modules who does not have __file__ attribute
    return [g_import_pylibs[pylib] for pylib in visitor.imports if g_import_pylibs[pylib]]


def append_raw_logfile_for_pylib_node(afile):
    '''
    Append to raw_logfile with fragments for afile itself and all its dependencies.
    This function recurses on itself.
    :param afile: the top-level file of dynlib dependency tree
    appends to raw_logfile, with build fragments written in correct order.
    it also updates g_dynlib_visited dict, flagging True for files that have dependency-fragments appended to raw_logfile.
    '''
    if afile in g_dynlib_visited:  # dependency-fragment for afile has been appended to raw_logfile
        return
    # add it to the visited dict, so it is visited only once
    g_dynlib_visited.add(afile)
    # will visit this afile now
    depfiles = get_import_libfiles(afile)
    if not depfiles:  # leaf node, do nothing
        return
    for depfile in depfiles:
        append_raw_logfile_for_pylib_node(depfile)
    if "sha1" in g_hashtypes:
        fragment = create_dependency_fragment(afile, depfiles)
        append_text_file(g_raw_logfile + ".sha1", fragment)
    if "sha256" in g_hashtypes:
        fragment = create_dependency_fragment(afile, depfiles, "sha256")
        append_text_file(g_raw_logfile + ".sha256", fragment)


def create_raw_logfile_for_files(afiles):
    '''
    Create raw_logfile with dependency fragments for a list of files.
    :param afiles: a list of Python source files
    writes new raw_logfile, with dependency fragments written in correct order.
    '''
    if len(afiles) < 11:
        print("\n==Creating raw_logfile for " + str(len(afiles)) + " Python .py script files: " + str(afiles))
    else:
        print("\n==Creating raw_logfile for " + str(len(afiles)) + " Python .py script files.")
    if "sha1" in g_hashtypes:
        write_text_file(g_raw_logfile + ".sha1", "")
    if "sha256" in g_hashtypes:
        write_text_file(g_raw_logfile + ".sha256", "")
    for afile in afiles:
        append_raw_logfile_for_pylib_node(afile)
    if "sha1" in g_hashtypes:
        print("==Created sha1 raw_logfile: " + g_raw_logfile + ".sha1\n")
    if "sha256" in g_hashtypes:
        print("==Created sha256 raw_logfile: " + g_raw_logfile + ".sha256\n")

############################################################
#### End of raw_logfile creation routines ####
############################################################

# The dict of { pyfile => list of all imported module details, like lineno/import_line, etc. }
g_pyfile_imports_db = {}

# a cache so that we visit same pyfile only once.
# dict of { pyfile => its dependency tree }
g_pyfile_visited_cache = {}

def get_all_import_libfiles(pyfile, ancestors):
    '''
    Get all the imported modules for a single python source files.
    This function recurses on itself.
    :param pyfile: a python script file
    :param ancestors: the list of pyfiles that are ancestors of this pyfile
    returns a dict of { imported pylib/pyfile => dependency tree }
    '''
    if pyfile in g_pyfile_visited_cache:
        return g_pyfile_visited_cache[pyfile]
    # check for recursion loop
    if pyfile in ancestors:
        verbose("Error in get import dependency tree: loop detected for pyfile " + pyfile + " ancestors: " + str(ancestors))
        return "RECURSION_LOOP_DETECTED"
    if not pyfile.endswith(".py"):
        verbose(pyfile + " is not python source file", LEVEL_2)
        return {}
    visitor = PyImportVisitor(pyfile)
    try:
        ast_tree = ast.parse(read_text_file(pyfile))
    except Exception as e:
        verbose(" ".join(['Failed to parse file', pyfile, type(e).__name__, 'error message:', str(e)]))
        return {}
    visitor.visit(ast_tree)
    verbose("##### After visting the ast tree of pyfile " + pyfile, LEVEL_4)
    imports_info = { "imports": visitor.imports_info }
    if visitor.failed_imports_info:
        imports_info["failed_imports"] = visitor.failed_imports_info
    if visitor.skipped_imports_info:
        imports_info["skipped_imports"] = visitor.skipped_imports_info
    g_pyfile_imports_db[pyfile] = imports_info
    ret = {}
    ancestors.append(pyfile)  # add myself to the list of ancestors
    for pylib in visitor.imports:
        libfile = g_import_pylibs[pylib]
        if libfile:
            ret[pylib + " " + libfile] = get_all_import_libfiles(libfile, ancestors)
        else:
            ret[pylib] = {}
    g_pyfile_visited_cache[pyfile] = ret
    ancestors.pop()  # remove myself from the list of ancestors
    return ret


def create_import_depend_tree_for_files(pyfiles):
    '''
    Create the import-dependency tree for a list of python source files.
    Get all the imported modules for pyfiles and their children.
    :param pyfiles: a list of python source files
    creates a dict of { pyfile => dependency tree } and a few other dicts.
    '''
    ret = {}
    for pyfile in pyfiles:
        ancestors = []  # ancestors is used to detect/stop possible recursion loop
        ret[pyfile] = get_all_import_libfiles(pyfile, ancestors)
    save_json_db(g_jsonfile + "-pylibs-db.json", g_import_pylibs)
    save_json_db(g_jsonfile + "-pyfile-imports.json", g_pyfile_imports_db)
    save_json_db(g_jsonfile + "-result.json", ret)
    if args.verbose > 3:
        save_json_db(g_jsonfile + "-pyfile-cache.json", g_pyfile_visited_cache)

############################################################
#### End of dependency tree creation routines ####
############################################################

def get_python_pkg(pyfile_path):
    '''
    Get the python package name from the pyfile path (which is absolute path).
    :param pyfile_path: the absolute path of the pyfile
    returns the proper package name for this python script file.
    '''
    # longest match wins if there are multiple matches
    max_len, found_pkg = 0, ''
    for path in sys.path:
        if pyfile_path.startswith(path):
            tokens = pyfile_path[len(path):].strip("/").split("/")
            if len(path) > max_len:
                max_len, found_pkg = len(path), tokens[0]
    return found_pkg


def get_python_absmodule(pyfile_path, level):
    '''
    Get the python absolute-import module name for a pyfile's relative import.
    :param pyfile_path: the absolute path of the pyfile
    :param level: the relative import level from the AST ImportFrom node
    returns the proper absolute-import module name for this relative import.
    '''
    # longest match wins if there are multiple matches
    max_len, found_abs_module = 0, ''
    for path in sys.path:
        if pyfile_path.startswith(path):
            tokens = pyfile_path[len(path):].strip("/").split("/")
            if len(path) > max_len:
                max_len, found_abs_module = len(path), ".".join(tokens[:len(tokens)-level])
    return found_abs_module


# dict of { python module name => python source file which is the __file__ attribute }
# It stores all imported python modules in absolute_import module format.
# relative import needs to be converted to absolute import before storing here.
g_import_pylibs = {}

# Note: all Python modules to import must be installed in order for this tool to work.
# If you cannot run your Python script successfully, then the result will be incomplete.
# will investigate venv later to see if uninstalled modules can be supported.

class PyImportVisitor(ast.NodeVisitor):
    """ only Import/ImportFrom and Try/ExceptHandler nodes are visited """

    def __init__(self, path):
        self.file_path = path  # must be absolute path
        self.file_lines = read_text_file(path).splitlines()  # for import_line retrieval
        self.parents = []  # keep the list of parents so we know if it is Try or ExceptHandler mode
        self.imports = set()  # the list of imported modules for this pyfile
        self.imports_info = {}  # the detailed imports info, including lineno, import_line, etc.
        self.failed_imports_info = {}  # the detailed imports info for failed module-imports
        self.skipped_imports_info = {}  # the detailed imports info for skipped module-imports
        self.try_import_fail = False  # if any module import fails in Try mode?
        verbose("Created visitor for pyfile " + path)

    def get_import_modules_from_ast_node(self, node):
        """ get the list of import modules from AST Import/ImportFrom node """
        if isinstance(node, ast.Import):
            return [alias.name for alias in node.names]
        # this must be ImportFrom node
        abs_module = ''
        if node.level > 0:  # convert relative imports to absolute imports
            abs_module = get_python_absmodule(self.file_path, node.level)
            verbose("This is relative import, and its abs_module is: " + abs_module, LEVEL_4)
        if abs_module:
            abs_module = abs_module + "."
        if node.module:
            modules = [abs_module + node.module,]
        else:
            modules = [abs_module + alias.name for alias in node.names]
        return modules

    def get_import_info(self, node):
        """ Get module import detail for AST Import/ImportFrom node """
        info = {'lineno': node.lineno, 'col_offset': node.col_offset}
        info["import_line"] = self.file_lines[node.lineno - 1]
        if hasattr(node, 'level'):
            info["level"] = node.level
        return info

    def import_pylib_from_import_node(self,node):
        """ import modules for AST Import/ImportFrom node """
        if not self.try_import_fail and isinstance(self.parents[-1], ast.ExceptHandler):
            verbose("there is no import failure in Try, thus skipping import-module in import node of ExceptHandler", LEVEL_3)
            modules = self.get_import_modules_from_ast_node(node)
            for module in modules:
                self.skipped_imports_info[module] = self.get_import_info(node)
            return
        modules = self.get_import_modules_from_ast_node(node)
        for module in modules:
            if module in g_import_pylibs:  # this module is already imported to global DB, just record its module info
                self.imports.add(module)
                self.imports_info[module] = self.get_import_info(node)
                continue
            try:
                pylib = importlib.import_module(module)
                if hasattr(pylib, '__file__'):
                    g_import_pylibs[module] = pylib.__file__
                else:  # this module should be Python build-in module
                    g_import_pylibs[module] = ''
                self.imports.add(module)
                self.imports_info[module] = self.get_import_info(node)
            except Exception as e:
                self.failed_imports_info[module] = self.get_import_info(node)
                verbose(" ".join(['Failed to import the', module, 'module,', type(e).__name__, 'error message:', str(e)]))
                if isinstance(self.parents[-1], ast.Try):
                    self.try_import_fail = True
                    verbose("Setting try_import_fail flag to True, so that we do import in ExceptHandler", LEVEL_3)
            except SystemExit as e:  # idle.pyshell module raises SystemExit(1), which is caught here
                self.failed_imports_info[module] = self.get_import_info(node)
                verbose(" ".join(['Failed to import the', module, 'module,', type(e).__name__, 'error message:', str(e)]))

    def recursive(func):
        """ decorator to make visitor work recursive """
        def wrapper(self,node):
            func(self,node)
            self.parents.append(node)  # push this node to the parents stack
            verbose("wrapper visit, after append, parents: " + str(self.parents), LEVEL_4)
            for child in ast.iter_child_nodes(node):
                self.visit(child)
            self.parents.pop()  # pop this node after visiting all its children
            verbose("wrapper visit, after pop, parents: " + str(self.parents), LEVEL_4)
        return wrapper

    @recursive
    def visit_Module(self,node):
        """ visit a Module node and visits it recursively"""
        verbose("Start visiting AST tree for pyfile " + self.file_path, LEVEL_3)

    @recursive
    def visit_Try(self,node):
        """ visit a Try node and visits it recursively"""
        verbose(ast.dump(node), LEVEL_3)
        self.try_import_fail = False  # set it False for a clean start of handling imports

    @recursive
    def visit_ExceptHandler(self,node):
        """ visit a Try node and visits it recursively"""
        verbose(ast.dump(node), LEVEL_3)
        if self.try_import_fail:
            verbose("Need to import module in this ExceptHandler.", LEVEL_2)
        else:
            verbose("No need to import module in this ExceptHandler.", LEVEL_2)

    def visit_Import(self,node):
        """ visit a Import node and not visit its children """
        verbose(ast.dump(node), LEVEL_2)
        self.import_pylib_from_import_node(node)

    def visit_ImportFrom(self,node):
        """ visit a ImportFrom node and not visits its children """
        verbose(ast.dump(node), LEVEL_2)
        self.import_pylib_from_import_node(node)

    def generic_visit(self,node):
        """ visit a generic node and not visits its children """
        verbose(ast.dump(node), LEVEL_4)

############################################################
#### End of PyImportVisitor routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool creates raw_logfile of runtime-dependency fragments for Python scripts")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('-r', '--raw_logfile',
                    help = "the raw log file, to store input/output file checksums")
    parser.add_argument('-O', '--output_dir',
                    help = "the output directory to store generated JSON files")
    parser.add_argument('-j', '--jsonfile',
                    help = "the output JSON file for the search result")
    parser.add_argument('--hashtype',
                    help = "the hash type, like sha1/sha256, the default is sha1")
    parser.add_argument('-f', '--files',
                    help = "comma-separated Python script files")
    parser.add_argument('-d', '--dirs',
                    help = "comma-separated directories to search for Python script files")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not (args.dirs or args.files):
        print ("Please specify the Python scripts with -f or directory with -d option!")
        print ("")
        parser.print_help()
        sys.exit()

    global g_jsonfile
    global g_tmpdir
    global g_raw_logfile
    if args.tmpdir:
        g_tmpdir = args.tmpdir
        g_jsonfile = os.path.join(g_tmpdir, "bomsh_pylib_jsonfile")
        g_raw_logfile = os.path.join(g_tmpdir, "bomsh_pylib_raw_logfile")
    if args.output_dir:
        output_dir = get_or_create_dir(args.output_dir)
        g_jsonfile = os.path.join(output_dir, "bomsh_pylib_jsonfile")
        g_raw_logfile = os.path.join(output_dir, "bomsh_pylib_raw_logfile")
    if args.raw_logfile:
        g_raw_logfile = args.raw_logfile
    if args.jsonfile:
        g_jsonfile = args.jsonfile
    if args.hashtype:  # only sha1 and sha256 are supported for now
        if "sha1" in args.hashtype:
            g_hashtypes.append("sha1")
        if "sha256" in args.hashtype:
            g_hashtypes.append("sha256")
    if not g_hashtypes:
        g_hashtypes.append("sha1")

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    afiles = []
    if args.files:
        afiles = args.files.split(",")
        afiles = [os.path.abspath(afile) for afile in afiles]
        bfiles = []
        for afile in afiles:
            if os.path.exists(afile):
                bfiles.append(afile)
            else:
                print("Warning!!! file " + afile + " does not exist.")
        afiles = bfiles
    elif args.dirs:
        for adir in args.dirs.split(","):
            afiles.extend(find_all_suffix_files(adir, ".py" ))

    # Create the raw_logfile with dependency fragments
    create_raw_logfile_for_files(afiles)
    # Create the module-import dependency tree
    create_import_depend_tree_for_files(afiles)


if __name__ == '__main__':
    main()
