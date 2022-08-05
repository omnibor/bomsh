# Compile Bombash and Bomtrace from Source

The Bombash tool is based on BASH, and Bomtrace/Bomtrace2 is based on STRACE. The corresponding patch files are stored in the patches directory.
To compile Bombash/Bomtrace2 from source, do the following steps:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://git.savannah.gnu.org/git/bash.git
    $ # or github repo # git clone https://github.com/bminor/bash.git
    $ cd bash ; patch -p1 < ../bomsh/patches/bombash.patch
    $ ./configure ; make ; cp ./bash ../bomsh/bin/bombash
    $ cd ..
    $ git clone https://github.com/strace/strace.git
    $ cd strace ; patch -p1 < ../bomsh/patches/bomtrace2.patch
    $ ./bootstrap ; ./configure ; make
    $ # if configure fails, try add --disable-mpers or --enable-mpers=check
    $ cp src/strace ../bomsh/bin/bomtrace2

