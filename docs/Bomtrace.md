# Generating gitBOM docs with Bomtrace

Do the following to generate gitBOM docs for the HelloWorld program with Bomtrace.

    $ git clone URL-of-this-git-repo bomsh
    $ cd bomsh
    $ cp scripts/bomsh_hook.py /tmp
    $ cd src
    $ ../bin/bomtrace make
    $ ls -tl /tmp/bomdir
    $ cat /tmp/bomsh_hook_jsonfile

Do the following to generate gitBOM docs for the RPM or DEB package of OpenOSC with Bomtrace.

    $ git clone URL-of-this-git-repo bomsh
    $ rm -rf /tmp/bomdir; rm /tmp/bomsh_hook_*; cp bomsh/scripts/bomsh_hook.py /tmp
    $ git clone https://github.com/cisco/OpenOSC.git
    $ cd OpenOSC
    $ autoreconf -vfi ; ./configure
    $ ../bomsh/bin/bomtrace make deb  # on debian Linux distro
    $ ls -tl /tmp/bomdir
    $ cat /tmp/bomsh_hook_jsonfile
    $ echo "{}" > openosc_cvedb.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_hook_jsonfile -d openosc_cvedb.json -f debian/openosc/usr/lib/x86_64-linux-gnu/libopenosc.so.0.0.0,debian/openosc/usr/lib/x86_64-linux-gnu/libopenosc.a
    $ cat /tmp/bomsh_search_jsonfile-details.json
    $
    $ # the below are only for AlmaLinux/Centos/RedHat Linux distro
    $ ../bomsh/bin/bomtrace make rpm  # on RedHat Linux distro
    $ mkdir rpm-extractdir ; cd rpm-extractdir
    $ rpm2cpio ../rpmbuild/RPMS/x86_64/openosc-1.0.5-1.el8.x86_64.rpm | cpio -idmv
    $ rpm2cpio ../rpmbuild/RPMS/x86_64/openosc-static-1.0.5-1.el8.x86_64.rpm | cpio -idmv ; cd ..
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_hook_jsonfile -d openosc_cvedb.json -f rpm-extractdir/usr/lib64/libopenosc.a,rpm-extractdir/usr/lib64/libopenosc.so.0.0.0
