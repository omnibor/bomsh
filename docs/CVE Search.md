# Software Vulnerability CVE Search

The generated hash tree database is /tmp/bomsh_hook_jsonfile, which can be fed to
the scripts/bomsh_search_cve.py script for CVE vulnerability search.

To create the CVE database and search for CVEs for a software like OpenSSL, with Bombash, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/openssl/openssl.git
    $ cd openssl
    $ ../bomsh/scripts/bomsh_create_cve.py -v -j openssl_cvedb.json
    $ git checkout OpenSSL_1_1_1k
    $ ./config
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_*; cp ../bomsh/scripts/bomsh_hook.py /tmp
    $ BOMSH= ../bomsh/bin/bombash
    $ make
    $ exit
    $ ../bomsh/scripts/bomsh_search_cve.py -r /tmp/bomsh_hook_jsonfile -d openssl_cvedb.json -f libssl.so.1.1,libcrypto.so.1.1

To create the CVE database and search for CVEs for a software like OpenSSL, with Bomtrace2, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/openssl/openssl.git
    $ cd openssl
    $ ../bomsh/scripts/bomsh_create_cve.py -v -j openssl_cvedb.json
    $ git checkout OpenSSL_1_1_1k
    $ ./config
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_* /tmp/bomsh_createbom_*
    $ cp ../bomsh/scripts/bomsh_hook2.py ../bomsh/scripts/bomsh_create_bom.py /tmp
    $ ../bomsh/bin/bomtrace2 make
    $ ../bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -b /tmp/bomdir
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_createbom_jsonfile -d openssl_cvedb.json -f libssl.so.1.1,libcrypto.so.1.1
    $ cat /tmp/bomsh_search_jsonfile-details.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -b /tmp/bomdir -d openssl_cvedb.json -f libssl.so.1.1,libcrypto.so.1.1
    $ # You can also directly provide checksums (blob_ids) with -c option, or gitBOM bom_ids with -g option
    $ cat /tmp/bomsh_search_jsonfile-details.json

To create the CVE database and search for CVEs for a software like Linux kernel, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/torvalds/linux.git
    $ cd linux
    $ ../bomsh/scripts/bomsh_create_cve.py -v -j linux_cvedb.json
    $ git checkout v4.18
    $ make menuconfig
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_* /tmp/bomsh_createbom_* ; cp ../bomsh/scripts/bomsh_*.py /tmp
    $ ../bomsh/bin/bomtrace2 -w ../bomsh/bin/bomtrace_watched_programs make
    $ ../bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -b /tmp/bomdir
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_createbom_jsonfile -d linux_cvedb.json -f arch/x86/boot/bzImage
    $ cat /tmp/bomsh_search_jsonfile-details.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -b /tmp/bomdir -d linux_cvedb.json -f vmlinux,arch/x86/boot/bzImage
    $ cat /tmp/bomsh_search_jsonfile-details.json

If you want to accurately create the CVE DB, please identify all the vulnerable source files for each CVE,
specify the blob ID ranges of the source files that are vulnerable to the CVE in a text file, and run
bomsh_create_cve script with the -r option.
A sample text file is provided in scripts/sample_vulnerable_ranges.txt file.

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/openssl/openssl.git
    $ cd openssl
    $ ../bomsh/scripts/bomsh_create_cve.py -v -j openssl_cvedb.json -r openssl_vulnerable_cve_ranges.txt

Please note, in order to create a more accurate CVE database, please follow the instructions in the "Creating CVE Database for Software" section.
It requires identification of CVE-add and CVE-fix git commits (which is one-time thing) in your software git repo.
Also CVE checking rules are useful when new source file blobs exist in Linux distros or private software builds/releases.

## Java Packages

To create the gitBOM database and the CVE database for Log4j2 CVE-2021-44228, and search for CVEs for the Log4j2 software, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone --branch rel/2.17.0 https://gitbox.apache.org/repos/asf/logging-log4j2.git log4j-2.17.0
    $ cd log4j-2.17.0
    $ ../bomsh/scripts/bomsh_create_cve.py -v -r ../bomsh/scripts/log4j2_CVE_2021_44228_ranges.txt -j ../log4j2_cvedb.json
    $ ./mvnw package -Dmaven.test.skip=true
    $ ../bomsh/scripts/bomsh_create_bom_java.py -r . -f log4j-core/target/log4j-core-2.17.0.jar -j log4j-treedb.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r log4j-treedb.json -d ../log4j2_cvedb.json -j result.json -f log4j-core/target/log4j-core-2.17.0.jar
    $ grep -6 CVElist result.json-details.json
    $
    $ cd ..
    $ git clone --branch rel/2.14.0 https://gitbox.apache.org/repos/asf/logging-log4j2.git log4j-2.14.0
    $ cd log4j-2.14.0
    $ ../bomsh/scripts/bomsh_create_cve.py -v -r ../bomsh/scripts/log4j2_CVE_2021_44228_ranges.txt -j ../log4j2_cvedb.json
    $ ./mvnw package -Dmaven.test.skip=true
    $ ../bomsh/scripts/bomsh_create_bom_java.py -r . -f log4j-core/target/log4j-core-2.14.0.jar -j log4j-treedb.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r log4j-treedb.json -d ../log4j2_cvedb.json -j result.json -f log4j-core/target/log4j-core-2.14.0.jar
    $ grep -6 CVElist result.json-details.json

Here are the CVE search results for two versions of Log4j2 software:

```
[root@000b478b5d68 log4j-2.17.0]# /tmp/bomsh_search_cve.py -r bomsh_createbom_jsonfile -d ../log4j2_cvedb.json -vv -j mysearchcve-result.json -f log4j-core/target/log4j-core-2.17.0.jar

Here is the CVE search results:
{
    "log4j-core/target/log4j-core-2.17.0.jar": {
        "CVElist": [],
        "FixedCVElist": [
            "CVE-2021-44228"
        ]
    }
}
[root@000b478b5d68 log4j-2.17.0]# grep -6 CVElist mysearchcve-result.json-details.json
                "file_path": "./log4j-core/src/main/java/org/apache/logging/log4j/core/config/plugins/convert/TypeConverterRegistry.java"
            },
            "file_path": "./log4j-core/target/classes/org/apache/logging/log4j/core/config/plugins/convert/TypeConverterRegistry.class"
        },
        "71e9c7daeb6f4e3819403a1e37f8171f548e50ed": {
            "a783ea43c171982723e87cc6afd29287c63c1b53": {
                "FixedCVElist": [
                    "CVE-2021-44228"
                ],
                "file_path": "./log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java"
            },
            "file_path": "./log4j-core/target/classes/org/apache/logging/log4j/core/lookup/JndiLookup.class"
        },
[root@000b478b5d68 log4j-2.17.0]#

[root@000b478b5d68 log4j-2.14.0]# /tmp/bomsh_search_cve.py -r bomsh_createbom_jsonfile -d ../log4j2_cvedb.json -vv -j mysearchcve-result.json -f log4j-core/target/log4j-core-2.14.0.jar

Here is the CVE search results:
{
    "log4j-core/target/log4j-core-2.14.0.jar": {
        "CVElist": [
            "CVE-2021-44228"
        ],
        "FixedCVElist": []
    }
}
[root@000b478b5d68 log4j-2.14.0]# grep -6 CVElist mysearchcve-result.json-details.json
                "file_path": "./log4j-core/src/main/java/org/apache/logging/log4j/core/pattern/DatePatternConverter.java"
            },
            "file_path": "./log4j-core/target/classes/org/apache/logging/log4j/core/pattern/DatePatternConverter$CachedTime.class"
        },
        "605c82e7442a5693745e1e28736446a8ced01d3c": {
            "30e65ad24f4b4d799e52cfd70fcbebc0490b7343": {
                "CVElist": [
                    "CVE-2021-44228"
                ],
                "file_path": "./log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java"
            },
            "file_path": "./log4j-core/target/classes/org/apache/logging/log4j/core/lookup/JndiLookup.class"
        },
[root@000b478b5d68 log4j-2.14.0]#
```

It shows that the 2.14.0 version log4j-core-2.14.0.jar is vulnerable to CVE-2021-44228, while the 2.17.0 version log4j-core-2.17.0.jar is not vulnerable (CVE has fixed).
Also it reports the root cause: it is due to the specific version of the JndiLookup.java file with the githash of 30e65ad24f4b4d799e52cfd70fcbebc0490b7343.
Note the git commit logs of log4j2 are manually inspected, and the "bomsh_create_cve.py -r ranges.txt" command is run to create log4j2_cvedb.json for CVE-2021-44228 in this example.

The bomsh_create_bom_java.py script also inserts .bom entry into .jar files automatically.

```
[root@000b478b5d68 log4j-2.17.0]# ../bomsh/scripts/bomsh_create_bom_java.py -r . -f log4j-core/target/log4j-core-2.17.0.jar -b bomdir -j log4j-treedb.json

[root@000b478b5d68 log4j-2.17.0]# jar tvf bomdir/with_bom_files/d4f6bcc969db60298df329972b9b6e83f3aec2e2-with_bom-0dc986b732c75ba0050cdbc859cd9b97eb2cf325-log4j-core-2.17.0.jar | tail -3
   650 Sat Jan 22 18:22:14 UTC 2022 org/apache/logging/log4j/core/jmx/LoggerConfigAdminMBean.class
  5833 Sat Jan 22 18:22:16 UTC 2022 org/apache/logging/log4j/core/jmx/StatusLoggerAdmin.class
    20 Mon Jan 24 04:38:45 UTC 2022 .bom
[root@000b478b5d68 log4j-2.17.0]# jar -xvf bomdir/with_bom_files/d4f6bcc969db60298df329972b9b6e83f3aec2e2-with_bom-0dc986b732c75ba0050cdbc859cd9b97eb2cf325-log4j-core-2.17.0.jar .bom
extracted: .bom
[root@000b478b5d68 log4j-2.17.0]# hexdump -C .bom
00000000  0d c9 86 b7 32 c7 5b a0  05 0c db c8 59 cd 9b 97  |....2.[.....Y...|
00000010  eb 2c f3 25                                       |.,.%|
00000014
[root@000b478b5d68 log4j-2.17.0]#
```

The bomsh_create_bom_java.py script can also work with strace to more accurately create the gitBOM hash-tree database.
Strace can be run first to collect the strace log, which is then read by bomsh_create_bom_java.py with the "-s" option.
This tracks the read/write of .java/.class files, and should be able to more accurately associate .class files to .java files.
The below is an example of creating the hash-tree database for Maven with strace logfile.

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/apache/maven.git ; cd maven
    $ strace -f -s99999 --seccomp-bpf -e trace=openat -qqq -o strace_logfile mvn -Drat.numUnapprovedLicenses=1000 package
    $ ../bomsh/scripts/bomsh_create_bom_java.py -r . -s strace_logfile -f maven-core/target/maven-core-4.0.0-alpha-1-SNAPSHOT.jar -j maven-treedb.json
    $ cat maven-treedb.json

## Rust Packages

To create the gitBOM database for a Rust package like kalker, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/PaddiM8/kalker.git
    $ cd kalker ; echo "{}" > kalker_cvedb.json
    $ ../bomsh/bin/bomtrace2 cargo build --release
    $ cat /tmp/bomsh_hook_raw_logfile
    $ ../bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -vv -b /tmp/bomdir
    $ cat /tmp/bomsh_createbom_jsonfile
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_createbom_jsonfile -d kalker_cvedb.json -j result.json -f target/release/kalker
    $ cat result.json-details.json

All the gitBOM docs are created in /tmp/bomdir (the -b option of bomsh_create_bom.py script).
And all the ELF files are automatically inserted with .bom ELF section, and all archive files are embedded with .bom entry.

## GoLang Packages

To create the gitBOM database for a golang package like outyet, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ # you need to find out the locaiton of your go compiler and tell bomtrace.
    $ # on Ubuntu20.04, it is /usr/lib/go-1.13/pkg/tool/linux_amd64/compile
    $ # the below is for RedHat/Centos/AlmaLinux
    $ sed -i "s|hook_script_cmdopt=-vv > |hook_script_cmdopt=-vv -w /usr/lib/golang/pkg/tool/linux_amd64/compile,/usr/lib/golang/pkg/tool/linux_amd64/link > |" bomsh/bin/bomtrace.conf
    $ sed -i "s|#syscalls=openat|syscalls=openat|" bomsh/bin/bomtrace.conf
    $ git clone https://github.com/golang/example
    $ cd example/outyet; echo "{}" > outyet_cvedb.json
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_* /tmp/bomsh_createbom_*
    $ ../bomsh/bin/bomtrace2 -c ../bomsh/bin/bomtrace.conf go build -a
    $ cat /tmp/bomsh_hook_raw_logfile
    $ ../bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -vv -b /tmp/bomdir
    $ cat /tmp/bomsh_createbom_jsonfile
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_createbom_jsonfile -d outyet_cvedb.json -j result.json -f outyet
    $ cat result.json-details.json

Notice that "go build" by default caches previously built packages. The -a option makes "go build" ignore the cache.
This is required for bomtrace to record all build steps.
Also remember to compile bin/bomtrace2 with the latest patches/bomtrace2.patch file, and a customized bomtrace.conf file must be used
because the bomtrace tool needs to know the location of go compiler and two more syscalls need to be traced.
Again all the gitBOM docs are created in /tmp/bomdir (the -b option of bomsh_create_bom.py script).
And all the ELF files are automatically inserted with .bom ELF section, and all archive files are embedded with .bom entry.

