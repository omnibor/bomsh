# Creating CVE Database for Software

The gitBOM artifact tree created by bomsh lays the foundation for more useful things like CVE search for software.
It is very important to create an accurate CVE database for your software.
We will take the OpenSSL software as an example since OpenSSL is a very critical security software in Linux.

In order to accurately create the CVE database for OpenSSL, we have proposed to use YAML format to tag the git commits that introduce or fix the CVE.
Here are some example YAML files for OpenSSL:

```
[yonhan@rtp-gpu-02 cveinfo_dir]$ more cveinfo.731f431.yaml
Fixed:
 CVE-2014-0160:
  src_files:
   - ssl/d1_both.c
   - ssl/t1_lib.c
[yonhan@rtp-gpu-02 cveinfo_dir]$ more cveinfo.4817504.yaml
Added:
 CVE-2014-0160:
  src_files:
   - ssl/d1_both.c
   - ssl/t1_lib.c
[yonhan@rtp-gpu-02 cveinfo_dir]$
```

When you put all such cveinfo.*.yaml files into a directory cveinfo_dir, you can run the below command to generate the CVE database for your software:

```
../bomsh/scripts/bomsh_create_cve.py --use_git_tags --cveinfo_dir cveinfo_dir -j openssl_bomsh_created_cvedb.json
```

The created CVE database file is the openssl_bomsh_created_cvedb.json file, which is used by the bomsh_search_cve.py script to search CVEs for binaries.

In order to cover more blobs that are not covered by the CVE-add/CVE-fix commits in the git repo, we have proposed the below YAML format for the CVE checking rules:

```
The below check in cveadd file for CVE-add:

CVE-2020-1967:
 ssl/t1_lib.c:
  include:
   - "if (sig_nid == sigalg->sigandhash)"
   - "? tls1_lookup_sigalg(s->s3.tmp.peer_cert_sigalgs[i])"
  exclude:
   - "if (sigalg != NULL && sig_nid == sigalg->sigandhash)"

The below check in cvefix file for CVE-fix:

CVE-2020-1967:
 ssl/t1_lib.c:
  include:
   - "if (sigalg != NULL && sig_nid == sigalg->sigandhash)"
  exclude:
   - "if (sig_nid == sigalg->sigandhash)"
```

The above CVE checking rules will be checked against for all the CVE-relevant source files in your git repo.
If you put the cveadd and cvefix files in the cvecheck directory, then run the below command to generate a more complete CVE database:

```
../bomsh/scripts/bomsh_create_cve.py --use_git_tags --cveinfo_dir cveinfo_dir --cve_check_dir cvecheck -j openssl_bomsh_created_cvedb.json
```

Note that the above command must be run from the git repo directory of your software.

Some Linux distros apply additional security patches (including backporting of high-severity CVE fixes) on top of upstream software releases.
This may generate new blobs that do not exist in the git repo of the software. The bomsh_create_cve.py script has been enhanced to cover this use case.
For [Centos](https://git.centos.org/rpms/openssl.git) or [Fedora](https://src.fedoraproject.org/rpms/openssl.git) RPM git repo,
you can clone the RPM git repo and run the below command, which scans your RPM git repo and finds all CVE-relevant blobs and checks against the CVE rules.
The openssl_bomsh_created_cvedb.json input parameter is the CVE database created from the official OpenSSL git repo with the above bomsh_create_cve.py script.

```
../bomsh/scripts/bomsh_create_cve.py --cvedbfile openssl_bomsh_created_cvedb.json -vv --cve_check_dir cvecheck --gen_extra_cvedb
```

Another use case is to run bomtrace2 with CVE checking during software build, that is, during gitBOM tree generation.
You need to run bomtrace2 with "-c bomtrace.conf" option, and modify bomtrace.conf file and add the below "--cve_check_dir cvecheck" option when invoking bomsh_hook2.py script.

```
hook_script_cmdopt= --cve_check_dir cvecheck
```

This will generate some additional CVE metadata during gitBOM tree generation, which will be utilized later by the bomsh_search_cve.py script.
This will cover any new source file blobs that are not covered by the bomsh_create_cve.py script.

Please check the [openssl-cve](https://github.com/yonhan3/openssl-cve) repo for some OpenSSL examples.

