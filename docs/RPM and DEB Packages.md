# RPM and DEB Packages

The `bomsh_create_bom.py` script can create GitBOM docs for RPM/DEB packages. The `-p` option takes a comma-separated list of built RPM/DEB package files.

`rpm2cpio` and `cpio` must be installed to unbundle RPM packages, and `dpkg-deb` must be installed to unbundle DEB packages.

An example for the `hostname` RPM package is:

```bash
dnf download hostname --source
bomtrace2 -w bomsh/bin/bomtrace_watched_programs rpmbuild --rebuild hostname-3.20-6.el8.src.rpm
python3 bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -p /root/rpmbuild/RPMS/x86_64/hostname-3.20-6.el8.x86_64.rpm
```

