# vCenterExp

### CheatSheet

Linux

``` bash
# Get Domain
/usr/lib/vmware-vmafd/bin/vmafd-cli get-domain-name --server-name localhost

# Reset Password
/usr/lib/vmware-vmdir/bin/vdcadmintool

# vCenter Database
/etc/vmware-vpx/vcdb.properties

# symkey.dat
/etc/vmware-vpx/ssl/symkey.dat

# Identity Provider
/storage/db/vmware-vmdir/data.mdb

# SSO WebPath
/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/

# LDAP
/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]'
# regvalues1
/storage/service-state/likewise/registry.db
```

Windows

``` powershell
# VMWARE_CIS_HOME
"C:\Program Files\VMware\vCenter Server"

# Get Domain
"%VMWARE_CIS_HOME%\vmafdd\vmafd-cli.exe" get-domain-name --server-name localhost

# Reset Password
"%VMWARE_CIS_HOME%\vmdird\vdcadmintool.exe"

# vCenter Database
C:\ProgramData\VMware\vCenterServer\cfg\vmware-vpx\vcdb.properties

# symkey.dat
C:\ProgramData\VMware\vCenterServer\cfg\vmware-vpx\ssl\symkey.dat

# Identity Provider
C:\ProgramData\VMware\vCenterServer\data\vmdird\data.mdb

# SSO WebPath
C:\ProgramData\VMware\vCenterServer\runtime\VMwareSTSService\webapps\ROOT\

# LDAP
reg query '\\HKEY_THIS_MACHINE\\services\\vmdir'
reg query "HKLM\SYSTEM\CurrentControlSet\services\VMwareDirectoryService" /v dcAccountDN
```

## Reference

[Taking over VMware Vcenter 6.7.0](https://github.com/HynekPetrak/HynekPetrak/blob/master/take_over_vcenter_670.md)

[Exploiting the Sudo Baron Samedit vulnerability (CVE-2021-3156) on VMWare vCenter Server 7.0](https://research.nccgroup.com/2021/07/06/exploiting-the-sudo-baron-samedit-vulnerability-cve-2021-3156-on-vmware-vcenter-server-7-0/)

[Compromising vCenter via SAML Certificates](https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/)