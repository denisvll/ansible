#!/usr/bin/python
#
# (c) 2018, Jean-Philippe Evrard <jean-philippe@evrard.me>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: etcd3
short_description: "create etcd roles"
version_added: "2.5"
requirements:
  - etcd3
description:
   - create roles in etcd3 cluster using its v3 api.
   - Needs python etcd3 lib to work
options:
    name:
        description:
            - role name
        required: true
    role:
        description:
            - assign role to user
    perm:
        description:
            - role permissions 
    state:
        description:
            - the state of the user
            - can be present or absent
        required: true
    host:
        description:
            - the IP address of the cluster
        default: 'localhost'
    port:
        description:
            - the port number used to connect to the cluster
        default: 2379
    auth_user:
        description:
            - The etcd user to authenticate with.
        version_added: '2.8'
    auth_password:
        description:
            - The password to use for authentication.
            - Required if I(user) is defined.
        version_added: '2.8'
    ca_cert:
        description:
            - The Certificate Authority to use to verify the etcd host.
            - Required if I(client_cert) and I(client_key) are defined.
        version_added: '2.8'
    client_cert:
        description:
            - PEM formatted certificate chain file to be used for SSL client authentication.
            - Required if I(client_key) is defined.
        version_added: '2.8'
    client_key:
        description:
            - PEM formatted file that contains your private key to be used for SSL client authentication.
            - Required if I(client_cert) is defined.
        version_added: '2.8'
    timeout:
        description:
            - The socket level timeout in seconds.
        version_added: '2.8'
author:
    - Jean-Philippe Evrard (@evrardjp)
    - Victor Fauth (@vfauth)
"""

EXAMPLES = """
# Store a value "bar" under the key "foo" for a cluster located "http://localhost:2379"
- etcd3_role:
    name: "foo"
    password: "baz3"
    host: "localhost"
    port: 2379
    state: "present"


# Authenticate using TLS certificates
- etcd3_role:
    name: "foo"
    password: "baz3"
    ca_cert: "/etc/ssl/certs/CA_CERT.pem"
    client_cert: "/etc/ssl/certs/cert.crt"
    client_key: "/etc/ssl/private/key.pem"
"""

RETURN = '''
key:
    description: The key that was queried
    returned: always
    type: str
old_value:
    description: The previous value in the cluster
    returned: always
    type: str
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import ansible.module_utils.etcdctl as etcdctl

def prepeare_perm(perm):

    prepeared_perm = []

    for key in perm:
        perm_templ = {
            'perm_type': '',
            'path': '',
            'range_end': '',
            'prefix': ''
        }
        if 'prefix' in key:
            perm_templ['prefix'] = True
            perm_templ['range_end'] = etcdctl.increment_last_byte(key['path'].encode()).decode()
        else:
            if 'range_end' in key:
                perm_templ['range_end'] = key['range_end']
                if key['range_end'] ==  etcdctl.increment_last_byte(key['path'].encode()).decode():
                    perm_templ['prefix'] = True
            else:
                perm_templ['range_end'] = False
                perm_templ['prefix'] = False



        perm_templ['perm_type'] = key['perm_type']
        perm_templ['path'] = key['path']

        prepeared_perm.append(perm_templ)

    return prepeared_perm

def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        name=dict(type='str', required=True),
        password=dict(type='str', no_log=True),
        perm=dict(type='list'),
        host=dict(type='str', default='localhost'),
        port=dict(type='int', default=2379),
        state=dict(type='str', required=True, choices=['present', 'absent']),
        role=dict(type='list'),
        auth_user=dict(type='str'),
        auth_password=dict(type='str', no_log=True),
        ca_cert=dict(type='path'),
        client_cert=dict(type='path'),
        client_key=dict(type='path'),
        timeout=dict(type='int'),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_together=[['client_cert', 'client_key'], ['auth_user', 'auth_password']],
    )

    # It is possible to set `ca_cert` to verify the server identity without
    # setting `client_cert` or `client_key` to authenticate the client
    # so required_together is enough
    # Due to `required_together=[['client_cert', 'client_key']]`, checking the presence
    # of either `client_cert` or `client_key` is enough
    if module.params['ca_cert'] is None and module.params['client_cert'] is not None:
        module.fail_json(msg="The 'ca_cert' parameter must be defined when 'client_cert' and 'client_key' are present.")

    result['key'] = module.params.get('key')
    module.params['cert_cert'] = module.params.pop('client_cert')
    module.params['cert_key'] = module.params.pop('client_key')
    #
    # if not HAS_ETCD:
    #     module.fail_json(msg=missing_required_lib('etcd3'), exception=ETCD_IMP_ERR)
    #
    # allowed_keys = ['host', 'port', 'ca_cert', 'cert_cert', 'cert_key',
    #                 'timeout', 'auth_user', 'auth_password']
    # # TODO(evrardjp): Move this back to a dict comprehension when python 2.7 is
    # # the minimum supported version
    # # client_params = {key: value for key, value in module.params.items() if key in allowed_keys}
    # client_params = dict()
    # for key, value in module.params.items():
    #     if key in allowed_keys:
    #         if key == "auth_user":
    #             key = "user"
    #         if key == "auth_password":
    #             key = "password"
    #         client_params[key] = value
    #
    # try:
    #     etcd = etcd3.client(**client_params)
    # except Exception as exp:
    #     module.fail_json(msg='Cannot connect to etcd ewe cluster: %s, %s' % (to_native(exp),client_params),
    #                      exception=traceback.format_exc())
    #
    # try:
    #     etcd_auth = etcd3.Auth(etcd)
    # except Exception as e:
    #     module.fail_json(msg='Cannot intilize etcd auth backand: %s' % (to_native(e)),
    #                      exception=traceback.format_exc())
    #
    #
    # perm = build_permission(module.params['perm'])
    # module.fail_json(msg=perm)
    #
    #
    # try:
    #     cluster_value = etcd_auth.role_get(module.params['name'])
    #     if cluster_value:
    #         etcd_perm=list(cluster_value)
    #         if etcd_perm:
    #             result['old_value'] = { "perm" : etcd_perm }
    #         else:
    #             result['old_value'] = { "perm" : None }
    #
    # except:
    #     result['old_value'] = None
    #
    # allowed_permissons = ['READ','WRITE','READWRITE']
    #
    # module.fail_json(msg=perm)
    # if perm:
    #     if perm['perm_type'] not in allowed_permissons:
    #         module.fail_json(msg='PErm Type %s is not allowed' % to_native(perm['perm_type']))
    #
    #

    if module.params['state'] == 'absent':
        if etcdctl.etcd_role_check(module.params['name']):
            if not etcdctl.etcd_role_delete(module.params['name']):
                module.fail_json(msg='Cannot delete role %s' % (module.params['name']))
            result['changed'] = True
        else:
            result['changed'] = False

    elif module.params['state'] == 'present':
        permissions=sorted(
            prepeare_perm(module.params['perm']),
            key = lambda i: i['path']
        )
        if etcdctl.etcd_role_check(module.params['name']):
            # role exist, check perm,
            old_permissions=[]
            for i in etcdctl.etcd_role_perm_list(module.params['name']):
                old_permissions.append(etcdctl.perm_decode(i))

            old_permissions=sorted(
                old_permissions,
                key=lambda i: i['path']
            )

            if old_permissions != permissions:
                #module.fail_json(msg="old: %s, new: %s" % (old_permissions, permissions))
                # user exist with incorect roles

                #find roles for delete
                for old_perm in old_permissions:
                    if old_perm not in permissions:
                        etcdctl.etcd_role_revoke_prem(module.params['name'],old_perm)

                for perm in permissions:
                   etcdctl.etcd_role_grant_perm(module.params['name'], perm)
                result['changed'] = True
        else:
            # create role
            etcdctl.etcd_role_add(module.params['name'])
            # add perms
            for perm in module.params['perm']:
                etcdctl.etcd_role_grant_perm(module.params['name'], perm)
            result['changed'] = True


    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)



def increment_last_byte(string):
    s = bytearray(string.encode())
    s[-1] = s[-1] + 1
    return s.decode()

def build_permission(perm):

    if perm['prefix']:
        perm['end_range'] = increment_last_byte(perm['path'])
        perm.pop('prefix')

    return perm


def to_bytes(maybe_bytestring):
    """
    Encode string to bytes.

    Convenience function to do a simple encode('utf-8') if the input is not
    already bytes. Returns the data unmodified if the input is bytes.
    """
    if isinstance(maybe_bytestring, bytes):
        return maybe_bytestring
    else:
        return maybe_bytestring.encode('utf-8')


def main():
    run_module()


if __name__ == '__main__':
    main()
