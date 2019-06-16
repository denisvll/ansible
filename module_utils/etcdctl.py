import os
import subprocess
import json
import base64

def etcdctl(*args):
    endpoint = os.environ.get('PYTHON_ETCD_HTTP_URL')
    os.environ['ETCDCTL_API'] = '3'
    etcdctl_bin = '/tmp/etcd-download-test/etcdctl'
    if endpoint:
        args = ['--endpoints', endpoint] + list(args)
    args = [etcdctl_bin, '-w', 'json'] + list(args)
    print(" ".join(args))
    try:
        with open(os.devnull, 'w') as devnull:
            output = subprocess.check_output(args,stderr=devnull)
    except subprocess.CalledProcessError:
        pass
    else:
        return json.loads(output.decode('utf-8'))


def etcd_user_check(user):
    result=etcdctl('user','get', user)
    if result:
        return True
    else:
        return False


def etcd_user_list():
    result = etcdctl('user', 'list')
    if 'users' in result:
        return result['users']
    else:
        return False


def etcd_user_role_list(user):
    if etcd_user_check(user):
        result = etcdctl('user', 'get', user)
        if 'roles' in result:
            return result['roles']
    else:
        return False


def etcd_user_add(user,password):
    result = etcdctl('user', 'add', user + ':' + password)
    if result is None:
        return False
    else:
        return True


def etcd_user_delete(user):
    result = etcdctl('user', 'delete', user)
    if result is None:
        return False
    else:
        return True


def etcd_user_grant_role(user,role):
    result = etcdctl('user', 'grant-role', user, role)
    if result is None:
        return False
    else:
        return True

def etcd_user_revoke_role(user,role):
    result = etcdctl('user', 'revoke-role', user, role)
    if result is None:
        return False
    else:
        return True


def etcd_role_check(role):
    result = etcdctl('role', 'get', role)
    if result:
        return True
    else:
        return False

def etcd_role_add(role):
    result = etcdctl('role', 'add', role)
    if result is None:
        return False
    else:
        return True

def etcd_role_delete(role):
    result = etcdctl('role', 'delete', role)
    if result is None:
        return False
    else:
        return True

def etcd_role_list():
    result = etcdctl('role', 'list')
    if 'roles' in result:
        return result['roles']
    else:
        return False

def etcd_role_perm_list(role):
    if etcd_role_check(role):
        result = etcdctl('role', 'get', role)
        if 'perm' in result:
            return result['perm']
        else:
            return []
    else:
        return False

def etcd_role_grant_perm(role,perm):
    # perm={
    #     'perm_type':'',
    #     'path':'',
    #     'range_end': '',
    #     'prefix': ''
    # }


    if perm['prefix']:
        result = etcdctl('role', 'grant-permission', role, perm['perm_type'],
                         perm['path'],
                         increment_last_byte(perm['path'].encode()).decode()
        )
    elif perm['range_end']:
        result = etcdctl('role', 'grant-permission', role, perm['perm_type'],
                         perm['path'],
                         perm['range_end']
        )
    else:
        result = etcdctl('role', 'grant-permission', role, perm['perm_type'],
                         perm['path'],
        )

    if result is None:
        return False
    else:
        return True

def etcd_role_revoke_prem(role,perm):

    if perm['prefix']:
        result = etcdctl('role', 'revoke-permission', role,
                         perm['path'],
                         increment_last_byte(perm['path'].encode()).decode()
        )
    elif perm['range_end']:
        result = etcdctl('role', 'revoke-permission', role,
                         perm['path'],
                         perm['range_end']
        )
    else:
        result = etcdctl('role', 'revoke-permission', role,
                         perm['path'],
        )
    if result is None:
        return False
    else:
        return True


def etcd_role_perm_check(role,perm):
    if etcd_role_perm_list(role):
        for role_perm in etcd_role_perm_list(role):
            if perm_decode(role_perm) == perm:
                return True
    return False



def perm_decode(perm):
    perm_decoded={
        'perm_type':'',
        'path':'',
        'range_end': '',
        'prefix': ''
    }

    if 'permType' not in perm:
        perm_decoded['perm_type'] = 'read'
    elif perm['permType'] == 1:
        perm_decoded['perm_type'] = 'write'
    elif perm['permType'] == 2:
        perm_decoded['perm_type'] = 'readwrite'
    else:
        raise Exception("unknow permission type")

    perm_decoded['path'] = base64.b64decode(perm['key'].encode()).decode()

    if 'range_end' in perm:
        perm_decoded['range_end'] = base64.b64decode(perm['range_end'].encode()).decode()
        if increment_last_byte(perm_decoded['path'].encode()) == perm_decoded['range_end'].encode():
            perm_decoded['prefix'] = True
    else:
        perm_decoded['range_end'] = False
        perm_decoded['prefix'] = False


    return perm_decoded

def increment_last_byte(byte_string):
    s = bytearray(byte_string)
    s[-1] = s[-1] + 1
    return bytes(s)
