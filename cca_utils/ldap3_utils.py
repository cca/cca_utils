import random
import string
import time

from ldap3 import (
    Server, Connection, AUTH_SIMPLE, STRATEGY_SYNC, ALL, SUBTREE,
    MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE)
from passlib.hash import ldap_sha1

from django.conf import settings


def ldap_connect():
    '''
    Returns an LDAP connection object, to be used by various search functions.
    We use different credentials depending on whether we're reading or writing -
    pass in `modify=True` to use the writable connection.
    '''

    try:
        server = Server(settings.LDAP_SERVER, port=389, get_info=ALL)
        conn = Connection(
            server, authentication=AUTH_SIMPLE, user=settings.LDAP_AUTH_SEARCH_DN,
            password=settings.LDAP_MODIFY_PASS, check_names=True, lazy=False,
            client_strategy=STRATEGY_SYNC, raise_exceptions=True
            )

        conn.bind()
        return conn

    except Exception:
        print("Connection to LDAP server failed")
        raise


def ldap_get_user_data(username=None, ccaid=None, uidnumber=None, wdid=None):
        '''
        Given a username or student ID, returns base LDAP data for a user.
        Pass ccaid=1234567 to retrieve by CCA ID rather than username.
        Pass wdid=1234567 to retrieve by Workday ID.
        Pass uidnumber=1234567 to retrieve by LDAP uidNumber.
        '''

        if ccaid:
            filter = "(ccaEmployeeNumber={ccaid})".format(ccaid=ccaid)
        elif uidnumber:
            filter = "(uidnumber={uidnumber})".format(uidnumber=uidnumber)
        elif wdid:
            filter = "(ccaWorkdayNumber={wdid})".format(wdid=wdid)
        else:
            filter = "(uid={user})".format(user=username)

        try:
            conn = ldap_connect()
            attributes = ['sn', 'givenName', 'uid', 'mail', 'ccaEmployeeNumber', 'ccaWorkdayNumber']
            results = conn.search(settings.LDAP_BASE_DN, filter, attributes=attributes)
            ret = conn.entries[0] if results else None
        except Exception:
            raise
        finally:
            conn.unbind()

        return ret


def ldap_generate_uidnumber():
    '''
    uidNumber is required by LDAP, though CCA doesn't use it for anything.
    LDAP has no auto-increment capability. Rather than go through all records
    and try to determine next ID, we set the uidNumber to something that's
    randomly chosen but available.

    Datatel starts numbering at 1000000; this func starts at 2000000 to distinguish.
    '''

    num = random.randint(2000000, 9999999)

    if not ldap_get_user_data(uidnumber=num):
        return num

    # If we're still here, that uidNumber already exists in LDAP; keep trying.
    while ldap_get_user_data(uidnumber=num):
        num = random.randint(2000000, 9999999)

    return num


def ldap_create_user(**kwargs):
    '''
    Takes a dictionary of key/value pairs, generates a dictonary of LDAP-formatted
    properties and attempts to submit new record. Pass in e.g.:

    kwargs = {
        "password": password,
        "fname": fname,
        "lname": lname,
        "birthdate": birthdate,
        "email": email,
        "uid": uid,
        "wdid": wdid,
        "cca_id": cca_id,
        }
    '''
    raw_password = kwargs.get('password')
    hashed_pass = ldap_sha1.encrypt(raw_password)

    uid = kwargs.get('uid')
    wdid = kwargs.get('wdid')
    cca_id = kwargs.get('cca_id')
    fname = kwargs.get('fname')
    lname = kwargs.get('lname')
    birthdate = kwargs.get('birthdate')
    email = kwargs.get('email')

    # LDAP stores birthdates as simple strings of format 19711203, so all we need to do is
    # stringify the date object and remove hyphens
    bday_string = str(birthdate).replace('-', '')

    objectclass = [
        'top',
        'person',
        'organizationalPerson',
        'inetOrgPerson',
        'eduPerson',
        'account',
        'posixAccount',
        'shadowAccount',
        'sambaSAMAccount',
        'passwordObject',
        'ccaPerson',
        'inetuser',
        ]

    attrs = {}
    attrs['sn'] = lname
    attrs['cn'] = fname
    attrs['displayName'] = '{first} {last}'.format(first=fname, last=lname)
    attrs['userPassword'] = '{passwd}'.format(passwd=hashed_pass),
    attrs['uid'] = uid
    attrs['givenName'] = fname
    attrs['ccaBirthDate'] = bday_string
    attrs['homeDirectory'] = '/Users/{username}'.format(username=uid)
    attrs['uidNumber'] = str(ldap_generate_uidnumber())
    attrs['gidNumber'] = str(20)
    attrs['ccaWorkdayNumber'] = str(wdid)
    attrs['ccaEmployeeNumber'] = str(cca_id)
    attrs['sambaSID'] = 'placeholder'  # We don't use this value but it must be present.
    attrs['mail'] = email

    # Attempt to insert new LDAP user
    try:
        dn = "uid={username},{ou}".format(username=uid, ou=settings.LDAP_PEOPLE_OU)
        conn = ldap_connect()
        conn.add(dn, objectclass, attrs)
        conn.unbind()
        ldap_enable_disable_acct(uid, "enable")  # Set their account activation timestamp
        return True
    except Exception:
        raise


def ldap_delete_user(username):
    '''
    Delete a User record if possible.
    '''

    try:
        dn = "uid={user},{ou}".format(user=username, ou=settings.LDAP_PEOPLE_OU)
        conn = ldap_connect()
        conn.delete(dn)
        return True
    except Exception:
        raise


def ldap_add_members_to_group(groupcn, new_members):
    '''
    groupcn is the 'cn' attribute of an LDAP group (as string)
    new_members is a python list of username strings to add to that group.
    Returns True or False.
    '''
    groupdn = "cn={groupcn},{ou}".format(groupcn=groupcn, ou=settings.LDAP_GROUPS_OU)
    mod_attrs = {}

    # Make sure new_members is actually a list
    if isinstance(new_members, list):
        add_members = []
        # Remove any non-existent LDAP users from list
        for person in new_members:
            add_members.append('uid={u},{ou}'.format(ou=settings.LDAP_PEOPLE_OU, u=person))
            if not ldap_get_user_data(person):
                add_members.remove(person)
        mod_attrs['member'] = [MODIFY_ADD, add_members]
        # Batch-add all new users
        try:
            conn = ldap_connect()
            conn.modify(groupdn, mod_attrs)
            return True
        except Exception:
            # In most cases a failure here is because there's an orphaned user already
            # in the group we're trying to add to.
            raise


def ldap_remove_members_from_group(groupcn, remove_members):
    '''
    groupcn is the 'cn' attribute of an LDAP group (as string)
    new_members is a python list of username strings to add to that group.
    Returns True or False.
    '''

    groupdn = "cn={groupcn},{ou}".format(groupcn=groupcn, ou=settings.LDAP_GROUPS_OU)
    mod_attrs = {}

    # Make sure remove_members is actually a list
    if isinstance(remove_members, list):
        del_members = []
        # Remove any non-existent LDAP users from list
        for person in remove_members:
            del_members.append('uid={u},{ou}'.format(ou=settings.LDAP_PEOPLE_OU, u=person))
            if not ldap_get_user_data(person):
                del_members.remove(person)
        mod_attrs['member'] = [MODIFY_DELETE, del_members]
        # Batch-add all new users
        try:
            conn = ldap_connect()
            conn.modify(groupdn, mod_attrs)
            return True
        except Exception:
            # In most cases a failure here is because there's an orphaned user already
            # in the group we're trying to add to.
            raise


def ldap_enable_disable_acct(username, action):
    '''
    An account is considered enabled or disabled by presence of ccaActivateTime or
    ccaDisableTime properties, with epoch as value. It's not logical to have both at once,
    so always scrub one when setting the other.
    '''

    epoch_time = str(int(time.time()))
    dn = "uid={user},{ou}".format(user=username, ou=settings.LDAP_PEOPLE_OU)
    mod_attrs = {}

    if action == "enable":
        mod_attrs['ccaActivateTime'] = [MODIFY_REPLACE, [epoch_time, ]]
        mod_attrs['ccaDisableTime'] = [MODIFY_REPLACE, []]

    if action == "disable":
        mod_attrs['ccaActivateTime'] = [MODIFY_REPLACE, []]
        mod_attrs['ccaDisableTime'] = [MODIFY_REPLACE, [epoch_time, ]]

        # Set random long password on disabled account
        randpass = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(24))
        ldap_change_password(username, randpass)

    try:
        conn = ldap_connect()
        conn.modify(dn, mod_attrs)
        return True
    except Exception:
        raise


def ldap_change_password(username, raw_password):
    dn = "uid={username},{ou}".format(username=username, ou=settings.LDAP_PEOPLE_OU)
    hashed_pass = ldap_sha1.encrypt(raw_password)
    mod_attrs = {}
    mod_attrs['userPassword'] = [MODIFY_REPLACE, [hashed_pass, ]]

    try:
        conn = ldap_connect()
        conn.modify(dn, mod_attrs)
        return True
    except Exception:
        raise


def ldap_add_assurance(username, assurance):
    dn = "uid={username},{ou}".format(username=username, ou=settings.LDAP_PEOPLE_OU)
    mod_attrs = {'eduPersonAssurance': [MODIFY_ADD, assurance]}

    conn = ldap_connect()
    conn.modify(dn, mod_attrs)
    return True


def ldap_remove_assurance(username, assurance):
    dn = "uid={username},{ou}".format(username=username, ou=settings.LDAP_PEOPLE_OU)
    mod_attrs = {'eduPersonAssurance': [MODIFY_DELETE, assurance]}

    conn = ldap_connect()
    conn.modify(dn, mod_attrs)
    return True


def replace_user_entitlements(username, entitlements):
    '''
    Takes a username and a simple list of the "uid"s of entitlements,
    then replaces all existing entitlements with the new set. Entitlements need
    to be stored in this bytestring format:

    'urn:mace:cca.edu:entitlement:horde'
    '''

    new_entitlements = []
    for ent in entitlements:
        ent = 'urn:mace:cca.edu:entitlement:{ent}'.format(ent=ent)
        new_entitlements.append(ent)

    dn = "uid={user},{ou}".format(user=username, ou=settings.LDAP_PEOPLE_OU)

    mod_attrs = {}
    mod_attrs['eduPersonEntitlement'] = [MODIFY_REPLACE, new_entitlements]

    try:
        conn = ldap_connect()
        conn.modify(dn, mod_attrs)
        return True
    except Exception:
        raise


def ldap_get_next_gidNumber():
    '''
    Parse output of get_all_groups to determine next group ID
    Dirapp group IDs are between 2000 & 4000
    '''
    results = ldap_get_all_groups()
    newarr = []
    for r in results:
        if 'gidNumber' in r[1]:
            num = int(r[1]['gidNumber'][0])
            if num >= 2000 and num <= 4000:
                newarr.append(num)

    final = sorted(list(set(newarr)))  # Sorted set of unique vals

    # In case list is empty, start numbering at 2000
    # Otherwise get last element and add one to get our value
    if len(final) == 0:
        newnum = 2000
    else:
        newnum = final[-1] + 1

    return newnum


def ldap_get_all_groups():
    '''Get all LDAP groups'''

    try:
        conn = ldap_connect()
        dn = settings.LDAP_GROUPS_OU
        results = conn.search(dn, search_scope=SUBTREE)
    except Exception:
        raise
    finally:
        conn.unbind()

    return results


def ldap_search(search_type, q):
    '''Search the directory by string (username, first, last names)'''

    if search_type == "username":
        filter = '(uid={q}*)'.format(q=q)

    if search_type == "fname":
        filter = '(givenName={q}*)'.format(q=q)

    if search_type == "lname":
        filter = '(sn={q}*)'.format(q=q)

    if search_type == "wdid":
        filter = '(ccaWorkdayNumber={q})'.format(q=q)

    if search_type == "id":
        filter = '(ccaEmployeeNumber={q}*)'.format(q=q)

    try:
        conn = ldap_connect()
        dn = settings.LDAP_PEOPLE_OU
        results = conn.search(dn, search_scope=SUBTREE, search_filter=filter)
    except Exception:
        raise
    finally:
        conn.unbind()

    return results


def ldap_user_has_group(username):
    '''
    Given a username, check if this user has group info in LDAP
    '''

    filter = "(uid={user})".format(user=username)
    try:
        conn = ldap_connect()
        attributes = ['memberOf']
        results = conn.search(settings.LDAP_BASE_DN, filter, attributes=attributes)
    except Exception:
        raise
    finally:
        conn.unbind()

    return True if results else False
