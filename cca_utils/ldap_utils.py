from random import randint
import ldap
import time
import random
import string
from passlib.hash import ldap_sha1
import ldap.modlist as modlist

from django.conf import settings
# import test_settings as settings
# from cca_utils import cca_test_settings as settings


def ldap_connect(modify=None):
    '''
    Returns an LDAP connection object, to be used by various search functions.
    We use different credentials depending on whether we're reading or writing -
    pass in `modify=True` to use the writable connection.
    '''

    if modify:
        ldap_auth_dn = settings.LDAP_AUTH_MODIFY_DN
        ldap_pass = settings.LDAP_MODIFY_PASS
    else:
        ldap_auth_dn = settings.LDAP_AUTH_SEARCH_DN
        ldap_pass = settings.LDAP_SEARCH_PASS

    try:
        conn = ldap.initialize(settings.LDAP_SERVER)
        conn.simple_bind_s(ldap_auth_dn, ldap_pass)

        return conn

    except ldap.SERVER_DOWN:
        print("Connection to LDAP server failed")
        raise


def ldap_get_user_data(username=None, sid=None, uidnumber=None, wdid=None, dn_only=None, full=None):
        '''
        Given a username or student ID, returns base LDAP data for a user.
        Pass sid=1234567 to retrieve by datatel ID rather than username.
        Pass uidnumber=1234567 to retrieve by LDAP uidNumber.
        Pass wdid=1234567 to retrieve by Workday ID.
        Pass dn_only=True to retrieve just the user's DN.
        Pass full=True to retrieve both the DN and
        '''

        conn = ldap_connect()

        if sid:
            filter = "(ccaEmployeeNumber={sid})".format(sid=sid)
        elif uidnumber:
            filter = "(uidnumber={uidnumber})".format(uidnumber=uidnumber)
        elif wdid:
            filter = "(ccaWorkdayNumber={wdid})".format(wdid=wdid)
        else:
            filter = "(uid={user})".format(user=username)

        try:
            results = conn.search_s(settings.LDAP_BASE_DN, ldap.SCOPE_SUBTREE, filter)
            # `results` is a tuple.
            # First element is the user DN, 2nd is a dict of their data,
            # which can be accessed via e.g.:
            # data['displayName'], data['ccaEmployeeNumber'], data['loginShell']
            if results:
                if dn_only and not full:
                    return results[0][0]
                elif full:
                    return results[0]
                else:
                    return results[0][1]
            else:
                return False

        except:
            raise


def ldap_get_all_users():
    '''Get all LDAP users as single giant dict. Useful for import scripts.'''

    conn = ldap_connect()

    try:
        dn = settings.LDAP_PEOPLE_OU
        results = conn.search_s(dn, ldap.SCOPE_SUBTREE)
        conn.unbind_s()
        return results
    except:
        raise


def ldap_get_all_groups():
    '''Get all LDAP groups'''

    conn = ldap_connect()

    try:
        dn = settings.LDAP_GROUPS_OU
        results = conn.search_s(dn, ldap.SCOPE_SUBTREE)
        conn.unbind_s()
        return results
    except:
        raise


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

    conn = ldap_connect()

    try:
        dn = settings.LDAP_PEOPLE_OU
        results = conn.search_s(dn, ldap.SCOPE_SUBTREE, filter)
        conn.unbind_s()
        return results
    except:
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


def ldap_generate_uidnumber():
    '''
    uidNumber is required by LDAP, though CCA doesn't use it for anything.
    LDAP has no auto-increment capability. Rather than go through all records
    and try to determine next ID, we set the uidNumber to something that's
    randomly chosen but available.

    Datatel starts numbering at 1000000; this func starts at 2000000 to distinguish.
    '''

    num = randint(2000000, 9999999)

    if not ldap_get_user_data(uidnumber=num):
        return num

    # If we're still here, that uidNumber already exists in LDAP; keep trying.
    while ldap_get_user_data(uidnumber=num):
        num = randint(2000000, 9999999)

    return num


def ldap_get_group(val):
    '''
    Get a single LDAP group.
    If val is alpha, get group by cn. Otherwise get by gidNumber.
    '''

    # LDAP only allows searching by string, not integer
    val = str(val)

    # Does val start with a digit? Then it's an ID
    if val[0].isalpha():
        dn = "cn={val},{ou}".format(val=val, ou=settings.LDAP_GROUPS_OU)
    else:
        dn = "gidNumber={val},{ou}".format(val=val, ou=settings.LDAP_GROUPS_OU)

    conn = ldap_connect()
    try:
        results = conn.search_s(dn, ldap.SCOPE_SUBTREE)
        return results
    except:
        return False


def ldap_add_members_to_group(groupcn, new_members):
    '''
    groupcn is the 'cn' attribute of an LDAP group (as string)
    new_members is a python list of username strings to add to that group.
    Returns True or False.
    '''

    groupdn = "cn={groupcn},{ou}".format(groupcn=groupcn, ou=settings.LDAP_GROUPS_OU)
    mod_attrs = []

    # Make sure there's something in the list to process
    if len(new_members) > 0:
        for person in new_members:

            # Verify user exists in LDAP before adding to group,
            # then build up the list of tuples LDAP expects.
            if ldap_get_user_data(person):
                mod_attrs.append((ldap.MOD_ADD, 'memberUid', [person.encode('utf-8')]))

        # Now batch-add all new users
        conn = ldap_connect(modify=True)
        try:
            conn.modify_s(groupdn, mod_attrs)
            return True
        except:
            # In most cases a failure here is because there's an orphaned user already
            # in the group we're trying to add to.
            return False


def ldap_remove_members_from_group(groupcn, remove_members):
    '''
    groupcn is the 'cn' attribute of an LDAP group (as string)
    new_members is a python list of username strings to add to that group.
    Returns True or False.
    '''

    groupdn = "cn={groupcn},{ou}".format(groupcn=groupcn, ou=settings.LDAP_GROUPS_OU)
    mod_attrs = []
    if len(remove_members) > 0:
        for person in remove_members:
            # Build up a list of tuples, which LDAP expects
            mod_attrs.append((ldap.MOD_DELETE, 'memberUid', [person.encode('utf-8')]))

        conn = ldap_connect(modify=True)
        try:
            conn.modify_s(groupdn, mod_attrs)
            return True
        except:
            raise


def ldap_create_group(groupcn, description, displayName):
    '''
    groupcn is the 'cn' attribute of an LDAP group (as string).
    description is brief description of group.
    Returns True or False.
    '''

    # Increment group number
    gidNumber = ldap_get_next_gidNumber()

    groupdn = "cn={groupcn},{ou}".format(groupcn=groupcn, ou=settings.LDAP_GROUPS_OU)
    mod_attrs = {}
    mod_attrs['objectclass'] = ['top'.encode('utf-8'), 'posixGroup'.encode('utf-8')]
    mod_attrs['cn'] = groupcn.encode('utf-8')
    mod_attrs['gidNumber'] = str(gidNumber).encode('utf-8')
    mod_attrs['description'] = description.encode('utf-8')

    ldif = modlist.addModlist(mod_attrs)
    conn = ldap_connect(modify=True)
    try:
        conn.add_s(groupdn, ldif)
        return True
    except:
        raise


def ldap_delete_group(groupcn):
    '''
    Delete a group and all of its members.
    groupcn is the 'cn' attribute of an LDAP group (as string).
    '''

    groupdn = "cn={groupcn},{ou}".format(groupcn=groupcn, ou=settings.LDAP_GROUPS_OU)
    conn = ldap_connect(modify=True)

    try:
        conn.delete(groupdn)
        return True
    except:
        print("failed to delete group")
        raise


def ldap_enable_disable_acct(username, action):
    '''
    An account is considered enabled or disabled by presence of ccaActivateTime or
    ccaDisableTime properties, with epoch as value. It's not logical to have both at once,
    so always scrub one when setting the other.
    '''

    epoch_time = str(int(time.time())).encode('utf-8')
    dn = "uid={user},{ou}".format(user=username, ou=settings.LDAP_PEOPLE_OU)
    mod_attrs = []

    if action == "enable":
        mod_attrs.append((ldap.MOD_REPLACE, 'ccaActivateTime', [epoch_time, ]))
        mod_attrs.append((ldap.MOD_REPLACE, 'ccaDisableTime', None))

    if action == "disable":
        mod_attrs.append((ldap.MOD_REPLACE, 'ccaDisableTime', [epoch_time, ]))
        mod_attrs.append((ldap.MOD_REPLACE, 'ccaActivateTime', None))

        # Set random long password on disabled account
        randpass = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(24))
        ldap_change_password(username, randpass)

    conn = ldap_connect(modify=True)
    try:
        conn.modify_s(dn, mod_attrs)
        return True
    except:
        raise


def ldap_rename_acct(oldusername, newusername):
    '''
    Rename an LDAP account from oldusername to newusername.
    '''

    dn = "uid={user},{ou}".format(user=oldusername, ou=settings.LDAP_PEOPLE_OU)
    newrdn = "uid={user}".format(user=newusername)

    conn = ldap_connect(modify=True)
    try:
        conn.rename_s(dn, newrdn, delold=1)
        return True
    except:
        raise


def get_all_entitlements():
    '''
    Retrieve set of all possible user entitlements from LDAP.
    '''
    conn = ldap_connect()

    try:
        # This DN is distinct from the main search and modify DNs
        dn = "ou=administrators,ou=TopologyManagement,o=NetscapeRoot"
        filter = '(objectclass=*)'
        unsorted_results = conn.search_ext_s(dn, ldap.SCOPE_ONELEVEL, filter, ["uid", "givenName", ])
        results = sorted(unsorted_results)  # Alphabetize for display
        conn.unbind_s()

        return results
    except:
        raise


def get_user_entitlements(username):
    '''
    Retrieve set of LDAP entitlements for a single user. They're already present
    in the raw LDAP record for a user, so this just pulls them out and packs them
    up as a list of uid strings.

    e.g. On user's main record:
    'eduPersonEntitlement': [b'urn:mace:cca.edu:entitlement:samba',
                             b'urn:mace:cca.edu:entitlement:idengines',
                             b'urn:mace:cca.edu:entitlement:webadvisor',
                             b'urn:mace:cca.edu:entitlement:horde'],


    We return:
    results = ['samba', 'idengines', 'webadvisor', 'horde']
    '''

    data = ldap_get_user_data(username)
    if 'eduPersonEntitlement' in data:
        entitlements = data['eduPersonEntitlement']
    else:
        entitlements = []

    results = []
    for ent in entitlements:
        # Decode from LDAP's bytestrings so we can split string. Get last element.
        uid = ent.decode('utf-8').split(':')[-1]
        # Now cast the result *back* to utf-8 so we end up with a list of normal strings.
        results.append(uid.encode('utf-8'))
    return results


def replace_user_entitlements(username, entitlements):
    '''
    Takes a username and a simple list of the "uid"s of entitlements,
    then replaces all existing entitlements with the new set. Entitlements need
    to be stored in this bytestring format:

    b'urn:mace:cca.edu:entitlement:horde'
    '''

    new_entitlements = []
    for ent in entitlements:
        ent = 'urn:mace:cca.edu:entitlement:{ent}'.format(ent=ent).encode('utf-8')
        new_entitlements.append(ent)

    dn = "uid={user},{ou}".format(user=username, ou=settings.LDAP_PEOPLE_OU)

    mod_attrs = []
    mod_attrs.append((ldap.MOD_REPLACE, 'eduPersonEntitlement', new_entitlements))

    try:
        conn = ldap_connect(modify=True)
        conn.modify_s(dn, mod_attrs)
        return True
    except:
        raise


def get_email_aliases(username):
    '''
    Retrieve user's email aliases from raw ldap record, return as list.
    '''
    data = ldap_get_user_data(username)
    if 'mail' in data:
        aliases = data['mail']
    else:
        aliases = []

    results = []
    for addr in aliases:
        # Cast back to utf-8 so we end up with a list of normal strings.
        results.append(addr.decode('utf-8'))
    return results


def replace_email_aliases(username, aliases):
    '''
    Takes a [list] of validated emails and updates user LDAP record.
    '''

    new_aliases = []
    for addr in aliases:
        addr = addr.encode('utf-8')
        new_aliases.append(addr)

    dn = "uid={user},{ou}".format(user=username, ou=settings.LDAP_PEOPLE_OU)

    mod_attrs = []
    mod_attrs.append((ldap.MOD_REPLACE, 'mail', new_aliases))

    conn = ldap_connect(modify=True)
    try:
        conn.modify_s(dn, mod_attrs)
        return True
    except:
        raise


def ldap_generate_username(first, last):
    '''
    Given a first and last name, generate a standard username
    '''
    # Strip spaces from first and last
    first = first.replace(' ', '')
    last = last.replace(' ', '')

    username = "{initial}{last}".format(initial=first[:1], last=last).lower()
    return username


def ldap_iterate_username(desired_username):
    '''
    Increment digits onto an LDAP username that already exists until an available one is found.
    If desired_username does not exist, we shouldn't be incrementing - return same.
    '''

    if not ldap_get_user_data(desired_username):
        return desired_username

    counter = 1
    while ldap_get_user_data(desired_username):
        desired_username = "{desired_username}{counter}".format(desired_username=desired_username, counter=counter)
        counter += 1

    return desired_username


def ldap_delete_user(username):
    '''
    Delete a User record if possible.
    '''

    conn = ldap_connect(modify=True)
    try:
        dn = "uid={user},{ou}".format(user=username, ou=settings.LDAP_PEOPLE_OU)
        conn = ldap_connect(modify=True)
        conn.delete_s(dn)
        return True
    except:
        raise


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

    attrs = {}
    attrs['objectclass'] = [
        'top'.encode('utf8'),
        'person'.encode('utf8'),
        'organizationalPerson'.encode('utf8'),
        'inetOrgPerson'.encode('utf8'),
        'eduPerson'.encode('utf8'),
        'account'.encode('utf8'),
        'posixAccount'.encode('utf8'),
        'shadowAccount'.encode('utf8'),
        'sambaSAMAccount'.encode('utf8'),
        'passwordObject'.encode('utf8'),
        'ccaPerson'.encode('utf8'),
        ]
    attrs['sn'] = lname.encode('utf8')
    attrs['cn'] = fname.encode('utf8')
    attrs['displayName'] = '{first} {last}'.format(first=fname, last=lname).encode('utf8')
    attrs['userPassword'] = '{passwd}'.format(passwd=hashed_pass.encode('utf8')),
    attrs['uid'] = uid.encode('utf8')
    attrs['givenName'] = fname.encode('utf8')
    attrs['ccaBirthDate'] = bday_string.encode('utf8')
    attrs['homeDirectory'] = '/Users/{username}'.format(username=uid).encode('utf8')
    attrs['uidNumber'] = str(ldap_generate_uidnumber()).encode('utf8')
    attrs['gidNumber'] = str(20).encode('utf8')
    attrs['ccaWorkdayNumber'] = str(wdid).encode('utf8')
    attrs['ccaEmployeeNumber'] = str(cca_id).encode('utf8')
    attrs['sambaSID'] = 'placeholder'.encode('utf8')  # We don't use this value but it must be present.
    attrs['mail'] = email.encode('utf8')

    # Attempt to insert new LDAP user
    try:
        dn = "uid={username},{ou}".format(username=uid, ou=settings.LDAP_PEOPLE_OU)
        ldif = modlist.addModlist(attrs)
        conn = ldap_connect(modify=True)
        conn.add_s(dn, ldif)
        conn.unbind_s()
        ldap_enable_disable_acct(uid, "enable")  # Set their account activation timestamp
        return True
    except:
        raise


def ldap_change_password(username, raw_password):
    dn = "uid={username},{ou}".format(username=username, ou=settings.LDAP_PEOPLE_OU)
    conn = ldap_connect(modify=True)
    hashed_pass = ldap_sha1.encrypt(raw_password)
    mod_attrs = [(ldap.MOD_REPLACE, 'userPassword', [hashed_pass])]

    try:
        conn.modify_s(dn, mod_attrs)
        return True
    except:
        raise
