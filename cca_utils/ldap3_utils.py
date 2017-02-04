import random
import string
import time

from ldap3 import (
    Server, Connection, ALL, SUBTREE,
    MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, ALL_ATTRIBUTES
    )

from passlib.hash import ldap_sha1
from django.conf import settings

##########
# TODO: remove all instances of encode('utf8') and decode
##########


def ldap_connect():
    '''
    Returns an LDAP connection object, to be used by various search functions.
    We use different credentials depending on whether we're reading or writing -
    pass in `` to use the writable connection.
    '''

    try:
        server = Server(settings.LDAP_SERVER, port=389, get_info=ALL)
        conn = Connection(
            server,
            user=settings.LDAP_AUTH_SEARCH_DN,
            password=settings.LDAP_MODIFY_PASS,
            raise_exceptions=True)
        # conn = Connection(
        #     server, authentication=AUTH_SIMPLE, user=settings.LDAP_AUTH_SEARCH_DN,
        #     password=settings.LDAP_MODIFY_PASS, check_names=True, lazy=False,
        #     client_strategy=STRATEGY_SYNC, raise_exceptions=True
        #     )

        conn.bind()
        return conn

    except:
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
            attributes = ['sn', 'givenName', 'uid', 'mail', 'ccaEmployeeNumber', 'ccaWorkdayNumber', 'ccaBirthDate']
            results = conn.search(settings.LDAP_BASE_DN, filter, attributes=ALL_ATTRIBUTES)
            print(conn)
            if results:
                entries = conn.entries[0]
                return entries
            else:
                return None

        except:
            raise


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
        results = conn.search_s(dn, SUBTREE)
        return results
    except:
        return False


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
    except:
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
    except:
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
        except:
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
        except:
            # In most cases a failure here is because there's an orphaned user already
            # in the group we're trying to add to.
            raise


def ldap_create_group(groupcn, description, displayName):
    '''
    groupcn is the 'cn' attribute of an LDAP group (as string).
    description is brief description of group.
    Returns True or False.
    '''

    # Increment group number
    # gidNumber = ldap_get_next_gidNumber()

    groupdn = "cn={groupcn},{ou}".format(groupcn=groupcn, ou=settings.LDAP_GROUPS_OU)
    mod_attrs = {}
    mod_attrs['objectclass'] = ['top'.encode('utf-8'), 'groupofnames'.encode('utf-8')]
    mod_attrs['cn'] = groupcn.encode('utf-8')
    mod_attrs['description'] = description.encode('utf-8')

    # ldif = modlist.addModlist(mod_attrs)
    conn = ldap_connect()
    try:
        conn.add_s(groupdn, mod_attrs)
        return True
    except:
        raise


def ldap_delete_group(groupcn):
    '''
    Delete a group and all of its members.
    groupcn is the 'cn' attribute of an LDAP group (as string).
    '''

    groupdn = "cn={groupcn},{ou}".format(groupcn=groupcn, ou=settings.LDAP_GROUPS_OU)
    conn = ldap_connect()

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
    except:
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
    except:
        raise


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
        results = conn.search_s(dn, SUBTREE, filter)
        conn.unbind_s()
        return results
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
        # unsorted_results = conn.search_ext_s(dn, ldap.SCOPE_ONELEVEL, filter, ["uid", "givenName", ])
        unsorted_results = conn.search_ext_s(dn, SUBTREE, filter, ["uid", "givenName", ])
        results = sorted(unsorted_results)  # Alphabetize for display
        conn.unbind_s()

        return results
    except:
        raise


def ldap_rename_acct(oldusername, newusername):
    '''
    Rename an LDAP account from oldusername to newusername.
    '''

    dn = "uid={user},{ou}".format(user=oldusername, ou=settings.LDAP_PEOPLE_OU)
    newrdn = "uid={user}".format(user=newusername)
    newemail = "{u}@cca.edu".format(u=newusername)

    conn = ldap_connect(modify=True)
    try:
        # Update the 'mail' field on the record *first*, then rename the account;
        # otherwise the dn object changes out from under us.
        mod_attrs = [
            (MODIFY_REPLACE, 'mail', [newemail.encode('utf8')]),
        ]
        conn.modify_s(dn, mod_attrs)

        # Rename the account itself
        conn.rename_s(dn, newrdn, delold=1)

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
    mod_attrs.append((MODIFY_REPLACE, 'mail', new_aliases))

    conn = ldap_connect(modify=True)
    try:
        conn.modify_s(dn, mod_attrs)
        return True
    except:
        raise


def convert_group_member_uid(ldapgroup):
    '''
    Takes the LDAP group member string (full LDAP DN) and returns a list of UIDs
    '''
    current_members = ldapgroup[0][1]['member']
    current_members_uid = []
    for person in current_members:
        user = (person.replace("uid=", "").replace(",ou=People,dc=cca,dc=edu", ""))
        current_members_uid.append(user)
    return current_members_uid
