from nose.tools import assert_equal, assert_not_equal

import ldap
from cca_utils import cca_test_settings

from cca_utils.ldap_utils import (
    get_all_entitlements, get_user_entitlements, ldap_add_members_to_group,
    ldap_change_password, ldap_create_group, ldap_create_user, ldap_delete_group,
    ldap_delete_user, ldap_enable_disable_acct, ldap_generate_uidnumber, ldap_generate_username,
    ldap_get_all_groups, ldap_get_all_users, ldap_get_group, ldap_get_next_gidNumber,
    ldap_get_user_data, ldap_iterate_username, ldap_remove_members_from_group, ldap_search,
    get_email_aliases, replace_email_aliases, replace_user_entitlements
    )


class TestClass:
    def setUp(self):
        self.ldap_username = 'qminix'
        self.pre_existing_group = 'zabbix'  # Real group - do not delete!
        self.pre_existing_entitlement = 'horde'  # Real entitlement - do not delete!

        # Create a simple LDAP user for testing.
        kwargs = {
            "uid": self.ldap_username,
            "fname": "Quillen",
            "lname": "Minix",
            "email": "a@b.com",
            "password": "s8jdf_6H2hs7",
            "employeenum": "7000533",
            "wdid": "555555",
            "birthdate": "1979-04-14",
            "campus": "Oakland",
            }
        try:
            ldap_create_user(**kwargs)
        except:
            pass

        # Create a group
        self.group_cn = 'unit_test_group'
        self.group_description = "Delete this group"
        self.group_display_name = "Delete this group"

        try:
            ldap_create_group(self.group_cn, self.group_description, self.group_display_name)
        except:
            pass

    def tearDown(self):
        try:
            ldap_delete_user('qminix')
        except:
            pass

        try:
            ldap_delete_group(self.group_cn)
        except:
            pass

    # =================
    # Begin tests. n.b.: Create/delete user & group are partially covered in the setup and teardown above.
    # =================

    def test_can_get_ldap_user(self):
        # Many of our functions return either the object or an exception, so we can't compare to True
        get_user = ldap_get_user_data(self.ldap_username)
        assert_not_equal(get_user, False)

    def test_get_group(self):
        get_group = ldap_get_group(self.group_cn)
        assert_not_equal(get_group, False)

    def test_add_remove_members_to_group(self):
        # ldap_get_group returns a deeply nested list.
        # For simplicity, just cast whole thing to
        # a string and see if qminix is/not in it.

        ldap_add_members_to_group(self.group_cn, [self.ldap_username, ])
        group = ldap_get_group(self.group_cn)
        assert_equal(self.ldap_username in str(group), True)

        # Now remove the user and verify gone
        ldap_remove_members_from_group(self.group_cn, [self.ldap_username, ])
        group = ldap_get_group(self.group_cn)
        assert_equal(self.ldap_username in str(group), False)

    def test_create_and_delete_group(self):
        creator = ldap_create_group("fizzy", self.group_description, self.group_display_name)
        assert_equal(creator, True)

        destroyer = ldap_delete_group("fizzy")
        assert_equal(destroyer, True)

    def test_process_entitlements(self):
        # Add and remove entitlements for a user
        replace_user_entitlements(self.ldap_username, cca_test_settings.LDAP_DEFAULT_ENTITLEMENTS)
        entitlements = get_user_entitlements(self.ldap_username)
        assert_equal('webadvisor' in str(entitlements), True)

        replace_user_entitlements(self.ldap_username, [])
        entitlements = get_user_entitlements(self.ldap_username)
        assert_equal('webadvisor' in str(entitlements), False)

    def test_get_all_groups(self):
        allgroups = ldap_get_all_groups()
        results = []
        for g in allgroups:
            if 'cn' in g[1]:
                results.append(g)
        assert_equal(self.pre_existing_group in str(results), True)
        assert_equal(len(results) > 50, True)

    def test_enable_disable_LDAP_acct(self):
        # Disable, then enable account

        ldap_enable_disable_acct(self.ldap_username, "disable")
        user = ldap_get_user_data(self.ldap_username)
        # User is a dict, and it should include the property 'ccaDisableTime'
        assert_equal('ccaDisableTime' in user, True)
        assert_equal('ccaActivateTime' in user, False)

        ldap_enable_disable_acct(self.ldap_username, "enable")
        user = ldap_get_user_data(self.ldap_username)
        assert_equal('ccaDisableTime' in user, False)
        assert_equal('ccaActivateTime' in user, True)

    def test_retrieve_all_entitlements(self):
        all_entitlements = get_all_entitlements()
        assert_equal(self.pre_existing_entitlement in str(all_entitlements), True)

    def test_process_aliases(self):
        # Add and remove email aliases (LDAP only) for user
        replace_email_aliases(self.ldap_username, ['foo@cca.edu', 'bar@cca.edu'])
        aliases = get_email_aliases(self.ldap_username)
        assert_equal('foo@cca.edu' in str(aliases), True)

        replace_email_aliases(self.ldap_username, ['bar@cca.edu'])
        aliases = get_email_aliases(self.ldap_username)
        assert_equal('foo@cca.edu' in str(aliases), False)

    def test_change_password(self):
        # Change password for user then try to log in as them

        newpass = "kljsd834ljdlk_6sjf"
        ldap_change_password(self.ldap_username, newpass)

        # Attempt to connect to LDAP with the new credentials.
        # A good LDAP login will return a tuple, like (97, [], 1, [])
        # A bad connection raises an exception, which is not a tuple.
        server = cca_test_settings.LDAP_SERVER
        user_dn = "uid={user},ou=People,dc=cca,dc=edu".format(user=self.ldap_username)
        conn = ldap.initialize(server)
        result = conn.simple_bind_s(user_dn, newpass)
        assert_equal(type(result), tuple)
        conn.unbind_s()

    def test_random_id_generation(self):
        # Should be greater than 2000000 and less than 9000000
        random_id = ldap_generate_uidnumber()
        assert_equal(2000000 < random_id < 9000000, True)

    def test_username_generator(self):
        username = ldap_generate_username('Zippy', "Starbuck")
        assert_equal(username, 'zstarbuck')
