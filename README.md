# cca_utils

Re-usable python functions for decoupled interactions with various LDAP and Google functions, services and APIs. It is unlikely these will work for you as-is; contributions welcome.

Currently assuming Python 2 due to slow migration of some external dependencies.

Some functions make full or partial assumptions about organization-specific LDAP fields (look for string 'cca' to locate them).

### LDAP function list

```
get_all_entitlements
get_email_aliases
get_user_entitlements
ldap_add_members_to_group
ldap_change_password
ldap_connect
ldap_create_group
ldap_create_user
ldap_delete_group
ldap_delete_user
ldap_enable_disable_acct
ldap_generate_uidnumber
ldap_generate_username
ldap_get_all_groups
ldap_get_all_users
ldap_get_group
ldap_get_next_gidNumber
ldap_get_user_data
ldap_iterate_username
ldap_remove_members_from_group
ldap_search
replace_email_aliases
replace_user_entitlements
```

### Google function list

```
google_create_user
google_get_auth
google_get_emailsettings_credentials
google_get_user
google_remove_user
google_set_aliases
google_update_user
```


## Dependencies
(most likely found in the `requirements.txt` of a parent Django project):

```
google-api-python-client
PyOpenSSL
gdata
beautifulsoup4
passlib
```

## Settings

Assumed to be established in your Django or Flask project:

```
LDAP_BASE_DN = 'dc=cca,dc=edu'
LDAP_PEOPLE_OU = 'ou=People,dc=cca,dc=edu'
LDAP_GROUPS_OU = 'ou=Groups,dc=cca,dc=edu'
LDAP_SERVER = 'ldap://directory.yourdomain.org'
LDAP_AUTH_SEARCH_DN = 'uid=search,ou=Administrators,ou=TopologyManagement,o=NetscapeRoot'
LDAP_AUTH_MODIFY_DN = 'cn=Directory Manager'
LDAP_SEARCH_PASS = 'the_search_pass'
LDAP_MODIFY_PASS = 'record_modification_pass'

GOOGLE_DOMAIN = 'yourdomain.org'
GOOGLE_CLIENT_EMAIL = '12345678-abc23@developer.gserviceaccount.com'
GOOGLE_PATH_TO_KEYFILE = "/full/path/to/our_key_file.p12"
GOOGLE_CLIENT_SECRET = 'abc123'
GOOGLE_SUB_USER = 'someone@yourdomain.org'  # Email of a superuser on your domain
GOOGLE_APPLICATION_NAME = 'our-project-name'  # As listed in Google Developers Console
```

## Tests

This library is intended to be used either with or without a Django project. However, it depends on a lot of settings (above), typically associated with Django. If you are working with it outside of Django or want to run the tests standalone, create a `cca_utils/test_settings.py` file and change this line in `ldap_utils.py`:

```
# from django.conf import settings
import test_settings as settings
```

To run all tests:

```nosetests```

To run a single test:

```nosetests tests:TestClass.test_add_members_to_group```

To prevent print debug print statements from being swallowed:

```nosetests -s ....```

