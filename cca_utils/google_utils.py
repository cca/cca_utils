from django.conf import settings

# Google python client library
from oauth2client.client import SignedJwtAssertionCredentials
from gdata.apps.emailsettings.client import EmailSettingsClient
from apiclient.discovery import build
from httplib2 import Http

# gdata is deprecated and won't be updated. Used here only for the EmailSettings API,
# which is an outlier and not yet updated to newer Google OAuth2. This will cause
# problems for Python3 users.
import gdata


def google_get_auth(scope=None):
    '''
    Get http authorization object for a given scope, passed in as a string,
    e.g. (from another function):

    http_auth = google_get_auth(scope='https://www.googleapis.com/auth/admin.directory.user')
    service = build("admin", "directory_v1", http=http_auth)
    '''

    client_email = settings.GOOGLE_CLIENT_EMAIL
    with open(settings.GOOGLE_PATH_TO_KEYFILE) as f:
        private_key = f.read()

    credentials = SignedJwtAssertionCredentials(client_email, private_key, scope=scope,
                                                sub=settings.GOOGLE_SUB_USER)
    http_auth = credentials.authorize(Http())
    return http_auth


def google_get_emailsettings_credentials():
    '''
    Google's EmailSettings API is not yet service-based, so delegation data
    has to be accessed differently from our other Google functions.
    TODO: Refactor when API is updated.
    '''

    with open(settings.GOOGLE_PATH_TO_KEYFILE) as f:
        private_key = f.read()

    client = EmailSettingsClient(domain=settings.GOOGLE_DOMAIN)
    credentials = SignedJwtAssertionCredentials(
        settings.GOOGLE_CLIENT_EMAIL,
        private_key,
        scope='https://apps-apis.google.com/a/feeds/emailsettings/2.0/',
        sub=settings.GOOGLE_SUB_USER)
    auth2token = gdata.gauth.OAuth2TokenFromCredentials(credentials)
    auth2token.authorize(client)

    return client


def google_update_user(request, username, data):
    '''
    Updates arbitrary fields on a Google Directory user entry. Takes `data` as
    a python data structure conforming to schema at http://bit.ly/1DzJS8P

    e.g. (in another function):
        hashed = hashlib.md5("foobar123").hexdigest()
        data = {'hashFunction': 'MD5', 'password': hashed}
        google_update_user(request, 'msmith', data)
    '''

    try:
        http_auth = google_get_auth(scope='https://www.googleapis.com/auth/admin.directory.user')
        service = build("admin", "directory_v1", http=http_auth)
        service.users().update(userKey="{u}@{d}".format(u=username, d=settings.GOOGLE_DOMAIN), body=data).execute()
        return True
    except:
        return False


def google_create_user(person_data):
    '''
    Creates a new person entry (email addr) in the Google Directory.
    Takes `person_data` as a python dict. e.g. (in another function):

        password = form.cleaned_data['password']
        hashed = hashlib.md5(password).hexdigest()

        person_data = {
            "name": {
                "familyName": lname,
                "givenName": fname
            },
            "hashFunction": 'MD5',
            "password": hashed,
            "primaryEmail": email
        }
        google_create_user(request, person_data)
    '''

    try:
        http_auth = google_get_auth(scope='https://www.googleapis.com/auth/admin.directory.user')
        service = build("admin", "directory_v1", http=http_auth)
        service.users().insert(body=person_data).execute()
        return True
    except:
        return False


def google_get_user(username):
    '''
    Get a user from the Google directory.
    Given a username, returns the user object or False.
    '''

    try:
        http_auth = google_get_auth(scope='https://www.googleapis.com/auth/admin.directory.user')
        service = build("admin", "directory_v1", http=http_auth)
        user_obj = service.users().get(userKey="{u}@{d}".format(u=username, d=settings.GOOGLE_DOMAIN)).execute()
        return user_obj
    except:
        return False


def google_remove_user(username):
    '''
    Deletes a person entry (email addr) in the Google Directory.
    Takes a username.
    '''

    try:
        http_auth = google_get_auth(scope='https://www.googleapis.com/auth/admin.directory.user')
        service = build("admin", "directory_v1", http=http_auth)
        service.users().delete(userKey="{u}@{d}".format(u=username, d=settings.GOOGLE_DOMAIN)).execute()
        return True
    except:
        return False


def google_set_aliases(request, username, aliases):
    '''
    Resets the list of email aliases for a user in the Google directory.
    To ensure that LDAP is canonical, we first delete all Google aliases,
    then insert the new list. Takes `aliases` as a python list of valid emails.

    e.g. (in another function):
        aliases = ['foo@cca.edu', 'bar@cca.edu']
        google_set_aliases(request, 'msmith', aliases)

    '''
    try:
        http_auth = google_get_auth(scope='https://www.googleapis.com/auth/admin.directory.user.alias')
        service = build("admin", "directory_v1", http=http_auth)

        # Get the user's complete set of Google-stored aliases.
        google_aliases = service.users().aliases().list(userKey="{u}@{d}".format(u=username, d=settings.GOOGLE_DOMAIN)).execute()

        # If returned set is non-empty, delete them all.
        if 'aliases' in google_aliases:
            templist = [entry['alias'] for entry in google_aliases['aliases']]
            for alias in templist:
                service.users().aliases().delete(userKey="{u}@{d}".format(u=username, d=settings.GOOGLE_DOMAIN), alias=alias).execute()

        # Now insert new aliases. Google automatically drops existing users so we don't have to check for conflicts.
        for alias in aliases:
            service.users().aliases().insert(userKey="{u}@{d}".format(u=username, d=settings.GOOGLE_DOMAIN), body={'alias': alias}).execute()

        return True
    except:
        return False
