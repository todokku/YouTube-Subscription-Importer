import os
import sys
import xml.etree.ElementTree as ET

import httplib2
from apiclient.discovery import build
from apiclient.errors import HttpError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import argparser, run_flow

# The CLIENT_SECRETS_FILE variable specifies the name of a file that contains
# the OAuth 2.0 information for this application, including its client_id and
# client_secret. You can acquire an OAuth 2.0 client ID and client secret from
# the {{ Google Cloud Console }} at
# {{ https://cloud.google.com/console }}.
# Please ensure that you have enabled the YouTube Data API for your project.
# For more information about using OAuth2 to access the YouTube Data API, see:
#   https://developers.google.com/youtube/v3/guides/authentication
# For more information about the client_secrets.json file format, see:
#   https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
CLIENT_SECRETS_FILE = "client_secrets.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account.
YOUTUBE_READ_WRITE_SCOPE = "https://www.googleapis.com/auth/youtube"
YOUTUBE_API_SERVICE_NAME = "youtube"
YOUTUBE_API_VERSION = "v3"

# This variable defines a message to display if the CLIENT_SECRETS_FILE is
# missing.
MISSING_CLIENT_SECRETS_MESSAGE = """
WARNING: Please configure OAuth 2.0

To make this sample run you will need to populate the client_secrets.json file
found at:

   %s

with information from the {{ Cloud Console }}
{{ https://cloud.google.com/console }}

For more information about the client_secrets.json file format, please visit:
https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
""" % os.path.abspath(os.path.join(os.path.dirname(__file__),
                                   CLIENT_SECRETS_FILE))

# The amount of characters to remove from the start of the youtube URL
# Example:
# https://www.youtube.com/feeds/videos.xml?channel_id=UCfQDD-pbllOCXHYwiXxjJxA
# minus the default of 52, leaves us with just the chanel id
# UCfQDD-pbllOCXHYwiXxjJxA
START_OF_CHANNEL_ID = 52

# The name of the file used to store the already subscribed to chanell ids
STORED_CHANNEL_FILE_NAME = 'channels_subscribed.txt'

STORED_BANNED_CHANNEL_FILE_NAME = 'BANNED_channels_subscribed.txt'

TOTAL = 0

def get_authenticated_service(args):
    flow = flow_from_clientsecrets(CLIENT_SECRETS_FILE,
                                   scope=YOUTUBE_READ_WRITE_SCOPE,
                                   message=MISSING_CLIENT_SECRETS_MESSAGE)

    storage = Storage("%s-oauth2.json" % sys.argv[0])
    credentials = storage.get()

    if credentials is None or credentials.invalid:
        credentials = run_flow(flow, storage, args)

    return build(YOUTUBE_API_SERVICE_NAME, YOUTUBE_API_VERSION,
                 http=credentials.authorize(httplib2.Http()))


def get_channels_list():
    stored_file_txt = ''
    if os.path.exists(STORED_CHANNEL_FILE_NAME):
        with open(STORED_CHANNEL_FILE_NAME, mode='r', encoding='utf-8') as ids_file:
            stored_file_txt = ids_file.read()

    if os.path.exists(STORED_BANNED_CHANNEL_FILE_NAME):
        with open(STORED_BANNED_CHANNEL_FILE_NAME, mode='r', encoding='utf-8') as ids_file:
            banned_stored_file_txt = ids_file.read()


    # Parse the channel id's from the xml file
    xmldoc = ET.parse(args.xml)
    start = xmldoc.getroot()[0][0]

    channels = {}

    for child in start:
        channel_id = child.get('xmlUrl')[START_OF_CHANNEL_ID:]
        channel_name = child.get('title')
        print('Testing: %s.%s' % (channel_id, channel_name))

        if channel_id+"."+channel_name in banned_stored_file_txt:
            print('Banned channel: %s.%s\n' % (channel_id, channel_name))
            # channel_ids.append(channel_id)
        elif channel_id not in stored_file_txt:
            channels[channel_id] = channel_name
            # print('Adding channel: %s %s\n\n' % (channel_id, channel_name))
        else:
            print('Already added channel\n')
    global TOTAL
    TOTAL = len(channels)
    print('Total channels to import: %s' % TOTAL)
    return channels


# This method calls the API's youtube.subscriptions.insert method to add a
# subscription to the specified channel.
def add_subscription(youtube, channel_id):
    global TOTAL
    print(TOTAL)
    TOTAL -= 1

    add_subscription_response = youtube.subscriptions().insert(
        part='snippet',
        body=dict(
            snippet=dict(
                resourceId=dict(
                    channelId=channel_id,
                    kind="youtube#channel"
                )
            )
        )).execute()

    # When a subscription is added, add the channel id into a file
    # this file will be used to not subscribe to the same channel again
    with open(STORED_CHANNEL_FILE_NAME, mode='a+', encoding='utf-8') as ids_file:
        # Write info message for file if not already written
        if os.path.getsize(STORED_CHANNEL_FILE_NAME) == 0:
            ids_file.write(
                'This file is used to keep track of channels that have already been subscribed.' +
                '\nIf you would like to restart fresh or on a new account. Delete this file.\n\n'
            )
        # Write channel id to file
        ids_file.write('%s\n' % channel_id)

    return add_subscription_response["snippet"]["title"]


if __name__ == "__main__":
    argparser.add_argument('--xml', help='The full path to the XML file containing the subscriptions',
                           default='subscriptions.xml')
    args = argparser.parse_args()

    youtube = get_authenticated_service(args)

    channels = get_channels_list()
    # print(channels)
    # exit(0)

    # We have all channel ids, lets subscribe now
    for key, value in channels.items():
        try:
            print("Impoting: %s \n%s" % (key, value), end='\n')
            channel_title = add_subscription(youtube, key)

        except HttpError as e:
            error_domain = eval(e.content.decode(
                'utf-8'))['error']['errors'][0]['domain']
            reason = eval(e.content.decode(
                'utf-8'))['error']['errors'][0]['reason']
            code = eval(e.content.decode(
                'utf-8'))['error']['code']

            if error_domain == 'youtube.subscription' and reason == "subscriptionForbidden" or error_domain == 'youtube.quota':
                print('\nSubscription quota has been reached.\n' +
                      'All subscribed channels were saved to channels_subscribed.txt.\nTry again at a later time...')
                exit(0)
            elif code == 404 and reason == "publisherNotFound":
                # print(e.content.decode('utf-8'))
                print("\nCannot be found: %s \n %s" % (key, value), end='\n')

                with open(STORED_BANNED_CHANNEL_FILE_NAME, mode='a+', encoding='utf-8') as ids_file:
                    # Write info message for file if not already written
                    if os.path.getsize(STORED_BANNED_CHANNEL_FILE_NAME) == 0:
                        ids_file.write(
                            'This file is used to keep track of banned channels.' +
                            '\nIf you would like to restart fresh or on a new account. Delete this file.\n\n'
                        )
                    # Write channel id to file
                    ids_file.write('%s.%s\n' % (key, value))
                    # exit(0)
                # print(code, reason + '\n')
            else:
                # print("An HTTP error %d occurred:\n%s" %
                #       (e.resp.status, e.content))
                print(code, reason)
                # print(youtube, channel_id)
                print(e.content.decode('utf-8'))
                # exit(1)
        else:
            print("A subscription to '%s' was added." % channel_title)

    print("Finished subscribing to all channels!")
