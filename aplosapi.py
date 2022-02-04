#!/usr/bin/env python

##############################
#
# Uses packages:
#     requests (http://docs.python-requests.org/en/latest/)
#     rsa (http://stuvel.eu/files/python-rsa-doc/)
#
# Requires application:
#     openssl (for converting keys from PKCS8 to PKCS1)
#
# Usage:
#     Download API key from https://www.aplos.com/aws/settings/api/configure
#     This should result in a file with the name (aplos_id.key).
#     Put that file in the same directory as this Python script, adding the extension:
#     .download, so your new file name will be (aplos_id.key.download).
#     Update the api_id value with your api_key value.
#
#
##############################

import base64
import json
import os
import textwrap
import subprocess
import sys

try:
    from requests import requests
except:
   import requests

try:
    from rsa import rsa
except:
    import rsa


# API url and Aplos key 
api_base_url = 'https://www.aplos.com/hermes/api/v1/'
api_id = '2bdc1c6f-7436-4ee9-bcf4-25ca2e0306dc'

def convert_pkcs8_to_pkcs1(api_id):
    
    # convert key to a formatted pkcs8 file
   
    with open(api_id + '.key.download', mode='rb') as pkcs8file:
        api_user_pkcs8file = '-----BEGIN PRIVATE KEY-----\n' + \
            textwrap.fill(pkcs8file.read(), 64) + \
            '\n-----END PRIVATE KEY-----\n\r'
    with open(api_id + '.pkcs8', mode='w') as pkcs1keyfile:
        pkcs1keyfile.write(api_user_pkcs8file)

    # convert pkcs8 to pkcs1. Code needs to change depending on OpenSSL version.
    #
    # OpenSSL > 0.9.8 should use:
    #   openssl rsa -in {}.pkcs8 -outform PEM -out {}.key
    #
    # OpenSSL < 0.9.8 should use
    #   openssl pkcs8 -nocrypt -in {}.pkcs8 -out {}.key

    p = subprocess.Popen(['openssl', 'version'], stdout=subprocess.PIPE)
    t = p.stdout.read()
    print (t)
    if '0.9.8' in t:
        openssl_cvrt_cmd = 'openssl pkcs8 -nocrypt -in {}.pkcs8 -out {}.key'.format(
            api_id, api_id)
    else:
        openssl_cvrt_cmd = 'openssl rsa -in {}.pkcs8 -outform PEM -out {}.key'.format(
            api_id, api_id)

    print (openssl_cvrt_cmd)
    p = subprocess.Popen(openssl_cvrt_cmd, shell=True, stderr=subprocess.PIPE)
    while True:
        out = p.stderr.read(1)
        if out == '' and p.poll() != None:
            break
        if out != '':
            sys.stdout.write(out)
            sys.stdout.flush()

    with open(api_id + '.key', mode='rb') as pkeyfile:
        api_user_pemkey = pkeyfile.read()
    return(api_user_pemkey)


def api_error_handling(status_code):
    # Error Handling:
    # Check for HTTP codes other than 200
    if status_code != 200:
        if status_code == 401:
            print ('Status:', status_code, 'Something is wrong with the auth code. Exiting')
            exit()
        elif status_code == 403:
            print ('Status:', status_code, 'Forbidden. Exiting')
            exit()
        elif status_code == 405:
            print ('Status:', status_code, 'Method not allowed. Exiting')
            exit()
        elif status_code == 422:
            print ('Status:', status_code, 'Unprocessable Entity. Exiting')
            exit()
        print ('Status:', status_code, 'Problem with the request. Exiting.')
        exit()
    else:
        print ('Status:', status_code, ': The API let me in!')
    return()


def api_auth(api_base_url, api_id, api_user_key):
    # This should return an authorized token
    print ('geting URL: {}auth/{}'.format(api_base_url, api_id))

    # request goes here.
    r = requests.get('{}auth/{}'.format(api_base_url, api_id))
    data = r.json()
    api_error_handling(r.status_code)

    api_token_encrypted = data['data']['token']
    api_token_encrypted_expires = data['data']['expires']
    print ('The API Token expires: {}'.format(api_token_encrypted_expires))

    api_bearer_token = rsa.decrypt(
        base64.decodestring(api_token_encrypted), api_user_key)
    return(api_bearer_token)


def api_contacts_get(api_base_url, api_id, api_access_token):
    # This should print a contact from Aplos.
    headers = {'Authorization': 'Bearer: {}'.format(api_access_token)}
    print ('geting URL: {}contacts'.format(api_base_url))
    print ('With headers: {}'.format(headers))

    # request goes here.
    r = requests.get('{}contacts'.format(api_base_url), headers=headers)
    api_error_handling(r.status_code)
    response = r.json()
    print ('JSON response: {}'.format(response))
    return (response)


def api_accounts_get(api_base_url, api_id, api_access_token):
    # This should print a contact from Aplos.
    headers = {'Authorization': 'Bearer: {}'.format(api_access_token)}
    print ('geting URL: {}accounts'.format(api_base_url))
    print ('With headers: {}'.format(headers))

    # request goes here.
    r = requests.get('{}accounts'.format(api_base_url), headers=headers)
    api_error_handling(r.status_code)
    response = r.json()
    print ('JSON response: {}'.format(response))
    return (response)


def api_transactions_get(api_base_url, api_id, api_access_token):
    # This should print a contact from Aplos.
    headers = {'Authorization': 'Bearer: {}'.format(api_access_token)}
    print ('geting URL: {}transactions'.format(api_base_url))
    print ('With headers: {}'.format(headers))

    # request goes here.
    r = requests.get('{}transactions'.format(api_base_url), headers=headers)
    api_error_handling(r.status_code)
    response = r.json()

    print ('JSON response: {}'.format(response))
    return (response)



# Setup RSA and import the PCKS1 version of the keyfile.
try:
    if os.stat(api_id + '.key').st_size > 0:
        print ('Key file exists\n')
        with open(api_id + '.key', mode='rb') as pkeyfile:
            api_user_pemkey = pkeyfile.read()
    else:
        print ('Key file empty\n')
        api_user_pemkey = convert_pkcs8_to_pkcs1(api_id)
except OSError:
    print ('No file\n')
    api_user_pemkey = convert_pkcs8_to_pkcs1(api_id)

api_user_key = rsa.PrivateKey.load_pkcs1(api_user_pemkey)

# API manipulation
api_access_token = api_auth(api_base_url, api_id, api_user_key)
#contacts = api_contacts_get(api_base_url, api_id, api_access_token)
#transactions = api_transactions_get(api_base_url, api_id, api_access_token)
accounts = api_accounts_get(api_base_url, api_id, api_access_token)
#transaction_post = api_transactions_post(api_base_url, api_id, api_access_token)
