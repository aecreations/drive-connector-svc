# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import requests
import urllib.parse
from datetime import datetime
from aeAuthorizationError import AuthorizationError


DEBUG = True

AUTHZ_SRV_KEY = "googledrive"
SYNC_FILENAME = "readnext.json"
SYNC_FILE_MIME_TYPE = "application/json"

_oauthClient = {
    'accessToken': None,
    'refreshToken': None,
    }
_syncFileID = None
_isAccessTokenRefreshed = False


def init(accessToken, refreshToken, syncFileID):
    global _oauthClient, _syncFileID    
    _oauthClient['accessToken'] = accessToken
    _oauthClient['refreshToken'] = refreshToken
    _syncFileID = syncFileID


def isAccessTokenRefreshed():
    return _isAccessTokenRefreshed


def getAccessToken():
    return _oauthClient['accessToken']


def syncFileExists():
    global _syncFileID
    fileExists = False
    srchFilter = urllib.parse.quote("name='readnext.json'")
    query = f"q={srchFilter}&spaces=drive&trashed=false"
    reqOpts = {
        'method': "GET",
        'headers': _getReqHdrs(),
        }

    # BUG!! Trashed files incorrectly returned even if `trashed=false` was set
    resp = _fetch(f"https://www.googleapis.com/drive/v3/files?{query}", reqOpts)
    resp.raise_for_status()
    respBody = resp.json()
    files = respBody['files']
    if len(files) > 0:
        filteredFiles = filter(lambda file:
                                   file['name'] == SYNC_FILENAME
                                   and file['kind'] == "drive#file"
                                   and file['mimeType'] == SYNC_FILE_MIME_TYPE,
                          files)
        fileList = list(filteredFiles)
        if len(fileList) > 0:
            _syncFileID = fileList[0]['id']
            fileExists = True
    return (fileExists, _syncFileID)


def createSyncFile(jsonStr):
    syncFileID, fileCreatedTime = _setSyncData(jsonStr, True)   
    return (syncFileID, fileCreatedTime)


def getSyncData():
    if _syncFileID is None:
        raise ValueError
    query = "alt=media"
    headers = _getReqHdrs();
    reqOpts = {
        'method': "GET",
        'headers': headers,
        }
    resp = _fetch(f"https://www.googleapis.com/drive/v3/files/{_syncFileID}?{query}", reqOpts)
    resp.raise_for_status()
    syncData = resp.text
    return syncData


def setSyncData(jsonStr):
    syncFileID, fileModifiedTime = _setSyncData(jsonStr, False)
    return (syncFileID, fileModifiedTime)


def getLastModifiedTime():
    if _syncFileID is None:
        raise ValueError
    query = "fields=modifiedTime"
    headers = _getReqHdrs();
    reqOpts = {
        'method': "GET",
        'headers': headers,
        }
    resp = _fetch(f"https://www.googleapis.com/drive/v3/files/{_syncFileID}?{query}", reqOpts)
    resp.raise_for_status()
    respBody = resp.json()
    lastModifiedTime = respBody['modifiedTime']
    return lastModifiedTime
    

#
# Helper functions
#

def _setSyncData(syncData, isNewFile):
    global _syncFileID
    query = "uploadType=multipart&fields=id,modifiedTime"
    headers = _getReqHdrs();
    headers['Content-Type'] = "multipart/related; boundary=ae-boundary"
    body = '--ae-boundary\n' + \
      'Content-Type: application/json; charset=UTF-8\n\n' + \
      '{\n' + \
      '  "name": "' + SYNC_FILENAME + '",\n' + \
      '  "kind": "drive#file",\n' + \
      '  "mimeType": "' + SYNC_FILE_MIME_TYPE + '"\n' + \
      '}\n' + \
      '--ae-boundary\n' + \
      'Content-Type: ' + SYNC_FILE_MIME_TYPE + '\n\n' + \
      syncData + '\n' + \
      '--ae-boundary--'
    headers['Content-Length'] = str(_getLengthInBytes(body))
    reqOpts = {
        'method': "POST" if isNewFile else "PATCH",
        'headers': headers,
        'body': body
        }
    fileIDSfx = "" if isNewFile else f"/{_syncFileID}"
    resp = _fetch(f"https://www.googleapis.com/upload/drive/v3/files{fileIDSfx}?{query}", reqOpts)
    resp.raise_for_status()
    respBody = resp.json()
    fileID = respBody['id']
    fileModifiedTime = respBody['modifiedTime']
    if isNewFile:
        _syncFileID = fileID
    return (fileID, fileModifiedTime)


def _getLengthInBytes(str):
    return len(str.encode("utf-8"))


def _getReqHdrs():
    reqHdrs = {
        'Authorization': f"Bearer {_oauthClient['accessToken']}"
        }
    return reqHdrs


def _fetch(url, requestOpts, isRetry=False):
    global _oauthClient, _isAccessTokenRefreshed
    rv = None
    method = requestOpts['method']
    args = {}
    if 'headers' in requestOpts:
        args['headers'] = requestOpts['headers']
    if 'body' in requestOpts:
        args['data'] = requestOpts['body']
    resp = requests.request(method, url, **args)
    if resp.status_code == requests.codes.unauthorized:
        _log("aeGoogleDrive._fetch(): API call to {} returned HTTP status {}".format(url, resp.status_code))
        if isRetry is True:
            # Prevent infinite recursion and just return the error response.
            rv = resp
        else:
            _log("aeGoogleDrive._fetch(): Access token may be expired. Getting new access token...")
            newAccessToken = _getNewAccessToken()
            _oauthClient['accessToken'] = newAccessToken
            _isAccessTokenRefreshed = True
            _log("aeGoogleDrive._fetch(): Refreshed access token:\n" + json.dumps(_oauthClient, indent=2))
            requestOpts['headers']['Authorization'] = f"Bearer {newAccessToken}"
            rv = _fetch(url, requestOpts, True)
    else:
        rv = resp
    return rv

    
def _getNewAccessToken():
    params = {
        'svc': AUTHZ_SRV_KEY,
        'grant_type': "refresh_token",
        'refresh_token': _oauthClient['refreshToken']
        }
    _log("aeGoogleDrive._getNewAccessToken(): Calling aeOAPS /token:\n" + json.dumps(params, indent=2))
    resp = requests.post("https://aeoaps.herokuapp.com/readnext/token", data=params)
    if resp.status_code != requests.codes.ok:
        _log("POST aeOAPS /token returned HTTP status {}, response body:\n{}".format(resp.status_code, json.dumps(resp.json(), indent=2)))
    if resp.status_code == requests.codes.bad_request:
        errResp = resp.json()
        if ('error' in errResp and errResp['error']['name'] == "AuthorizationError"):
            raise AuthorizationError(errResp['error']['message'])
        else:
            resp.raise_for_status()
    else:
        resp.raise_for_status()
    respBody = resp.json()
    newAccessToken = respBody['access_token']
    return newAccessToken


def _log(msg):
    if DEBUG:
        with open("debug.txt", "a") as file:
            dt = datetime.now()
            file.write("{} {}".format(dt, msg))
            file.write("\n")
