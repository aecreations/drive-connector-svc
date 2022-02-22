#!/usr/local/bin/python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import struct
import json
import aeGoogleDrive


DEBUG = True
APP_NAME = "Drive Connector Service"
APP_VER = "1.0a0+"

def getAppName():
    return APP_NAME

def getAppVer():
    return APP_VER

def sliceReadingList(readingList, startIdx, slcLen):
    endIdx = startIdx + slcLen
    slicedRdgList = readingList[slice(startIdx, endIdx)]
    hasMoreItems = len(readingList[slice(startIdx + slcLen, endIdx + slcLen)]) > 0
    return (slicedRdgList, hasMoreItems)

def log(msg):
    if DEBUG:
        with open("debug.txt", "a") as file:
            file.write(msg)
            file.write("\n")

def getMessage():
    rawLength = sys.stdin.buffer.read(4)
    if len(rawLength) == 0:
        sys.exit(0)
    stdioMsgLen = struct.unpack('@I', rawLength)[0]
    stdioMsg = sys.stdin.buffer.read(stdioMsgLen).decode('utf-8')
    message = json.loads(stdioMsg)
    return message

def encodeMessage(msgData):
    encodedContent = json.dumps(msgData).encode('utf-8')
    encodedLength = struct.pack('@I', len(encodedContent))
    return {'length': encodedLength, 'content': encodedContent}

def sendMessage(encodedMsg):
    sys.stdout.buffer.write(encodedMsg['length'])
    sys.stdout.buffer.write(encodedMsg['content'])
    sys.stdout.buffer.flush()


while True:
    msg = getMessage()
    resp = None
    if 'id' not in msg:
        err = "Error: Missing message ID"
        log(err)
        sys.stderr.buffer.write("driveConnectorSvc: " + err)
        sys.stderr.buffer.flush()
        sys.exit(1)
    log('driveConnectorSvc: Received native message "{}"'.format(msg['id']))
    if msg['id'] == "get-app-version":
        # accessToken, refreshToken and syncFileID not required.
        resp = {
            'appName': getAppName(),
            'appVersion': getAppVer()
            }
        sendMessage(encodeMessage(resp))
        continue
    if ('accessToken' not in msg) or ('refreshToken' not in msg) or ('syncFileID' not in msg):
        err = "Error: Missing accessToken, refreshToken and/or syncFileID"
        log(err)
        sys.stderr.buffer.write("driveConnectorSvc: " + err)
        sys.stderr.buffer.flush()
        sys.exit(1)
    initArgs = (
        msg['accessToken'],
        msg['refreshToken'],
        msg['syncFileID']
        )
    aeGoogleDrive.init(*initArgs)
    if msg['id'] == "sync-file-exists":
        fileExists, syncFileID = aeGoogleDrive.syncFileExists()
        resp = {
            'syncFileExists': fileExists,
            'syncFileID': syncFileID,
            }
    elif msg['id'] == "create-sync-file":
        syncData = json.dumps(msg['syncData'])
        syncFileID, fileCreatedTime = aeGoogleDrive.createSyncFile(syncData)
        resp = {
            'syncFileID': syncFileID,
            'fileCreatedTime': fileCreatedTime,
            }
    elif msg['id'] == "get-sync-data":
        remoteSyncData = aeGoogleDrive.getSyncData()
        rdgList = json.loads(remoteSyncData)
        startIdx = 0
        if 'startIdx' in msg:
            startIdx = msg['startIdx']
        sliceLen = 4
        if 'sliceLen' in msg:
            sliceLen = msg['sliceLen']
        slicedRdgList, hasMoreItems = sliceReadingList(rdgList, startIdx, sliceLen)
        resp = {
            'syncData': slicedRdgList,
            'hasMoreItems': hasMoreItems,
            }
    elif msg['id'] == "set-sync-data":
        syncData = json.dumps(msg['syncData'])
        _, fileModifiedTime = aeGoogleDrive.setSyncData(syncData)
        resp = {
            'fileModifiedTime': fileModifiedTime
            }
    elif msg['id'] == "get-last-modified-time":        
        resp = {
            'lastModifiedTime': aeGoogleDrive.getLastModifiedTime()
            }

    if aeGoogleDrive.isAccessTokenRefreshed():
        resp['newAccessToken'] = aeGoogleDrive.getAccessToken()

    if resp is not None:
        sendMessage(encodeMessage(resp))
