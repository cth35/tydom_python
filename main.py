#!/usr/bin/env python
import asyncio
import websockets
import http.client
from requests.auth import HTTPDigestAuth
import sys
import logging
from http.client import HTTPResponse
from io import BytesIO
import urllib3
import json
import os
import base64
import time
from http.server import BaseHTTPRequestHandler
import ssl

# Globals
mac = "The mac address (16 bytes) of your Tydom like : AB00AB00AB00AB"
login = mac
password = "The password of your tydom"

# Local ip address or mediation.tydom.com for remote connexion
host = "mediation.tydom.com" #"192.168.0.20"

if host == "mediation.tydom.com":
    remote_mode = True
    ssl_context = None
    cmd_prefix = "\x02"
else:
    remote_mode = False
    ssl_context = ssl._create_unverified_context()
    cmd_prefix = ""
    
class BytesIOSocket:
    def __init__(self, content):
        self.handle = BytesIO(content)

    def makefile(self, mode):
        return self.handle

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        #self.rfile = StringIO(request_text)
        self.raw_requestline = request_text
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

def response_from_bytes(data):
    sock = BytesIOSocket(data)
    response = HTTPResponse(sock)
    response.begin()
    return urllib3.HTTPResponse.from_httplib(response)

def put_response_from_bytes(data):
    request = HTTPRequest(data)
    return request

def parse_response(bytes_str):
    response = response_from_bytes(bytes_str[len(cmd_prefix):])
    data = response.data.decode("utf-8")
    if (data != ''):
        parsed = json.loads(data)
        print(json.dumps(parsed, sort_keys=True, indent=4, separators=(',', ': ')))

def parse_put_response(bytes_str):
    # TODO : Find a cool way to parse nicely the PUT HTTP
    #a = bytes_str.replace(b'\r\n\r\n0\r\n\r\n',b'\r\nHTTP/1.1\r\n\r\n')
    response = put_response_from_bytes(bytes_str[len(cmd_prefix):])
    data = response.data.decode("utf-8")
    if (data != ''):
        parsed = json.loads(data)
        print(json.dumps(parsed, sort_keys=True, indent=4, separators=(',', ': ')))

async def get_info(websocket):
    str = cmd_prefix + "GET /info HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"
    a_bytes = bytes(str, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)

async def get_ping(websocket):
    str = cmd_prefix + "GET /ping HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"
    a_bytes = bytes(str, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)

async def get_devices_meta(websocket):
    str = cmd_prefix + "GET /devices/meta HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"
    a_bytes = bytes(str, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)

async def get_devices_data(websocket):
    str = cmd_prefix + "GET /devices/data HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"
    a_bytes = bytes(str, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)

# List the device to get the endpoint id
async def get_confis_file(websocket):
    str = cmd_prefix + "GET /configs/file HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"
    a_bytes = bytes(str, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)

# Give order to endpoint
async def put_devices_data(websocket):
    # 67.0 is the percentage of opening
    body="[{\"name\":\"position\",\"value\":\"67.0\"}]"
    # 10 here is the endpoint = the device (shutter in this case) to open.
    str_request = cmd_prefix + "PUT /devices/10/endpoints/10/data HTTP/1.1\r\nContent-Length: "+str(len(body))+"\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"+body+"\r\n\r\n"
    a_bytes = bytes(str_request, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)
    name = await websocket.recv()
    try:
        parse_response(name)
    except:
        # TODO : Parse HTML PUT response (as HTML PUT request)
        parse_put_response(name)

@asyncio.coroutine
async def hello():
    #logger = logging.getLogger('websockets')
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    # Generate 16 bytes random key for Sec-WebSocket-Key
    rnd = os.urandom(16)
    # Convert it t base64
    encoded = base64.b64encode(rnd)
    httpHeaders = {"Connection": "Upgrade",
               "Upgrade": "websocket",
               "Host": host + ":443",
               "Accept": "*/*",
               "Sec-WebSocket-Key": encoded,
               "Sec-WebSocket-Version": "13"
               }
    http.client.HTTPSConnection.debuglevel = 1
    http.client.HTTPConnection.debuglevel = 1
    # Create HTTPS connection on tydom server
    conn = http.client.HTTPSConnection(host, 443, context=ssl_context)
    # Get first handshake
    conn.request("GET", "/mediation/client?mac={}&appli=1".format(mac), None, httpHeaders)
    res = conn.getresponse()
    # Get authentication
    nonce = res.headers["WWW-Authenticate"].split(',', 3)

    res.read()

    digestAuth = HTTPDigestAuth(login, password)
    chal = dict()
    chal["nonce"] = nonce[2].split('=', 1)[1].split('"')[1]
    chal["realm"] = "ServiceMedia" if remote_mode is True else "protected area"
    chal["qop"] = "auth"
    digestAuth._thread_local.chal = chal
    digestAuth._thread_local.last_nonce = nonce
    digestAuth._thread_local.nonce_count = 1
    digestAuthHeader = digestAuth.build_digest_header('GET', "https://{}:443/mediation/client?mac={}&appli=1".format(host, mac))
    # Close HTTPS Connection
    conn.close()
    # Generate 16 bytes random key for Sec-WebSocket-Key
    rnd = os.urandom(16)
    # Convert it t base64
    encoded = base64.b64encode(rnd)
    # Build websocket headers : Cookie not needed 'Cookie': cook_split[0],
    websocketHeaders = {'Authorization': digestAuthHeader}

    if ssl_context is not None:
        websocket_ssl_context = ssl_context
    else:
        websocket_ssl_context = True # Verify certificate

    async with websockets.client.connect('wss://{}:443/mediation/client?mac={}&appli=1'.format(host, mac), extra_headers=websocketHeaders, ssl=websocket_ssl_context) as websocket:
        #await get_info(websocket)
        await get_confis_file(websocket)
        #await get_devices_meta(websocket)
        #await get_devices_data(websocket)
        await put_devices_data(websocket)
        # TODO : Wait hardcoded for now to put response from websocket server
        time.sleep(45)
asyncio.get_event_loop().run_until_complete(hello())
