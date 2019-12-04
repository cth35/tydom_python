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

# Alarm available keywords
# alarmMode  : ON or ZONE or OFF or TEST or MAINTENANCE
# alarmState : ON or OFF or DELAYED or QUIET
# alarmSOS   : true = SOS triggered
deviceAlarmKeywords = ['alarmMode','alarmState','alarmSOS','zone1State','zone2State','zone3State','zone4State','zone5State','zone6State','zone7State','zone8State','gsmLevel','inactiveProduct','zone1State','liveCheckRunning','networkDefect','unitAutoProtect','unitBatteryDefect','unackedEvent','alarmTechnical','systAutoProtect','sysBatteryDefect','systSupervisionDefect','systOpenIssue','systTechnicalDefect','videoLinkDefect','simDefect','remoteSurveyDefect']

# Local ip address or mediation.tydom.com for remote connexion
host = "mediation.tydom.com" #"192.168.0.20"

# Device dict for parsing
device_dict = dict()

# Set Host, ssl context and prefix for remote or local connection
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

# Basic response parsing. Typically GET responses
def parse_response(bytes_str, type=None):
    try:
        response = response_from_bytes(bytes_str[len(cmd_prefix):])
        data = response.data.decode("utf-8")
        if (data != ''):
            parsed = json.loads(data)
            if type == '/configs/file':
                for i in parsed["endpoints"]:
                    # Get list of shutter
                    if i["last_usage"] == 'shutter':
                        print('{} {}'.format(i["id_endpoint"],i["name"]))
                        device_dict[i["id_endpoint"]] = i["name"]
                        # TODO get other device type
                    if i["last_usage"] == 'alarm':
                        print('{} {}'.format(i["id_endpoint"], i["name"]))
            elif type == '/devices/data':
                for i in parsed:
                    if i["endpoints"][0]["error"] == 0:
                        for elem in i["endpoints"][0]["data"]:
                            # Get full name of this id
                            endpoint_id = i["endpoints"][0]["id"]
                            # Element name
                            elementName = elem["name"]
                            # Element value
                            elementValue = elem["value"]
                            # Get last known position (for shutter)
                            if elementName == 'position':
                                name_of_id = get_name_from_id(endpoint_id)
                                if len(name_of_id) != 0:
                                    print_id = name_of_id
                                else:
                                    print_id = endpoint_id
                                print('{} : {}'.format(print_id, elementValue))
                            # Get last known position (for alarm)
                            if elementName in deviceAlarmKeywords:
                                print('{} : {} : {}'.format(endpoint_id, elementName, elementValue))
            else:
                # Default json dump
                print(json.dumps(parsed, sort_keys=True, indent=4, separators=(',', ': ')))
    except Exception as e:
        print('Cannot parse response')
        print(e)

# PUT response DIRTY parsing
def parse_put_response(bytes_str):
    # TODO : Find a cooler way to parse nicely the PUT HTTP response
    resp = bytes_str[len(cmd_prefix):].decode("utf-8")
    fields = resp.split("\r\n")
    fields = fields[6:]  # ignore the PUT / HTTP/1.1
    end_parsing = False
    i = 0
    output = str()
    while not end_parsing:
        field = fields[i]
        if len(field) == 0 or field == '0':
            end_parsing = True
        else:
            output += field
            i = i + 2
    parsed = json.loads(output)
    print(json.dumps(parsed, sort_keys=True, indent=4, separators=(',', ': ')))

# Generate 16 bytes random key for Sec-WebSocket-Keyand convert it to base64
def generate_random_key():
    return base64.b64encode(os.urandom(16))

# Build the headers of Digest Authentication
def build_digest_headers(nonce):
    digestAuth = HTTPDigestAuth(login, password)
    chal = dict()
    chal["nonce"] = nonce[2].split('=', 1)[1].split('"')[1]
    chal["realm"] = "ServiceMedia" if remote_mode is True else "protected area"
    chal["qop"] = "auth"
    digestAuth._thread_local.chal = chal
    digestAuth._thread_local.last_nonce = nonce
    digestAuth._thread_local.nonce_count = 1
    return digestAuth.build_digest_header('GET', "https://{}:443/mediation/client?mac={}&appli=1".format(host, mac))

# Get pretty name for a device id
def get_name_from_id(id):
    name = ""
    if len(device_dict) != 0:
        name = device_dict[id]
    return(name)

# Send Generic GET message
async def send_message(websocket, msg):
    str = cmd_prefix + "GET " + msg +" HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"
    a_bytes = bytes(str, "ascii")
    await websocket.send(a_bytes)
    return await websocket.recv()

###############################################################
# Commands                                                    #
###############################################################

# Get some information on Tydom
async def get_info(websocket):
    msg_type = '/info'
    parse_response(await send_message(websocket, msg_type), msg_type)

# Get the moments (programs)
async def get_moments(websocket):
    msg_type = '/moments/file'
    parse_response(await send_message(websocket, msg_type), msg_type)

# Get the scenarios
async def get_scenarios(websocket):
    msg_type = '/scenarios/file'
    parse_response(await send_message(websocket, msg_type), msg_type)

# Get a ping (pong should be returned)
async def get_ping(websocket):
    msg_type = 'ping'
    parse_response(await send_message(websocket, msg_type), msg_type)

# Get all devices metadata
async def get_devices_meta(websocket):
    msg_type = '/devices/meta'
    parse_response(await send_message(websocket, msg_type), msg_type)

# Get all devices data
async def get_devices_data(websocket):
    msg_type = '/devices/data'
    parse_response(await send_message(websocket, msg_type), msg_type)

# List the device to get the endpoint id
async def get_configs_file(websocket):
    msg_type = '/configs/file'
    parse_response(await send_message(websocket, msg_type), msg_type)

# Give order (name + value) to endpoint
async def put_devices_data(websocket, endpoint_id, name, value):
    # For shutter, value is the percentage of closing
    body="[{\"name\":\"" + name + "\",\"value\":\""+ value + "\"}]"
    # endpoint_id is the endpoint = the device (shutter in this case) to open.
    str_request = cmd_prefix + "PUT /devices/{}/endpoints/{}/data HTTP/1.1\r\nContent-Length: ".format(str(endpoint_id),str(endpoint_id))+str(len(body))+"\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"+body+"\r\n\r\n"
    a_bytes = bytes(str_request, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)
    name = await websocket.recv()
    try:
        parse_response(name)
    except:
        parse_put_response(name)

# Run scenario
async def put_scenarios(websocket, scenario_id):
    body=""
    # scenario_id is the id of scenario got from the get_scenarios command
    str_request = cmd_prefix + "PUT /scenarios/{} HTTP/1.1\r\nContent-Length: ".format(str(scenario_id))+str(len(body))+"\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"+body+"\r\n\r\n"
    a_bytes = bytes(str_request, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)

# Give order to endpoint
async def get_device_data(websocket, id):
    # 10 here is the endpoint = the device (shutter in this case) to open.
    str_request = cmd_prefix + "GET /devices/{}/endpoints/{}/data HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n".format(str(id),str(id))
    a_bytes = bytes(str_request, "ascii")
    await websocket.send(a_bytes)
    name = await websocket.recv()
    parse_response(name)

# Main async task
@asyncio.coroutine
async def main_task():
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    httpHeaders =  {"Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Host": host + ":443",
                    "Accept": "*/*",
                    "Sec-WebSocket-Key": generate_random_key(),
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
    # read response
    res.read()
    # Close HTTPS Connection
    conn.close()

    # Build websocket headers
    websocketHeaders = {'Authorization': build_digest_headers(nonce)}

    if ssl_context is not None:
        websocket_ssl_context = ssl_context
    else:
        websocket_ssl_context = True # Verify certificate

    async with websockets.client.connect('wss://{}:443/mediation/client?mac={}&appli=1'.format(host, mac),
                                         extra_headers=websocketHeaders, ssl=websocket_ssl_context) as websocket:

        # Get informations (not very useful)
        #await get_info(websocket)

        # Get all moments stored on Tydom
        #await get_moments(websocket)

        # Get scenarios ids
        await get_scenarios(websocket)

        # Run scenario with scn id returned in previous command
        await put_scenarios(websocket, 15)

        #await get_configs_file(websocket)
        #await get_devices_meta(websocket)

        # Get data of all device
        #await get_devices_data(websocket)

        # Get data of a specific device
        #await get_device_data(websocket, 9)

        # Set a shutter position to 10%
        #await put_devices_data(websocket, 9, "position", "10.0")
        # TODO : Wait hardcoded for now to put response from websocket server
        #time.sleep(45)
asyncio.get_event_loop().run_until_complete(main_task())
