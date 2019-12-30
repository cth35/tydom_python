#!/usr/bin/env python
import asyncio
from datetime import datetime
import websockets
import sys
import logging
import urllib3
import json
import os
import base64
import time
import ssl
import socket
import subprocess, platform

from requests.auth import HTTPDigestAuth
import http.client
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler
from io import BytesIO

from gmqtt.mqtt.constants import MQTTv311
from gmqtt import Client as MQTTClient

from tendo import singleton

enable_MQTT = True #Disable MQTT if you want
hassio = None
tydom = None
me = singleton.SingleInstance() # will sys.exit(-1) if other instance is running

def pingOk(sHost):
    try:
        output = subprocess.check_output("ping -{} 1 {}".format('n' if platform.system().lower()=="windows" else 'c', sHost), shell=True)
    except Exception as e:
        return False
    return True

####### SETTINGS
logfile = os.environ.get('LOGFILE', "tydom2mqtt.log")
remote_adress = os.environ.get('REMOTE_HTTP_TYDOM', "mediation.tydom.com")
####### TYDOM CREDENTIALS 
mac = os.environ.get('TYDOM_MAC_ADDRESS', "xxxxxxxxx") #MAC Address of Tydom Box
tydom_ip = os.environ.get('TYDOM_IP', remote_adress) # Local ip address or mediation.tydom.com for remote connexion
login = os.environ.get('TYDOM_USERNAME', mac)
password = os.environ.get('TYDOM_PASSWORD', "") #Tydom password
####### MQTT CREDENTIALS 
mqtt_client_id = "client-id"
mqtt_host = os.environ.get('MQTT_HOST', "xxxxxxxxx")
mqtt_port = os.environ.get('MQTT_PORT', 1883)
mqtt_user = os.environ.get('MQTT_USER')
mqtt_pass = os.environ.get('MQTT_PASSWORD')
mqtt_ssl = os.environ.get('MQTT_SSL', 1) == 1

# Local use ?
local = tydom_ip != remote_adress
host = tydom_ip

if (local):
    print('Local Execution Detected')
else:
    print('Remote Execution Detected')

####### TEST IF REMOTE IP CAN WORK
if pingOk(tydom_ip):
    print(f"'{tydom_ip}' is reachable.")
else:
    print(f"'{tydom_ip}' is unreachable.")
    exit(1)

# Set Host, ssl context and prefix for remote or local connection
if local == False:
    ssl_context = None
    cmd_prefix = "\x02"
else:
    ssl_context = ssl._create_unverified_context()
    cmd_prefix = ""

deviceAlarmKeywords = ['alarmMode','alarmState','alarmSOS','zone1State','zone2State','zone3State','zone4State','zone5State','zone6State','zone7State','zone8State','gsmLevel','inactiveProduct','zone1State','liveCheckRunning','networkDefect','unitAutoProtect','unitBatteryDefect','unackedEvent','alarmTechnical','systAutoProtect','sysBatteryDefect','zsystSupervisionDefect','systOpenIssue','systTechnicalDefect','videoLinkDefect']
# Device dict for parsing
device_dict = dict()

# Globals
####################################### MQTT
qos_pub=1

tydom_topic = "homeassistant/+/tydom/#"

cover_config_topic = "homeassistant/cover/tydom/{id}/config"
cover_config = "homeassistant/cover/tydom/{id}/config"
cover_position_topic = "homeassistant/cover/tydom/{id}/current_position"
cover_set_postion_topic = "homeassistant/cover/tydom/{id}/set_position"
cover_attributes_topic = "homeassistant/cover/tydom/{id}/attributes"


alarm_topic = "homeassistant/alarm_control_panel/tydom/#"
alarm_config = "homeassistant/alarm_control_panel/tydom/{id}/config"
alarm_state_topic = "homeassistant/alarm_control_panel/tydom/{id}/state"
alarm_command_topic = "homeassistant/alarm_control_panel/tydom/{id}/set"
alarm_sos_topic = "homeassistant/binary_sensor/tydom/{id}/sos"
alarm_attributes_topic = "homeassistant/alarm_control_panel/tydom/{id}/attributes"

refresh_topic = "homeassistant/requests/tydom/refresh"

#MQTT
STOP = asyncio.Event()

def on_error(client, err):
    print('Error', err)

def on_connect(client, flags, rc, properties):
    print("##################################")
    try:
        print("Subscribing to : ", tydom_topic)
        # client.subscribe('homeassistant/#', qos=qos_pub)
        client.subscribe(tydom_topic, qos=qos_pub)
    except Exception as e:
        print("Error : ", e)

async def on_message(client, topic, payload, qos, properties):
    # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
    # print('MQTT incoming : ', topic, payload)
    if tydom:
        if (topic == "homeassistant/requests/tydom/update"):
            print('Incoming MQTT update request : ', topic, payload)
            await get_data(tydom)
        if (topic == "homeassistant/requests/tydom/refresh"):
            print('Incoming MQTT refresh request : ', topic, payload)
            await post_refresh(tydom)
        if (topic == "homeassistant/requests/tydom/scenarii"):
            print('Incoming MQTT scenarii request : ', topic, payload)
            await get_scenarii(tydom)
        if ('set_scenario' in str(topic)):
            print('Incoming MQTT set_scenario request : ', topic, payload)
            get_id = (topic.split("/"))[3] #extract id from mqtt
            # print(tydom, str(get_id), 'position', json.loads(payload))
            await put_devices_data(tydom, str(get_id), 'position', str(json.loads(payload)))
        
        if ('set_position' in str(topic)):
            print('Incoming MQTT set_position request : ', topic, payload)
            get_id = (topic.split("/"))[3] #extract id from mqtt
            # print(tydom, str(get_id), 'position', json.loads(payload))
            await put_devices_data(tydom, str(get_id), 'position', str(json.loads(payload)))
        
        else:
            return 0
    else:
        print("No websocket connection yet !")

async def on_disconnect(client, packet, exc=None):
    print('MQTT Disconnected')
    print("##################################")
    await mqttconnection(mqtt_host, mqtt_user, mqtt_pass)    

def on_subscribe(client, mid, qos):
    print("MQTT is connected and suscribed ! =)", client)
    pyld = 'Started !',str(datetime.fromtimestamp(time.time()))
    hassio.publish('homeassistant/sensor/tydom/last_clean_startup', pyld, qos=1, retain=True)
            
def ask_exit(*args):
    STOP.set()

async def mqttconnection(mqtt_client_id, broker_host, user, password):
    try:
        global hassio
        if (hassio == None):
            print('Attempting MQTT connection...')
            client = MQTTClient(mqtt_client_id)

            client.on_connect = on_connect
            client.on_disconnect = on_disconnect
            client.on_subscribe = on_subscribe
            client.on_message = on_message

            if user is not None and password is not None:
                client.set_auth_credentials(user, password)

            await client.connect(broker_host, port=mqtt_port, ssl=mqtt_ssl)
            hassio = client

    except Exception as err:
        print(f"Error : {err}")
        print('MQTT error, restarting in 8s...')
        await asyncio.sleep(8)
        await mqttconnection(mqtt_client_id, mqtt_host, mqtt_user, mqtt_pass)

# client.publish('TEST/TIME', str(time.time()), qos=1)

# await STOP.wait()
    # await client.disconnect()


#######" END MQTT"


class Cover:
    def __init__(self, id, name, current_position=None, set_position=None, attributes=None):
        
        self.id = id
        self.name = name
        self.current_position = current_position
        self.set_position = set_position
        self.attributes = attributes

    def id(self):
        return self.id

    def name(self):
        return self.name

    def current_position(self):
        return self.current_position

    def set_position(self):
        return self.set_position

    def attributes(self):
        return self.attributes

    # cover_config_topic = "homeassistant/cover/tydom/{id}/config"
    # cover_position_topic = "homeassistant/cover/tydom/{id}/current_position"
    # cover_set_postion_topic = "homeassistant/cover/tydom/{id}/set_position"
    # cover_attributes_topic = "homeassistant/cover/tydom/{id}/attributes"

    def setup(self):
        self.device = {}
        self.device['manufacturer'] = 'Delta Dore'
        self.device['model'] = 'Volet'
        self.device['name'] = self.name
        self.device['identifiers'] = id=self.id
        self.config_topic = cover_config_topic.format(id=self.id)
        self.config = {}
        self.config['name'] = self.name
        self.config['unique_id'] = self.id
        # self.config['attributes'] = self.attributes
        self.config['command_topic'] = cover_set_postion_topic.format(id=self.id)
        self.config['set_position_topic'] = cover_set_postion_topic.format(id=self.id)
        self.config['position_topic'] = cover_position_topic.format(id=self.id)
        self.config['payload_open'] = 100
        self.config['payload_close'] = 0
        self.config['retain'] = 'false'
        self.config['device'] = self.device

        # print(self.config)
        hassio.publish(self.config_topic, json.dumps(self.config), qos=qos_pub)

    def update(self):
        self.setup()
        self.position_topic = cover_position_topic.format(id=self.id, current_position=self.current_position)
        hassio.publish(self.position_topic, self.current_position, qos=qos_pub, retain=True)

        # self.attributes_topic = cover_attributes_topic.format(id=self.id, attributes=self.attributes)
        # hassio.publish(self.attributes_topic, self.attributes, qos=qos_pub)

class Alarm:
    def __init__(self, id, name, current_state=None, attributes=None):
        self.id = id
        self.name = name
        self.current_state = current_state
        self.attributes = attributes

    # def id(self):
    #     return id

    # def name(self):
    #     return name

    # def current_state(self):
    #     return current_state

    # def attributes(self):
    #     return attributes
    
    def setup(self):
        self.device = {}
        self.device['manufacturer'] = 'Delta Dore'
        self.device['model'] = 'Tyxal'
        self.device['name'] = self.name
        self.device['identifiers'] = id=self.id
        self.config_alarm = alarm_config.format(id=self.id)
        self.config = {}
        self.config['name'] = self.name
        self.config['unique_id'] = self.id
        self.config['device'] = self.device
        # self.config['attributes'] = self.attributes
        self.config['command_topic'] = alarm_command_topic.format(id=self.id)
        self.config['state_topic'] = alarm_state_topic.format(id=self.id)


        # print(self.config)
        hassio.publish(self.config_alarm, json.dumps(self.config), qos=qos_pub)

    def update(self):
        self.setup()
        self.state_topic = alarm_state_topic.format(id=self.id, state=self.current_state)
        hassio.publish(self.state_topic, self.current_state, qos=qos_pub, retain=True)

        # self.attributes_topic = alarm_attributes_topic.format(id=self.id, attributes=self.attributes)
        # hassio.publish(self.attributes_topic, self.attributes, qos=qos_pub)
 
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

# Get pretty name for a device id
def get_name_from_id(id):
    name = ""
    if len(device_dict) != 0:
        name = device_dict[id]
    return(name)

# Generate 16 bytes random key for Sec-WebSocket-Keyand convert it to base64
def generate_random_key():
    return base64.b64encode(os.urandom(16))

# Build the headers of Digest Authentication
def build_digest_headers(nonce):
    digestAuth = HTTPDigestAuth(login, password)
    chal = dict()
    chal["nonce"] = nonce[2].split('=', 1)[1].split('"')[1]
    chal["realm"] = "ServiceMedia" if local is False else "protected area"
    chal["qop"] = "auth"
    digestAuth._thread_local.chal = chal
    digestAuth._thread_local.last_nonce = nonce
    digestAuth._thread_local.nonce_count = 1
    return digestAuth.build_digest_header('GET', "https://{}:443/mediation/client?mac={}&appli=1".format(host, mac))

# Send Generic GET message
async def send_message(websocket, msg):
    str = cmd_prefix + "GET " + msg +" HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"
    a_bytes = bytes(str, "ascii")
    await websocket.send(a_bytes)
    return 0
    # return await websocket.recv() #disable if handler

# Send Generic POST message
async def send_post_message(websocket, msg):
    str = cmd_prefix + "POST " + msg +" HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"
    a_bytes = bytes(str, "ascii")
    await websocket.send(a_bytes)
    return 0
    # return await websocket.recv()


###############################################################
# Commands                                                    #
###############################################################

# Get some information on Tydom
async def get_info(websocket):
    msg_type = '/info'
    await send_message(websocket, msg_type)

# Refresh (all)
async def post_refresh(websocket):
    if (websocket == None):
        print('Websocket not opened, reconnect...')
        await websocket_connection()
    else:
        print("Refresh....")
        msg_type = '/refresh/all'
        await send_post_message(websocket, msg_type)

# Get the moments (programs)
async def get_moments(websocket):
    msg_type = '/moments/file'
    await send_message(websocket, msg_type)

# Get the scenarios
async def get_scenarii(websocket):
    msg_type = '/scenarios/file'
    await send_message(websocket, msg_type)

# Get a ping (pong should be returned)
async def get_ping(websocket):
    msg_type = 'ping'
    await send_message(websocket, msg_type)

# Get all devices metadata
async def get_devices_meta(websocket):
    msg_type = '/devices/meta'
    await send_message(websocket, msg_type)

# Get all devices data
async def get_devices_data(websocket):
    msg_type = '/devices/data'
    await send_message(websocket, msg_type)

# List the device to get the endpoint id
async def get_configs_file(websocket):
    msg_type = '/configs/file'
    await send_message(websocket, msg_type)


async def get_data(websocket):
    if (websocket_connection == None):
        print('Websocket not opened, reconnect...')
        await websocket_connection()

    else:
        await get_configs_file(websocket)
        await asyncio.sleep(2)
        await get_devices_data(websocket)

# Give order (name + value) to endpoint
async def put_devices_data(websocket, endpoint_id, name, value):
    if (websocket_connection == None):
        print('Websocket not opened, reconnect...')
        await websocket_connection()
        
    else:
        # For shutter, value is the percentage of closing
        body="[{\"name\":\"" + name + "\",\"value\":\""+ value + "\"}]"
        # endpoint_id is the endpoint = the device (shutter in this case) to open.
        str_request = cmd_prefix + "PUT /devices/{}/endpoints/{}/data HTTP/1.1\r\nContent-Length: ".format(str(endpoint_id),str(endpoint_id))+str(len(body))+"\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"+body+"\r\n\r\n"
        a_bytes = bytes(str_request, "ascii")
        await websocket.send(a_bytes)

# Run scenario
async def put_scenarios(websocket, scenario_id):
    body=""
    # scenario_id is the id of scenario got from the get_scenarios command
    str_request = cmd_prefix + "PUT /scenarios/{} HTTP/1.1\r\nContent-Length: ".format(str(scenario_id))+str(len(body))+"\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n"+body+"\r\n\r\n"
    a_bytes = bytes(str_request, "ascii")
    await websocket.send(a_bytes)
    # name = await websocket.recv()
    # parse_response(name)

# Give order to endpoint
async def get_device_data(websocket, id):
    # 10 here is the endpoint = the device (shutter in this case) to open.
    str_request = cmd_prefix + "GET /devices/{}/endpoints/{}/data HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: application/json; charset=UTF-8\r\nTransac-Id: 0\r\n\r\n".format(str(id),str(id))
    a_bytes = bytes(str_request, "ascii")
    await websocket.send(a_bytes)
    # name = await websocket.recv()
    # parse_response(name)



# Basic response parsing. Typically GET responses
async def parse_response(incoming):
    data = incoming
    msg_type = None
    first = str(data[:20])
    
    # Detect type of incoming data
    if (data != ''):
        if ("id" in first):
            print('Incoming message type : data detected')
            msg_type = 'msg_data'
        elif ("date" in first):
            print('Incoming message type : config detected')
            msg_type = 'msg_config'
        elif ("doctype" in first):
            print('Incoming message type : html detected (probable 404)')
            msg_type = 'msg_html'
            print(data)
        elif ("productName" in first):
            print('Incoming message type : Info detected')
            msg_type = 'msg_info'
            print(data)        
        else:
            print('Incoming message type : no type detected')
            print(first)

        if not (msg_type == None):
            try:
                parsed = json.loads(data)
                # print(parsed)
                if (msg_type == 'msg_config'):
                    for i in parsed["endpoints"]:
                        # Get list of shutter
                        if i["last_usage"] == 'shutter':
                            # print('{} {}'.format(i["id_endpoint"],i["name"]))
                            device_dict[i["id_endpoint"]] = i["name"]
                                                
                            # TODO get other device type
                        if i["last_usage"] == 'alarm':
                            # print('{} {}'.format(i["id_endpoint"], i["name"]))
                            device_dict[i["id_endpoint"]] = "Tyxal Alarm"
                    print('Configuration updated')
                elif (msg_type == 'msg_data'):
                    for i in parsed:
                        attr = {}
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
                                    # print('{} : {}'.format(print_id, elementValue))
                                    new_cover = "cover_tydom_"+str(endpoint_id)
                                    print("Cover created / updated : "+new_cover)
                                    new_cover = Cover(id=endpoint_id,name=print_id, current_position=elementValue, attributes=i)
                                    new_cover.update()

                                # Get last known position (for alarm)
                                if elementName in deviceAlarmKeywords:
                                    alarm_data = '{} : {}'.format(elementName, elementValue)
                                    # print(alarm_data)
                                    # alarmMode  : ON or ZONE or OFF
                                    # alarmState : ON = Triggered
                                    # alarmSOS   : true = SOS triggered
                                    state = None
                                    sos = False
                                    
                                    if alarm_data == "alarmMode : ON":
                                        state = "armed_away"
                                    elif alarm_data == "alarmMode : ZONE":
                                        state = "armed_home"
                                    elif alarm_data == "alarmMode : OFF":
                                        state = "disarmed"
                                    elif alarm_data == "alarmState : ON":
                                        state = "triggered"
                                    elif alarm_data == "alarmSOS : true":
                                        sos = True
                                    else:
                                        attr[elementName] = [elementValue]
                                    #     attr[alarm_data]
                                        # print(attr)
                                    #device_dict[i["id_endpoint"]] = i["name"]
                                    if (sos == True):
                                        print("SOS !")
                                    if not (state == None):
                                        # print(state)
                                        alarm = "alarm_tydom_"+str(endpoint_id)
                                        print("Alarm created / updated : "+alarm)
                                        alarm = Alarm(id=endpoint_id,name="Tyxal Alarm", current_state=state, attributes=attr)
                                        alarm.update()
                elif (msg_type == 'msg_html'):
                    print("pong")
                else:
                    # Default json dump
                    print()
                    print(json.dumps(parsed, sort_keys=True, indent=4, separators=(',', ': ')))
            except Exception as e:
                print('Cannot parse response !')
                # print('Response :')
                # print(data)
                if (e != 'Expecting value: line 1 column 1 (char 0)'):
                    print("Error : ", e)


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
    return json.dumps(parsed)
    # print(json.dumps(parsed, sort_keys=True, indent=4, separators=(',', ': ')))

######## Messages Logic
async def consumer_handler(websocket):
    while True :
        try:
            await consumer(websocket)
        except Exception as e:
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print('Consumer handler task has crashed !')
            print("Error : ", e)
            error = "Webconnection consumer_handler error ! {}".format(e)
            if (hassio != None):
                hassio.publish('homeassistant/sensor/tydom/last_crash', str(error), qos=1, retain=True)
            print('Webconnection consumer_handler error, retrying in 8 seconds...')
            tydom = None
            await asyncio.sleep(8)
            await websocket_connection()

async def consumer(websocket):
    # Receiver
    # while True:
    bytes_str = await websocket.recv()
    print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
    # print(bytes_str)
    first = str(bytes_str[:40]) # Scanning 1st characters
    try:
        if ("refresh" in first):
            print('OK refresh message detected !')
            try:
                hassio.publish('homeassistant/sensor/tydom/last_update', str(datetime.fromtimestamp(time.time())), qos=1, retain=True)
            except:
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                print('RAW INCOMING :')
                print(bytes_str)
                print('END RAW')
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        if ("PUT /devices/data" in first):
            print('PUT /devices/data message detected !')
            try:
                incoming = parse_put_response(bytes_str)
                # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                await parse_response(incoming)
                print('PUT message processed !')
                print("##################################")
                hassio.publish('homeassistant/sensor/tydom/last_update', str(datetime.fromtimestamp(time.time())), qos=1, retain=True)
            except:
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                print('RAW INCOMING :')
                print(bytes_str)
                print('END RAW')
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        elif ("scn" in first):
            try:
                # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                incoming = get(bytes_str)
                await parse_response(incoming)
                print('Scenarii message processed !')
                print("##################################")
            except:
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                print('RAW INCOMING :')
                print(bytes_str)
                print('END RAW')
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")            
        elif ("POST" in first):
            try:
                # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                incoming = parse_put_response(bytes_str)
                await parse_response(incoming)
                print('POST message processed !')
                print("##################################")
            except:
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                print('RAW INCOMING :')
                print(bytes_str)
                print('END RAW')
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        elif ("HTTP/1.1" in first): #(bytes_str != 0) and 
            response = response_from_bytes(bytes_str[len(cmd_prefix):])
            incoming = response.data.decode("utf-8")
            # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
            # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
            # print(incoming)
            # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
            # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
            try:
                # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                await parse_response(incoming)
                print('Common / GET response message processed !')
                print("##################################")
                hassio.publish('homeassistant/sensor/tydom/last_update', str(datetime.fromtimestamp(time.time())), qos=1, retain=True)
            except:
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                print('RAW INCOMING :')
                print(bytes_str)
                print('END RAW')
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                # await parse_put_response(incoming)
        else:
            print("Didn't detect incoming type, here it is :")
            print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
            print('RAW INCOMING :')
            print(bytes_str)
            print('END RAW')
            print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
    except Exception as e: 
        print('Consumer task has crashed !')    
        print("Error : ", e)
        error = "Consumer crashed ! {}".format(e)
        if (hassio != None):
            hassio.publish('homeassistant/sensor/tydom/last_crash', str(error), qos=1, retain=True)
        print('Webconnection consumer error, retrying in 8 seconds...')
        tydom = None
        await asyncio.sleep(8)
        await websocket_connection()



async def producer_handler(websocket):
    while True :
        await producer(websocket)

async def producer(websocket):
    if (tydom != None):
        await asyncio.sleep(48)
        try:
         
            # await get_ping(websocket)
            await post_refresh(tydom)
            # await get_data(tydom)
            print("Websocket refreshed at ", str(datetime.fromtimestamp(time.time())))
        except Exception as e:
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            error = "Producer error ! {}".format(e)
            print(error)
            # if (hassio != None):
            #     hassio.publish('homeassistant/sensor/tydom/last_crash', str(error), qos=1, retain=True)
            print('Producer error, retrying in 8 seconds...')
    else: pass
######## HANDLER
async def handler(websocket):
    try:
        # print("Starting handlers...")
        consumer_task = asyncio.ensure_future(
            consumer_handler(websocket))
        producer_task = asyncio.ensure_future(
            producer_handler(websocket))
        # mqtt_task = asyncio.ensure_future(
        #     mqttconnection(mqtt_host, mqtt_user, mqtt_pass))
        done, pending = await asyncio.wait(
            [consumer_task, producer_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()

    except Exception as e:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        error = "Webconnection handler error ! {}".format(e)
        print(error)
        if (hassio != None):
            hassio.publish('homeassistant/sensor/tydom/last_crash', str(error), qos=1, retain=True)
        print('Webconnection handler error, retrying in 8 seconds...')
        tydom = None
        await asyncio.sleep(8)
        await main_task()



async def websocket_connection():
    global tydom
    httpHeaders =  {"Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Host": host + ":443",
                    "Accept": "*/*",
                    "Sec-WebSocket-Key": generate_random_key(),
                    "Sec-WebSocket-Version": "13"
                    }

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
    try:
        print('"Attempting websocket connection..."')
        ########## CONNECTION
        websocket = await websockets.client.connect('wss://{}:443/mediation/client?mac={}&appli=1'.format(host, mac),
                                             extra_headers=websocketHeaders, ssl=websocket_ssl_context)
        
        # async with websockets.client.connect('wss://{}:443/mediation/client?mac={}&appli=1'.format(host, mac),
        #                                     extra_headers=websocketHeaders, ssl=websocket_ssl_context) as websocket:
        
        
        tydom = websocket
        print("Tydom Websocket is Connected !", tydom)
        print("##################################")
        await get_info(tydom)
        print('Requesting 1st data...')
        await post_refresh(tydom)
        await get_data(tydom)

        while True:
            # await consumer(tydom) # Only receiving from socket in real time
            await handler(tydom) # If you want to send periodically something, disable await consumer(tydom)

    except Exception as e:
        print('Webconnection main error, retrying in 8 seconds...')
        
        error = "Websocket main connexion error ! {}".format(e)
        print(error)
        if (hassio != None):
            hassio.publish('homeassistant/sensor/tydom/last_crash', str(error), qos=1, retain=True)
        await asyncio.sleep(8)
        await websocket_connection()

# Main async task
async def main_task():
    print(str(datetime.fromtimestamp(time.time())))
    try:
        if (tydom == None) or not tydom.open or (hassio == None):
            print("##################################")
            start = time.time()
            if (enable_MQTT == True):
                print('MQTT is enabled')
                await mqttconnection(mqtt_client_id, mqtt_host, mqtt_user, mqtt_pass)
                hassio.publish('homeassistant/sensor/tydom/last_crash', '', qos=1, retain=True)

            else:
                print('MQTT is disabled')
            await websocket_connection()
            print('Connection total time :')
            end = time.time()
            print(end - start)

        else:
            print('Websocket is still opened ! requesting data...')
            await post_refresh(tydom)
    except Exception as e:

        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print('Connection total time :')
        end = time.time()
        print(end - start)
        print(str(datetime.fromtimestamp(time.time())))
        error = "Main task crashed ! {}".format(e)
        print(error)
        if (hassio != None):
            
            hassio.publish('homeassistant/sensor/tydom/last_crash', str(error), qos=1, retain=True)
        print('Main task crashed !, reconnecting in 8 s...')
        await asyncio.sleep(8)
        await main_task()

def start_loop():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main_task())
    loop.run_forever()

if __name__ == '__main__':
    while True:
        try:
            start_loop()
        except Exception as e:
            print('FATAL ERROR !')
            
            error = "FATAL ERROR ! {}".format(e)
            print(error)
            try:
                error = "FATAL ERROR ! {}".format(e)
                hassio.publish('homeassistant/sensor/tydom/last_crash', error, qos=1, retain=True)
            except:
                print("Error : ", e)
            os.excel("tydom2mqtt_restarter.sh","")
            sys.exit(-1)