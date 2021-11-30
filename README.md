# tydom_python

Example of Python Code (Python >= 3.5) to manage Tydom (Delta Dore) devices  
Need Tydom Gateway (I've used a Tydom 1.0)  
Code Reversed Engineered with help of Eli (creator of JeeDore plugin for Jeedom)  

*Modules required :*  

    pip install websockets requests
  
## Run with Docker:
Configure env:
```
    cp .env.default .env
```

Build docker image:
```
    ./scripts/build.sh
```

Run:
```
    ./scripts/run.sh
```

## Run without Docker:
Configure env:
```
    cp .env.default .env
```

Run:
```
    pip install -r requirements.txt
    python sources/main.py
```
  
Following commands are implemented :  

**get_info**  
Get some information on tydom (version ...)  
**get_ping**  
Just Send a ping message to the Tydom. Not useful  
**get_devices_meta**  
Get some metadata on the devices  
**get_devices_data**  
Get the data on the devices  
**get_configs_file**  
This one get the list of device declared on your tydom  
**put_devices_data**  
Give order to Tydom endpoint  

## Sources: 
- https://github.com/cth35/tydom_python
- https://github.com/WiwiWillou/tydom_python
- https://github.com/largotef/tydom_python
- https://github.com/mgcrea/node-tydom-client
- https://community.home-assistant.io/t/tydom2mqtt-make-delta-dore-devices-home-assistant-compatible/154439

