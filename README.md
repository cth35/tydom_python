# tydom_python

Example of Python Code (Python >= 3.5) to manage Tydom (Delta Dore) devices<br />
Need Tydom Gateway (I've used a Tydom 1.0)<br />
Code Reversed Engineered with help of Eli (creator of JeeDore plugin for Jeedom)<br />

*Modules required :*
    
    pip install websockets requests

Following commands are implemented :<br />
 

**get_info**<br />
Get some information on tydom (version ...)<br />
**get_ping**<br />
Just Send a ping message to the Tydom. Not useful<br />
**get_devices_meta**<br />
Get some metadata on the devices<br />
**get_devices_data**<br />
Get the data on the devices<br />
**get_configs_file**<br />
This one get the list of device declared on your tydom<br />
**put_devices_data**<br />
Give order to Tydom endpoint<br />
