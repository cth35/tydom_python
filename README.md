# tydom_python

Example of Python Code (Python >= 3.5) to manage Tydom (Delta Dore) devices<br />
Need Tydom Gateway (I've used a Tydom 1.0)<br />
Code Reversed Engineered with help of Eli (JeeDore plugin for Jeedom creator)<br />
<br />
Modules requires :
    
    pip install websockets requests

<br/>
Following commands are implemented :<br />
**get_info**            : Get some information on tydom (version ...)<br />
**get_ping**            : Just Send a ping message to the Tydom. Not useful<br />
**get_devices_meta**    :<br />
**get_devices_data**    :<br />
**get_configs_file**    : This one get the list of device declared on your tydom<br />
**put_devices_data**    : Give order to Tydom<br />
