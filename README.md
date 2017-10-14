Tools to automate and/or expedite response.

### cblr-basic.py
Platforms: Carbon Black (Response)

Execute a basic response plan targeting a single endpoint.
Performs the following actions:

1. Isolate the endpoint. 
2. Kill associated processes.
3. Ban offending binary file(s).

### netconn-util.py
Platforms: Carbon Black (Response)

Enumerate network connections based on a wide variety of criteria. Includes
support for:

- process- and connection-based whitelists
- filtering by host type (Workstation or Server)
- more

### sensor-util.py
Platforms: Carbon Black (Response)

Enumerate sensors and output metadata, to include endpoint health.

### timeline.py
Platforms: Carbon Black (Response)

Generate a timeline of activity associated with a user, endpoint, or other
limiting criteria. 

### usb-util.py
Platforms: Carbon Black (Response)

Enumerate USB mass storage devices. 

NOTE: Only supports enumeration of devices on Windows endpoints.
