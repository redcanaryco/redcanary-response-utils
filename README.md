Tools to automate and/or expedite response.

### Setup

```
git clone git@github.com:redcanaryco/redcanary-response-utils.git

mkvirtualenv redcanary-response-utils

python setup.py develop


./sensor-util.py

```

### cblr-basic.py
Platforms: Carbon Black (Response)

Execute a basic response plan targeting a single endpoint.
Performs the following actions:

1. Isolate the endpoint. 
2. Kill associated processes.
3. Ban offending binary file(s).

### network-util.py
Platforms: Carbon Black (Response)

Enumerate network connections based on a wide variety of criteria. Includes
support for:

- process- and connection-based whitelists
- filtering by host type (Workstation or Server)
- more

### process-util.py
Platforms: Carbon Black (Response)

Enumerate processes. This is a performant alternative to timeline.py if you
wish to quickly examine process start events only.

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
