import argparse
import logging

from cbapi.response import BannedHash
from cbapi.response.models import Process, Sensor
from cbapi.response.rest_api import CbEnterpriseResponseAPI

logging.basicConfig(level=logging.INFO)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--hostname", type=str, action="store",
                        help="Target a specific hostname.")
    parser.add_argument("--process-name", type=str, action="store",
                        help="Name of the process to kill.")
    args = parser.parse_args() 

    # Connect to Cb Response
    cb = CbEnterpriseResponseAPI()

    # Target hostname and process
    sensor = cb.select(Sensor).where("hostname:{0}".format(args.hostname))[0]
    target_process = args.process_name

    # Isolate sensor
    sensor.network_isolation_enabled = True
    sensor.save()
    
    # Initiate Live Response session
    cblr = cb.live_response.request_session(sensor.id)
    
    # Find processes by name, then kill them.
    process_list = cblr.list_processes()
    target_pids = [proc['pid'] for proc in process_list if target_process in proc['path']]
    for pid in target_pids:
        cblr.kill_process(pid)

    # Ban the hash
    process_list = cb.select(Process).where("process_name:{0}".format(args.process_name))
    target_md5s = set()
    for process in process_list:
        target_md5s.add(process.process_md5)

    for md5 in target_md5s:
        banned_hash = cb.create(BannedHash)
        banned_hash.md5hash = md5
        banned_hash.text = "Banned by Joe Dirt"
        banned_hash.enabled = True
        banned_hash.save()


if __name__ == '__main__':

    main()


