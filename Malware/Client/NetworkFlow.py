import time, logging
from concurrent.futures import ProcessPoolExecutor

class NetworkFlow():

    def __init__(self):
        self._startFlowTime = time.time()
        self.transmissions = {"packetsSentTimestamps" : [], "packetsReceivedTimestamps:" : []}
        print("Started initial network flow timestamp")
        logging.debug("Started initial network flow timestamp")

    def package_sent_add_timestamp(self):
        self.transmissions["packetsSentTimestamps"].append(time.time())

    def package_received_add_timestamp(self):
        self.transmissions["packetsReceivedTimestamps"].append(time.time())

    def get_latest_transmissionsSent_timestamp(self):
        return self.transmissions["packetsSentTimestamps"][-1]

    def get_latest_transmissionsReceived_timestamp(self):
        return self.transmissions["packetsReceivedTimestamps"][-1]

    def get_startflowtime(self):
        return self._startFlowTime
