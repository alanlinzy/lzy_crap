import protocol
from playground.common.logging import EnablePresetLogging, PRESET_DEBUG, PRESET_VERBOSE
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToStorageStream as MockTransport
import unittest
# import sys
# import os
# sys.path.insert(0, os.path.abspath('.'))


def print_pkt(pkt):  # try to print packet content
    print("-----------")
    for f in pkt.FIELDS:
        f_name = f[0]
        print(str(f_name) + ": " + str(pkt._fields[f_name]._data))
    print("-----------")
    return


class ListWriter:
    def __init__(self, l):
        self.l = l

    def write(self, data):
        self.l.append(data)
        
class DummyApplication(asyncio.Protocol):
    def __init__(self):
        self._connection_made_called = 0
        self._connection_lost_called = 0
        self._data = []
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport
        self._connection_made_called += 1

    def connection_lost(self, reason=None):
        self._connection_lost_called += 1

    def data_received(self, data):
        self._data.append(data)
        print('Application data received: ' + data.decode('utf-8'))

    def pop_all_data(self):
        data = b""
        while self._data:
            data += self._data.pop(0)
        return data
class Test_handshake(unittest.TestCase):
    def setUp(self):
        self.c_crap = CRAP(mode="client")
        self.s_crap = CRAP(mode="server")

        self.client = DummyApplication()
        self.server = DummyApplication()

        self.c_crap.setHigherProtocol(self.client)
        self.s_crap.setHigherProtocol(self.server)

        self.client_write_storage = []
        self.server_write_storage = []

        self.client_transport = MockTransport(
            ListWriter(self.client_write_storage))
        self.server_transport = MockTransport(
            ListWriter(self.server_write_storage))

        self.deserializer = CrapPacketType.Deserializer()
    def get_client_last_write_pkt(self):
        s = self.client_write_storage
        if not s:
            return None
        else:
            self.deserializer.update(s.pop())
            for pkt in self.deserializer.nextPackets():
                return pkt

    def get_server_last_write_pkt(self):
        s = self.server_write_storage
        if not s:
            return None
        else:
            self.deserializer.update(s.pop())
            for pkt in self.deserializer.nextPackets():
                return pkt

