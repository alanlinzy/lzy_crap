import asyncio
import playground
import sys

from cmdHandler import *
from class_packet import *
from autograder_lab2_packets import *
# from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
# EnablePresetLogging(PRESET_DEBUG)


# bank params
USER_NAME_INIT_PKT = "test" # TODO:make sure of this
MY_UNAME           = "wli71"
MY_ACCOUNT         = "wli71_account"

def set_server_info(team):

    if team == 1:
        IP_ADDR = "20194.1.1.200"
        PORT    = 12345
    elif team == 2:
        IP_ADDR = "localhost"
        PORT    = 2222
    elif team == 3:
        IP_ADDR = "20194.3.6.9"
        PORT    = 333
    elif team == 4:
        IP_ADDR = "20194.4.4.4"
        PORT    = 8666
    elif team == 5:
        IP_ADDR = "20194.5.20.30"
        PORT    = 8989
    elif team == 6:
        IP_ADDR = "20194.6.20.30"
        PORT    = 16666
    elif team == 9:
        IP_ADDR = "20194.9.1.1"
        PORT    = 7826
    else:
        printError("No such team number in record, connect to team2 server")
        IP_ADDR = "localhost"
        PORT    = 2222
    return IP_ADDR, PORT

class ClientProtocol(asyncio.Protocol):
    def __init__(self, loop, firstPkt=None):
        self.loop = loop
        self.firstPkt = firstPkt
        self.bankManager = BankManager()
class ClientProtocol(asyncio.Protocol):
    def __init__(self, loop, firstPkt=None):
        self.loop = loop
        self.firstPkt = firstPkt
        self.bankManager = BankManager()

    def connection_made(self, transport):
        self.transport   = transport
        self.dataHandler = DataHandler(transport)
        self.peer_domain = self.transport.get_extra_info("peername")[0]
        self.peer_port   = self.transport.get_extra_info("peername")[1]
        printx("App Connection made to {}:{}".format(self.peer_domain, self.peer_port))
        asyncio.create_task(self.timer())

        if(self.firstPkt != None):
            self.send_init_game()
            # self.send_game_cmd()
        asyncio.get_event_loop().add_reader(sys.stdin,lambda: self.dataHandler.sendPktNoPrint(GameCommandPacket(command=input('>>'))))
        # asyncio.get_event_loop().add_reader(sys.stdin, lambda: self.dataHandler.sendPktNoPrint(self.send_init_game()))

    # def handle_input(self):
    async def timer(self):
        while True:
            printx("start time")
            await asyncio.sleep(30)
            self.send_init_game()


    def send_init_game(self):
        self.dataHandler.sendPkt(create_game_init_packet(USER_NAME_INIT_PKT))
    def send_game_cmd(self):
        self.dataHandler.sendPkt(GameCommandPacket(command="look"))

    def data_received(self, data):
        pkts = self.dataHandler.getPktsFromData(data)
        for pkt in pkts:
            asyncio.create_task(self.data_received_helper(pkt))

    async def data_received_helper(self, pkt):
        pktID = pkt.DEFINITION_IDENTIFIER
        # 1: respond to game payment request, make payment
        if pktID == GameRequirePayPacket.DEFINITION_IDENTIFIER:
            self.dataHandler.printPkt(pkt)
            # todo: play this
            # self.no_pay()
            # return
            id, account, amount = process_game_require_pay_packet(pkt)
            user_answer = input(
                "the amount you need to pay is {}, to confirm, enter \'y\', enter anything else to cancle:".format(amount))
            if(user_answer != 'y'):
                printx("the payment is cancled!")
            else:
                receipt, receipt_sig = await self.bankManager.transfer(MY_ACCOUNT, account, amount, id)
                if(receipt == None or receipt_sig == None):
                    printError("the bank transaction is not successful, so the process stopped")
                else:
                    self.dataHandler.sendPkt(create_game_pay_packet(receipt, receipt_sig))

        # 2: respond to game response, send game cmd
        elif pktID == GameResponsePacket.DEFINITION_IDENTIFIER:
            print(":" + pkt.response)
            # NOTE: this part's function is replaced by loop.add_reader()
            return

        else:
            printx("unknown pkt recived:" + pktID)

    def connection_lost(self, exc):
        printx('The server closed the connction, now stop the event loop')
        self.loop.stop()

    def no_pay(self):
        # receipt     = b'\x80\x03cBankCore\nLedgerLine\nq\x00)\x81q\x01}q\x02(X\x17\x00\x00\x00_LedgerLine__prevNumberq\x03M%\x03X\x13\x00\x00\x00_LedgerLine__numberq\x04M&\x03X\x15\x00\x00\x00_LedgerLine__accountsq\x05ccollections\nOrderedDict\nq\x06)Rq\x07X\r\x00\x00\x00wli71_accountq\x08]q\t(M"\x05K\nM"\x05esX\x15\x00\x00\x00_LedgerLine__completeq\n\x88X\x1c\x00\x00\x00_LedgerLine__transactionDateq\x0bX\x18\x00\x00\x00Fri Dec  6 19:35:58 2019q\x0cX\x1c\x00\x00\x00_LedgerLine__transactionMemoq\rX\n\x00\x00\x00dphjhhnfefq\x0eX \x00\x00\x00_LedgerLine__transactionAccountsq\x0fcbuiltins\nset\nq\x10]q\x11h\x08a\x85q\x12Rq\x13ub.'
        # receipt_sig = b"b\xa1\xa6\x1c\xd5|\xc5\xf1A\x0c\xd7Le\xbe\xe5\xbe\x84j\xc1\x19;\x80Z\xf2=\xd7B\xf2\x01\x8d?\xe7Z\x86Lw\x19\xac\xde\xc6\x91\xe8\xda=3\xca.\xba\xc9\xb2D)\xcb\x7f\xaf\x82\xb2\xf1\xd69\x0e\x87Z\xbet`\xf2\x04\xddZ\xa6\x87\x96.\x95b\x15\x1d@\xd0\x86(\nq\xf4\x0elx\xb6\x07\xecM\xb6\xd4k\xcfM\x8e\xf2\xb5-\xa3\xea\x1f9\xd3\xb1E\xc0X4W\xb4$:-p\xa7\xdc\x19V/\x8e\xa1\xfc\xf0\x1b\x95\xaaC\xd9\x86j\xf6\xca\xf5\x08\xf1\xfe\xd9{\x9f\xff\xcc\xea-\x12E\x96\xbd\xa5\xa5\xb3\xe7M?j\x8f\x7f\x0f|\x07!\x1c\xf5\x9eC\x06\xa2\x95\xb03\xed\xdf^\x96\xe3\x01\x0b\x10\x7f\x03\x88\x88\x81\xfd\xae\xc6\xb6\xe8X5\xc47\xd0\xc1\x84C8\xebG\xb9\xea\xe4\x18*\xda\x84[9.[\x8a\x04\xa2\xc21\x03\xce\xbe\xcf\xab\xb2\xa4'%]x\x1f\xdb\xad\x93\x86\xffq\nTb\x98\xae\xbbG\x0e.\xa2\x0f\x17\xf6*@\x81t\x80g\x19v"
        receipt = b'\x80\x03cBankCore\nLedgerLine\nq\x00)\x81q\x01}q\x02(X\x17\x00\x00\x00_LedgerLine__prevNumberq\x03M\xb9\x03X\x13\x00\x00\x00_LedgerLine__numberq\x04M\xba\x03X\x15\x00\x00\x00_LedgerLine__accountsq\x05ccollections\nOrderedDict\nq\x06)Rq\x07(X\x10\x00\x00\x00tnguy188_accountq\x08]q\t(M\xd6\x01K\x05M\xdb\x01eX\r\x00\x00\x00wli71_accountq\n]q\x0b(K\x00J\xfb\xff\xff\xffK\x00euX\x15\x00\x00\x00_LedgerLine__completeq\x0c\x88X\x1c\x00\x00\x00_LedgerLine__transactionDateq\rX\x18\x00\x00\x00Sat Dec  7 16:47:51 2019q\x0eX\x1c\x00\x00\x00_LedgerLine__transactionMemoq\x0fX\x13\x00\x00\x003486515589754568862q\x10X \x00\x00\x00_LedgerLine__transactionAccountsq\x11cbuiltins\nset\nq\x12]q\x13(h\x08h\ne\x85q\x14Rq\x15ub.'
        receipt_sig = b'\xad4\xcb\xab\x9a3\xc8me\x92\x17yF\xfa\x10\x8d@\xe1\x1b\x80[\x98C\x9f,g\xce\xa0\xf4>$\xe21\x00\x05W\xdd\x9b\xa2\xcb\xf6+\xf9\x9b"gY\x94\xbf\xa7k\x19\xea\x07\xb4\x14\xa3\xe5X\xcf\xce\x1d\x9f\xb6\xcc\x8b\'B\xe38O\xf0\xc3\x16S\xe3\x8ax\xe8etD\x16y\xb3x\x83\x83\x1fIi\xf5!\x80\xe4\x14]\xae\x15q\xf0\xb5\xb5\xcb-^\xbbu:Rq\xf1{k\xe9n\xb3\x1d\x0b\xe1\x9d\xad\x86\xd3tW>rg>\x91\x96e\xbd9\x15\x10\xfc\xe3\xf5c\x06\x0fR^\xe8\xdb\xf2\xb0*\x81\xe5\xb0_D\x8cs1``\xe4)V@\x8b,\x8bi"Y\x14e\xb0\xec\x12\xbe\x19H\xb9\x10\xa90o%\x07w2\xc1\xfe\x04\xbb\xb3\nF?\xe9\xdc\xfa\x90\xfbp+\xdf\xb8\xae\xdd\x1d\r\x82\x19 >\xe0K\xb1\x15\xde\x93\xf3N\xddq\xc0\xb1\xbc\x81\x86\xd3\x1c\n\xd7\x11\xffI\xbd!u\x9b\x97Z\x9baaf{\x05\xa9\xf0\xee\xcc\xe8\xd8A\xe7\xb2\x9d'
        # receipt = receipt_sig = ""
        self.dataHandler.sendPkt(create_game_pay_packet(receipt, receipt_sig))
def main(args):
    for i in range(0)
        IP_ADDR, PORT = set_server_info(team_num)
        if IP_ADDR =="localhost":
            continue
        loop = asyncio.get_event_loop()
        firstPkt = create_game_init_packet(USER_NAME_INIT_PKT)
        coro = playground.create_connection(lambda: ClientProtocol(loop=loop, firstPkt=firstPkt),
                                            IP_ADDR, PORT, family="crap_xjm_lab3")  # for E5
        loop.run_until_complete(coro)
        loop.run_forever()
        loop.close()


if __name__ == "__main__":
    main(sys.argv[1:])
