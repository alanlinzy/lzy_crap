import logging
import time
import asyncio
import datetime
import random
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key
from cryptography import x509
from ..poop.protocol import POOP

logger = logging.getLogger("playground.__connector__." + __name__)

# pakcet part
class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"

class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2

    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional:True})),
        ("nonceSignature", BUFFER({Optional:True})),
        ("signature", BUFFER({Optional:True})),
        ("pk", BUFFER({Optional:True})),
        ("cert", BUFFER({Optional:True}))
    ]
class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER)
    ]



class CRAPTransport(StackingTransport):
    def connect_protocol(self,protocol):
        self.protocol =protocol
    def write(self,data):
        self.protocol.send_data(data)
    def close(self):
        self.protocol.init_close()
    


# tls handshake part
class CRAP(StackingProtocol):
    def __init__(self,mode):
        super().__init__()
        self.mode = mode
        self.higher_transport = None
        self.deserializer = CrapPacketType.Deserializer()
        self.status = "LISTEN"
        self.nonce = random.randrange(1000000)
        

    def connection_made(self, transport):
        print("connection made crap")
        self.transport = transport
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)
        
        if self.mode == "client":
            print("client init")
            try:
                self.make_key()
                print("made key")
                pktstatus = 0
                pkt = HandshakePacket(status=pktstatus, pk=self.public_bytes(self.public_key,"pk"), signature=self.signature, cert=self.public_bytes(self.certificate,"cert"),nonce=self.nonce)
                self.transport.write(pkt.__serialize__())
                print("send packet")
                self.status = "HS_SENT"
                print("client handshake sent")
            except Exception as e:
                print(e)
            
    def send_error_handshake_pkt(self):
        pkt = HandshakePacket(status=2)
        self.transport.write(pkt.__serialize__())

    def make_key(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        
        self.public_key = self.private_key.public_key()

        self.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
        self.verification_key = self.signing_key.public_key()
        self.issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()) #no have it right now
        
        self.certificate = self.generate_cert(self.generate_subject("subjectname"),self.generate_subject("issuename"),self.verification_key,self.issuer_key)#something I need check which key to use
        
        self.signature = self.signing_key.sign(self.public_bytes(self.public_key,"pk"), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        
    def public_bytes(self,thesubject,check = ""):
        if check == "pk":
            return thesubject.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        elif check == "cert":
            return thesubject.public_bytes(Encoding.PEM)
        else:
            print("can't byte!")
            print(str(thesubject))
            return

    def data_received(self,buffer):
        print("recive packets!")
        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
            self.printpkt(pkt)
            if pkt.DEFINITION_IDENTIFIER == HandshakePacket().DEFINITION_IDENTIFIER:
                self.handshake_pkt_recv(pkt)
            elif pkt.DEFINITION_IDENTIFIER == DataPacket().DEFINITION_IDENTIFIER:
                self.data_pkt_recv(pkt)
            else:
                print("wrong packet!")

                
    def handshake_pkt_recv(self,pkt):
        if pkt.status == 2:
            print("ERROR PACKET")
            self.transport.close()
        
        elif self.status == "LISTEN":# server get the first packet
            if pkt.cert and pkt.pk and pkt.signture:
                if pkt.status == 0:
                    print("recvive client's first handshake packet")
                    if verify_signature(pkt):
                        self.make_key()
                        #verify
                        # verify the signiature  fail: send error else:pass
                        # generate its own ECDH public key
                        nonce_sig = self.generate_signature(self.signing_key, pkt.nonce)
                        #self.shared_key = private_key.exchange(ec.ECDH(), pkt.pk)
                        #self.derived_key = get_derived_key(shared_key)
                        pktstatus = 1 
                        sendpkt = HandshakePacket(status=pktstatus,nonceSignature=nonce_sig,pk=self.public_bytes(self.public_key,"pk"), signature=self.signature, cert=self.public_bytes(self.certificate,"cert"),nonce=self.nonce)
                        self.transport.write(sendpkt.__serialize__())
                        self.status = "HS_SENT"
                elif pkt.status == 1:
                    print("handshake packet status shouldn't be 1 when the server status is LISTEN")      
            else:
                print("miss handshake field")
                self.send_error_handshake_pkt()
        elif elf.status == "HS_SENT":#client and server already sent the first packet
            if pkt.status == 1:
                if self.mode == "client":
                    print("client handshake made")
                    if verify_signature(pkt) and verify_nonce(pkt):
                        #verify nonce and signature
                        self.shared_key = self.private_key.exchange(ec.ECDH(), pkt.pk)
                        self.derived_key = get_derived_key(shared_key)
                        nonce_sig = self.generate_signature(self.signing_key, pkt.nonce)
                        sendpkt = HandshakePacket(status=1, nonceSignature=nonce_sig)
                        self.transport.write(pkt.__serialize__())
                else:
                    if verify_nonce(pkt):
                        self.shared_key = self.private_key.exchange(ec.ECDH(), pkt.pk)
                        self.derived_key = get_derived_key(shared_key)
                        print("server handshake made")
                self.status = "ESTABILISHED"
                self.higherProtocol().connection_made(self.higher_transport)
                
                print("calling the higher transport")
        else:
            self.send_error_handshake_pkt()
        return
                
    def data_pkt_recv(self,pkt):
        print("send data packet")

    def generate_signature(self,sign_key,nonce):
        if type(data_to_sign) != bytes:
            nonce = bytes(nonce)
        return sign_key.sign( nonce, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

    def verify_nonce(self,pkt):
        print("verify nonce")
        if type(data_to_sign) != bytes:
            nonce = bytes(pkt.nonce)
        else:
            nonce = pkt.nonce
            
        try:
            self.peer_cert_public_key.verify(pkt.nonceSignature, nonce, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception as e :
            print(e)
            return False
        
    def verify_signature(self,pkt):
        print("verify signature")
        try:
            cert_to_verify = x509.load_pem_x509_certificate(pkt.cert, default_backend())
            self.peer_public_key = load_pem_public_key(pkt.pk, default_backend())
            self.peer_cert_public_key = cert_to_verify.public_key()
            self.issuer_public_key = ec.generate_private_key(ec.SECP384R1(), default_backend()).public_key()
            self.issuer_public_key.verify(cert_to_verify.signature,cert_to_verify.tbs_certificate_bytes,padding.PKCS1v15(),cert_to_verify.signature_hash_algorithm,)
            self.peer_cert_public_key.verify(pkt.signature, pkt.cert, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception as e :
            print(e)
            return False
        
                    
    def generate_subject(self, common_name):
        return x509.Name([
            #x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
            #x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            #x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
            #x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        ])

    def generate_cert(self, subject, issuer, cert_public_key, issuer_sign_key):
        return x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            cert_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(issuer_sign_key, hashes.SHA256(), default_backend())
    
    def get_derived_key(shared_key):
        return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',backend=default_backend()).derive(shared_key)
  

    def printpkt(self, pkt):  # try to print packet content
        print("--------------------")
        for f in pkt.FIELDS:
            fname = f[0]
            print(str(fname) + ": " + str(pkt._fields[fname]._data))
        print("--------------------")
        return
    def connection_lost(self, exc):
        print("connection lost")
        self.higherProtocol().connection_lost(exc)


        
def function():#(self, transport):
    #self.transport = transport
    if self.mode == "CLIENT" or True:
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        verification_key = signing_key.public_key()
        #certificate = x509.load_pem_x509_certificate(verification_key, default_backend())
        #certificate.public_bytes(serialization.Encoding.PEM)
        #x509subject = generate_subject("whatever")
        certificate = generate_cert("subjectname","issuename",public_key,signing_key)
        signature = signing_key.sign(public_key, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        #need to seriallize packet
        pkt = HandshakePacket(status=0, pk=public_key, signature=signature, cert=certificate)
        self.transport.write(pkt.__serialize__())
        shared_key = private_key.exchange(ec.ECDH(), pkt.pk)
        derived_key = get_derived_key(shared_key)
        return derived_key
                 



#encrypt transfor data part
import os

#from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, ciphertext, encryptor.tag)

def decrypt(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


CRAPClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: CRAP(mode="client"))

CRAPServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: CRAP(mode="server"))


'''
iv, ciphertext, tag = encrypt(
    key,
    b"a secret message!",
    b"authenticated but not encrypted payload"
)

print(decrypt(
    key,
    b"authenticated but not encrypted payload",
    iv,
    ciphertext,
    tag
))
'''






