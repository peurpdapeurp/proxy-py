
import sys

from pyndn import Name, Data, HmacWithSha256Signature, KeyLocatorType
from pyndn.security import KeyChain
from pyndn.util import Blob
from pyndn import Face, Interest
import time, random
from threading import Thread
from pyndn.encoding import ProtobufTlv
from datetime import datetime
import signal

from basic_insertion import requestInsert
from test_register_route import registerRouteWithNameAndIp

def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else str(element)) + " "
    print(result)

def handler(signal, frame):
    print('Caught keyboard interrupt, exiting...\n')
    global t
    global t2
    t = None
    t2 = None
    face.shutdown();
    with open('%s' % (deviceIDListName), 'a') as the_file:
        the_file.seek(0)
        the_file.truncate(0)
    exit()

def run_data_fetcher(str):

    os.system("dc-exp " + str + " /NIST/library/mainroom repo1")
    
class OnboardListener(object):
    def __init__(self, keyChain, certificateName):
        self._keyChain = keyChain
        self._certificateName = certificateName

    def onInterest(self, prefix, interest, face, interestFilterId, filter):

        key = Blob(bytearray([
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        ]))
        
        print "Got onboarding interest with name: %s" % (interest.getName().toUri())

        try:
            if KeyChain.verifyInterestWithHmacWithSha256(interest, key):
                dump("Onboarding interest signature verification: VERIFIED")
            else:
                dump("Onboarding interest signature verification: FAILED")
        except:
            print "Exception when attempting to verify onboarding interest signature."
    
        data = Data(interest.getName())
        signature = HmacWithSha256Signature()
        signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        signature.getKeyLocator().setKeyName(Name("key1"))
        data.setSignature(signature)
        data.setContent("")
        dump("Signing onboarding response data packet", data.getName().toUri())
        KeyChain.signWithHmacWithSha256(data, key)
    
        deviceID = str(interest.getName().getSubName(-3, 1).toUri()[1:])
        deviceIP = str(interest.getName().getSubName(-4, 1).toUri()[1:])
        
        print "Device ip: %s" % (deviceIP)
        print "Device ID: %s" % (deviceID)

        routeToRegister = str(Name(deviceID))
        
        registerRouteWithNameAndIp(routeToRegister, deviceIP)

        thread = threading.Thread(target=run_data_fetcher, args=(deviceID))
        thread.daemon = True                            # Daemonize thread
        thread.start()  

        #commandRouteToRegister = "/device/command/" + deviceID

        #registerRouteWithNameAndIp(commandRouteToRegister, deviceIP)

        face.putData(data)

        with open('%s' % (deviceIDListName), 'a') as the_file:
            the_file.seek(0)
            read_file = open('%s' % (deviceIDListName), 'r')
            if deviceID not in read_file.read():
                the_file.write('%s\n' % (deviceID))

        


    def onRegisterFailed(self, prefix):
        self._responseCount += 1
        dump("Register failed for prefix", prefix.toUri())

class SeqReqListener(object):
    def __init__(self, keyChain, certificateName):
        self._keyChain = keyChain
        self._certificateName = certificateName

    def onInterest(self, prefix, interest, face, interestFilterId, filter):

        print "Got interest for latest device seq num."

        deviceID = str(interest.getName().getSubName(-1, 1).toUri()[1:])
        
        file = open("../repo-ng/seq/%s.seq" % (deviceID), "r")
        deviceIDList = file.read()

        data = Data(interest.getName())
        signature = HmacWithSha256Signature()
        signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        signature.getKeyLocator().setKeyName(Name("key1"))
        data.setSignature(signature)
        data.setContent(deviceIDList)
        dump("Signing device ID List data packet", data.getName().toUri())
        KeyChain.signWithHmacWithSha256(data, key)

        face.putData(data)
        
    def onRegisterFailed(self, prefix):
        self._responseCount += 1
        dump("Register failed for prefix", prefix.toUri())

class DeviceIDReqListener(object):
    def __init__(self, keyChain, certificateName):
        self._keyChain = keyChain
        self._certificateName = certificateName

    def onInterest(self, prefix, interest, face, interestFilterId, filter):

        print "Got interest for device ID list."

        file = open("%s" % (deviceIDListName), "r")
        deviceIDList = file.read()

        data = Data(interest.getName())
        signature = HmacWithSha256Signature()
        signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        signature.getKeyLocator().setKeyName(Name("key1"))
        data.setSignature(signature)
        data.setContent(deviceIDList)
        dump("Signing device ID List data packet", data.getName().toUri())
        KeyChain.signWithHmacWithSha256(data, key)

        face.putData(data)

    def onRegisterFailed(self, prefix):
        self._responseCount += 1
        dump("Register failed for prefix", prefix.toUri())

class RepoDataRequestListener(object):
    def __init__(self, keyChain, certificateName):
        self._keyChain = keyChain
        self._certificateName = certificateName

    def onInterest(self, prefix, interest, face, interestFilterId, filter):

        print "Got interest for data from repo."

        # need to have code here to somehow serve the last data packet we retrieved from a sensor 
        
    def onRegisterFailed(self, prefix):
        self._responseCount += 1
        dump("Register failed for prefix", prefix.toUri())

        
def listenForOnboardingRequests():

    # Also use the default certificate name to sign data packets.
    onboardListener = OnboardListener(keyChain, keyChain.getDefaultCertificateName())
    prefix = Name("/NIST/library/mainroom/repo1/proxy/onboard")
    dump("Register prefix", prefix.toUri())
    face.registerPrefix(prefix, onboardListener.onInterest, onboardListener.onRegisterFailed)

    while True:
        face.processEvents()
        time.sleep(0.01)

def registerPrefixForSeqReq():

    seqReqListener = SeqReqListener(keyChain, keyChain.getDefaultCertificateName())
    prefix = Name("/NIST/library/mainroom/repo1/proxy").append("initialSeq")
    dump("Registering time stamp request prefix", prefix.toUri())
    face.registerPrefix(prefix, seqReqListener.onInterest, seqReqListener.onRegisterFailed)

def registerPrefixForDeviceIDReq():

    deviceIDReqListener = DeviceIDReqListener(keyChain, keyChain.getDefaultCertificateName())
    prefix = Name("/NIST/library/mainroom/repo1/proxy").append("deviceIDList")
    dump("Registering device IDs request prefix", prefix.toUri())
    face.registerPrefix(prefix, deviceIDReqListener.onInterest, deviceIDReqListener.onRegisterFailed)

global key
# Use a hard-wired secret for testing. In a real application the signer
# ensures that the verifier knows the shared key and its keyName.
key = Blob(bytearray([
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
]))

global face
# The default Face will connect using a Unix socket, or to "localhost".
face = Face()

global keychain
# Use the system default key chain and certificate name to sign commands.
keyChain = KeyChain()
face.setCommandSigningInfo(keyChain, keyChain.getDefaultCertificateName())

global repoCommandPrefix
repoCommandPrefix = Name("/localhost/repo1")
global repoDataPrefix
repoDataPrefix = Name("/NIST/library/mainroom/repo1")

global lastDeviceIDList
lastDeviceIDList = []
  
global deviceIDListName
deviceIDListName = "proxy-py/deviceInfo/DeviceIDList.txt"

global first_repo_insert_after_startup
first_repo_insert_after_startup = True

global tempSeq
tempSeq = 0

registerPrefixForDeviceIDReq()

registerPrefixForSeqReq()

t = Thread(target=listenForOnboardingRequests)
t.daemon = True
t.start()

signal.signal(signal.SIGINT, handler)

while True:
    t.join(600)
    if not t.isAlive():
        break
