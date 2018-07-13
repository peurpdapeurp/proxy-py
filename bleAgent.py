
from bluepy.btle import Scanner, DefaultDelegate, Peripheral, UUID
import binascii
import sys

from pyndn import Name
from pyndn import Data
from pyndn import ContentType
from pyndn import KeyLocatorType
from pyndn import DigestSha256Signature
from pyndn import Sha256WithRsaSignature
from pyndn import Sha256WithEcdsaSignature
from pyndn import HmacWithSha256Signature
from pyndn import GenericSignature
from pyndn.security import KeyChain
from pyndn.security import SafeBag
from pyndn.security.v2 import Validator
from pyndn.security.v2 import ValidationPolicyFromPib
from pyndn.util import Blob

esp32Address = ""
foundNistSensor = 0
      
def dump(*list):
    result = ""
    for element in list:
        result += (element if type(element) is str else repr(element)) + " "
    print(result)

class ScanDelegate(DefaultDelegate):
      def __init__(self):
            DefaultDelegate.__init__(self)
            
      def handleDiscovery(self, dev, isNewDev, isNewData):
            if isNewDev:
                  for (adtype, desc, value) in dev.getScanData():
                        if desc == "Complete Local Name" and value == "nist_sensor":
                              print "Found a nist sensor wanting to be onboarded, MAC address: %s" % (dev.addr)
                              #print "Device address: %s" % (dev.addr)
                              #print "Address type: %s" % (dev.addrType)
                              #print "Rssi: %s" % (dev.rssi)

                              global esp32Address
                              esp32Address = dev.addr

                              global foundNistSensor
                              foundNistSensor = 1
                              
            #elif isNewData:
                  #print "Received new data from", dev.addr
                        

def scanForNistSensors():

    scanner = Scanner().withDelegate(ScanDelegate())
    scanner.scan(.1)

    if foundNistSensor == 0:
        print "Didn't find any nist sensors..."
        return False

    p = Peripheral(esp32Address)
    p.setMTU(500)

    #svcList = p.getServices()
    #print "Handle   UUID                                Properties"
    #print "-------------------------------------------------------"
    #for svc in svcList:
    #      print (str(svc.uuid))
    
    #chList = p.getCharacteristics()
    #print "Handle   UUID                                Properties"
    #print "-------------------------------------------------------"
    #for ch in chList:
    #         print ("  0x"+ format(ch.getHandle(),'02X')  +"   "+str(ch.uuid) +" " + ch.propertiesToString())

    nist_service_uuid = UUID("0000ffe0-0000-1000-8000-00805f9b34fb")
    nist_characteristic_uuid = UUID("beb5483e-36e1-4688-b7f5-ea07361b26a8")

    nistService = p.getServiceByUUID(nist_service_uuid)
    #nistCharacteristic = p.getCharacteristics(nist_characteristic_uuid)[0]
    nistCharacteristic = nistService.getCharacteristics("beb5483e-36e1-4688-b7f5-ea07361b26a8")[0]

    #readBytes = bytes(p.readCharacteristic(0x2A))
    #readBytes = bytes(nistCharacteristic.read())

    #print binascii.hexlify(readBytes)

    #with open('/home/pi/Desktop/esp32-ndn-ble/src/readBytes.txt', 'a') as the_file:
    #      the_file.seek(0)
    #      the_file.truncate()
    #      the_file.write(binascii.hexlify(readBytes))

    #TlvData = Blob(readBytes)

    #data = Data()
    #data.wireDecode(TlvData)

    # Use a hard-wired secret for testing. In a real application the signer
    # ensures that the verifier knows the shared key and its keyName.
    key = Blob(bytearray([
       0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    ]))

    #if KeyChain.verifyDataWithHmacWithSha256(data, key):
    #  dump("Hard-coded data signature verification: VERIFIED")
    #else:
    #  dump("Hard-coded data signature verification: FAILED")

    freshData = Data(Name("/netInfo"))
    signature = HmacWithSha256Signature()
    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
    signature.getKeyLocator().setKeyName(Name("key1"))
    freshData.setSignature(signature)
    freshData.setContent("EdwardPi\n11111111\n192.168.4.1\n")
    dump("Signing fresh data packet", freshData.getName().toUri())
    KeyChain.signWithHmacWithSha256(freshData, key)

    if KeyChain.verifyDataWithHmacWithSha256(freshData, key):
      dump("Freshly-signed data signature verification: VERIFIED")
    else:
      dump("Freshly-signed data signature verification: FAILED")

    bytesSend = freshData.wireEncode()

    print binascii.hexlify(bytes(bytesSend))

    try:
        nistCharacteristic.write(bytes(bytesSend), True)
    except:
        print "Exception when trying to write to BLE characteristic."

scanForNistSensors()
