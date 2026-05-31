import socket
import glob
import json

port = 53

ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def load_zones():
    jsonzone = {}
    zonefiles = glob.glob("zones/*.zone")

    for zone in zonefiles:
        with open(zone, 'r') as f:
            data = json.load(f)

            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone

zonedata = load_zones()

def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    rflags = ''

    QR = '1'

    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += str(ord(byte1) & (1 << bit))

    AA = '1'

    TC = '0'

    RD = '0'

    RA = '0'

    Z ='000'

    RCODE = '0000'

    return int(QR+OPCODE+AA+TC+RD,2).to_bytes(1, byteorder='big') + int(RA+Z+RCODE,2).to_bytes(1, byteorder='big')

def getquestiondomain(data):
    state = 0
    expected_length = 0
    domainstring = ""
    domainparts = []
    x = 0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expected_length:
                domainparts.append(domainstring)
                domainstring = ""
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expected_length = byte
        y += 1

    questiontype = data[y:y+2]

    print(questiontype)

    # print(f"Domain: {'.'.join(domainparts)}")
    # print(f"Question Type: {questiontype}")

    return (domainparts, questiontype)

def getzone(domain):
    global zonedata

    zone_name = '.'.join(domain)
    return zonedata.get(zone_name)

def getrecs(data):
    domain, questionType = getquestiondomain(data)

    qt = ''
    if questionType == b'\x00\x01':
        qt = 'a'

    zone = getzone(domain)

    return (zone[qt], qt, domain)

def buildquestion(domain, qt):
    question = b''

    for part in domain:
        length = len(part)
        question += bytes([length])

        for char in part:
            question += ord(char).to_bytes(1, byteorder='big')

    if qt == 'a':
        question += (1).to_bytes(2, byteorder='big')

    question += (1).to_bytes(2, byteorder='big')

    return question

def rectobytes(domain, qt, ttl, value):
    record = b'\xc0\x0c'

    if qt == 'a':
        record += bytes([0]) + bytes([1])

    record += bytes([0]) + bytes([1])

    record += int(ttl).to_bytes(4, byteorder='big')

    if qt == 'a':
        record += bytes([0]) + bytes([4])

        for octet in value.split('.'):
            record += bytes([int(octet)])

    return record

def buildresponse(data):

    #Transaction ID
    transaction_id = data[0:2]

    #Flags
    flags = getflags(data[2:4])

    #Question Count
    QDCOUNT = b'\x00\x01'

    #Answer Count
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    #Name Server Count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    #Additional Count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = transaction_id + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    dnsbody = b''

    #Get answer
    records, qt, domain = getrecs(data[12:])

    dnsquestion = buildquestion(domain, qt)

    for record in records:
        dnsbody += rectobytes(domain, qt, record['ttl'], record['value'])

    return dnsheader + dnsquestion + dnsbody

while True:
    data, addr = sock.recvfrom(512)
    # print(f"Received data from {addr}: {data}")

    r = buildresponse(data)

    sock.sendto(r, addr)