import getdns
import socket, fcntl, sys
from struct import pack, unpack


#
#  returns a tuple containing the network part of the ip 
#  address for the interface and the netmask, both encoded
#  in strings.  Definitely not portable to Windows, probably
#  not portable to some Unixes.  Unfortunately you have
#  to pass in the name of the interface; interface name
#  will be discovered in a future version
#

def get_network_info(ifname):
    SIOCGIFADDR = 0x8915
    SIOCGIFNETMASK = 0x891b

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    netmask = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, pack('256s',ifname))[20:24]
    addr = fcntl.ioctl(s.fileno(), SIOCGIFADDR, pack('256s', ifname))[20:24]
    return (pack('!I', (unpack('!I', addr)[0] & unpack('!I', netmask)[0])), netmask)
    

def main():
    CLIENT_SUBNET_OPCODE = 8
    LOCAL_INTERFACE = 'eth0'
    host = 'getdnsapi.net'
    
    if len(sys.argv) == 2:
        host = sys.argv[1]
    family = pack("!H", 1)  # start building the edns option fields
    source_netmask, address = get_network_info(LOCAL_INTERFACE)
    scope_netmask = pack("B", 0)

#
# encoding the binary data in strings makes it really easy
# to build packets by concatenating those strings
#
    payload = family + source_netmask + scope_netmask + address
    length = pack("!H", len(payload))
    ext = { 'add_opt_parameters': {'options':
                                       [ {'option_code': CLIENT_SUBNET_OPCODE,
                                          'option_data': length+payload} ] }}

    c = getdns.Context()
    c.resolution_type = getdns.RESOLUTION_STUB
    response = c.address(host, extensions=ext)

# do things with response ...
    print response

if __name__ == '__main__':
    main()
