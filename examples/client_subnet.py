import getdns
from struct import pack, unpack
    

def main():
    CLIENT_SUBNET_OPCODE = 8
        
    address = '192.168.1.0'
    host = 'getdnsapi.net'
    source_len = 12
    
    family = pack("!H", 1)  # start building the edns option fields
    source_len = pack('!B', source_len)
    scope_len = pack('!B', 0)

#
# encoding the binary data in strings makes it really easy
# to build packets by concatenating those strings
#
    address = pack('!BBBB', 192, 168, 1, 0)
    payload = family + source_len + scope_len + address
    ext = { 'add_opt_parameters': {'options':
                                       [ {'option_code': CLIENT_SUBNET_OPCODE,
                                          'option_data': payload} ] }}

    c = getdns.Context()
    c.resolution_type = getdns.RESOLUTION_STUB
    response = c.address(host, extensions=ext)

# do things with response ...
    print response

if __name__ == '__main__':
    main()
