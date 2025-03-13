#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Global variables for STP (Spanning Tree Protocol) and VLAN configurations
root_bridge_id = -1       # ID of the root bridge in the STP topology
own_bridge_id = -1        # ID of this switch
root_path_cost = 0        # Cost to reach the root bridge
root_port = None          # Port used to reach the root bridge
mac_table = {}            # MAC address table
vlan_table = {}           # VLAN table mapping interfaces to VLAN IDs
interface_states = []     # Track the state (Blocking/Listening) of each interface
interfaces = []           # List of interfaces

def parse_ethernet_header(data):
    # Parse Ethernet frame header to get destination MAC, source MAC, EtherType, and VLAN ID
    dest_mac = data[0:6]
    src_mac = data[6:12]
    ether_type = (data[12] << 8) + data[13]

    # Check if the frame has a custom VLAN tag (EtherType 0x8200)
    vlan_id = -1
    if ether_type == 0x8200:  # 802.1Q VLAN tagged frame (TPID)
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # Extract VLAN ID from the 12-bit field
        ether_type = (data[16] << 8) + data[17]  # Update EtherType

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # Create a VLAN tag for Ethernet frames
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    # Periodically send BPDU frames if this switch is the root bridge
    while True:
        if own_bridge_id == root_bridge_id:
            for interface in interfaces:
                # Only send on trunk ports
                if vlan_table.get(get_interface_name(interface)) != 'T':
                    continue
                bpdu_pack = build_bpdu()
                send_to_link(interface, len(bpdu_pack), bpdu_pack)
        time.sleep(1)

def build_bpdu():
    # Build a simplified BPDU (Bridge Protocol Data Unit) frame for STP
    
    # Multicast MAC address for STP BPDU frames
    multicast_mac = struct.pack('!BBBBBB', 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00)
    # Bridge ID (8 bytes): ID of this switch
    own_bridge_bytes = struct.pack('!Q', own_bridge_id)
    # Root Bridge ID (8 bytes): ID of the root bridge
    root_bridge_bytes = struct.pack('!Q', root_bridge_id)
    # Path Cost to Root (4 bytes): Cost to reach the root bridge
    path_cost = struct.pack('!I', root_path_cost)
    # Source MAC (MAC address of the switch)
    src_mac = get_switch_mac()
    
    # Combine all parts to form the complete BPDU frame
    bpdu = (
        multicast_mac +
        own_bridge_bytes +
        root_bridge_bytes +
        path_cost +
        src_mac
    )
    
    return bpdu

def is_unicast(mac_address):
    # Check if the MAC address is unicast.
    return mac_address[0] & 1 == 0

def get_vlan_id(vlan):
    # Return VLAN ID as an integer (0 for trunk ports).
    return 0 if vlan == 'T' else int(vlan)

def forward_unicast(dest_mac, vlan_id, frame, frame_length, frame_no_tag):
    # Forward unicast frame to the specified destination MAC address
    target_interface = mac_table[dest_mac]
    target_vlan = get_vlan_id(vlan_table.get(get_interface_name(target_interface)))
    if target_vlan == 0:
        send_to_link(target_interface, frame_length, frame)
    else:
        send_to_link(target_interface, frame_length - 4, frame_no_tag)

def forward_broadcast(vlan_id, src_interface, frame, frame_length, frame_no_tag):
    # Broadcast frames to all ports within the same VLAN
    for interface in interfaces:
        if interface == src_interface or not interface_states[interface]:
            continue
        target_vlan = get_vlan_id(vlan_table.get(get_interface_name(interface)))
        if target_vlan == 0:
            send_to_link(interface, frame_length, frame)
        elif target_vlan == vlan_id:
            send_to_link(interface, frame_length - 4, frame_no_tag)

def forward_trunk(dest_mac, vlan_id, src_interface, frame, frame_length):
    # Forward frames on trunk ports based on VLAN ID
    frame_no_tag = frame[0:12] + frame[16:]  # Remove VLAN tag for trunk forwarding
    if is_unicast(dest_mac) and dest_mac in mac_table:
        forward_unicast(dest_mac, vlan_id, frame, frame_length, frame_no_tag)
    else:
        forward_broadcast(vlan_id, src_interface, frame, frame_length, frame_no_tag)

def forward_access(dest_mac, vlan_id, src_interface, frame, frame_length):
    # Forward frames on access ports, adding VLAN tag if necessary
    frame_with_tag = frame[0:12] + create_vlan_tag(vlan_id) + frame[12:]
    if is_unicast(dest_mac) and dest_mac in mac_table:
        forward_unicast(dest_mac, vlan_id, frame_with_tag, frame_length + 4, frame)
    else:
        forward_broadcast(vlan_id, src_interface, frame_with_tag, frame_length + 4, frame)

def process_bpdu(src_interface, frame):
    # Process a received BPDU frame and update root bridge information if necessary
    global root_bridge_id, root_path_cost, root_port
    # Extract Root Bridge ID from the BPDU frame
    received_root_bridge_id = int.from_bytes(frame[14:22], byteorder='big')
    # Extract Path Cost to Root from the BPDU frame
    received_path_cost = int.from_bytes(frame[22:26], byteorder='big')
    # Update root bridge information if a better path is found
    if (received_root_bridge_id < root_bridge_id) or (received_root_bridge_id == root_bridge_id and received_path_cost + 10 < root_path_cost):
        # Update root bridge information
        root_bridge_id = received_root_bridge_id
        root_path_cost = received_path_cost + 10
        root_port = src_interface
        
        # Update port states if the root has changed
        update_ports()

def update_ports():
    # Update port states based on the root port (Blocking/Listening)
    for i in interfaces:
        if i != root_port and vlan_table.get(get_interface_name(i)) == 'T':
            interface_states[i] = False
    if not interface_states[root_port]:
        interface_states[root_port] = True

def main():
    global own_bridge_id, root_bridge_id, root_path_cost, mac_table, vlan_table, interface_states, interfaces
    
    # Initialize the switch and its configuration
    switch_id = sys.argv[1]
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    interface_states = [True] * num_interfaces  # All interfaces start in Listening state

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Read VLAN and bridge ID configurations from configs directory
    config_file = f'configs/switch{switch_id}.cfg'
    with open(config_file, 'r') as f:
        own_bridge_id = int(f.readline().strip())  # Set own bridge ID
        root_bridge_id = own_bridge_id  # Initially assume this switch is also root bridge
        root_path_cost = 0
        for line in f:
            port_name, vlan_info = line.split()
            vlan_table[port_name] = vlan_info

    # Create and start a new thread for sending BPDU frames
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Main loop for receiving and forwarding frames
    while True:
        interface, frame, frame_length = recv_from_any_link()
        if not interface_states[interface]:  # Skip blocked ports
            continue

        # Process BPDU frames
        if frame[0:6] == b'\x01\x80\xc2\x00\x00\x00':
            process_bpdu(interface, frame)
            continue
        
        # Parse frame and update MAC table
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(frame)
        if vlan_id == -1:
            vlan_id = get_vlan_id(vlan_table.get(get_interface_name(interface)))

        mac_table[src_mac] = interface  # Update MAC table entry
        source_vlan_id = get_vlan_id(vlan_table.get(get_interface_name(interface)))

        # Forward frame based on port type (trunk or access)
        if source_vlan_id == 0:
            forward_trunk(dest_mac, vlan_id, interface, frame, frame_length)
        else:
            forward_access(dest_mac, vlan_id, interface, frame, frame_length)

if __name__ == "__main__":
    main()
