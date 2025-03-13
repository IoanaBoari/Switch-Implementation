SWITCH IMPLEMENTATION

In this project, I implemented a switch with basic switching functionalities, support for VLANs 
and Spanning Tree Protocol (STP), which is necessary to prevent loops in a network.

1.Switching Process
The switch is configured to automatically learn the MAC addresses of connected devices. 
When a frame is received on an interface, the switch records the source MAC address and associates it with that interface. 
This information is used to forward frames directly to the correct port, based on the destination MAC address.
Each time a frame is received, the source MAC address is added to the MAC table along with the associated interface. 
Thus, the switch keeps track of which port each device is connected to.
If the destination MAC address is known, the frame is sent to the associated interface. 
Otherwise, the frame is broadcast on all interfaces (except the one on which it was received).

2.VLAN
VLANs are used to logically separate network traffic, even if the devices are connected to the same physical switch. 
In this implementation, each port is associated with a VLAN ID, defined in the VLAN table. 
Trunk ports (with VLAN ID 0) can carry data for multiple VLANs, while access ports are assigned to a single VLAN.
Each switch configuration file defines the VLAN assignments for each port. 
For frames with known MAC addresses, the switch only forwards the frame if it belongs to the same VLAN. 
Broadcast frames are sent only on the interfaces within the same VLAN.

3.STP
STP is implemented to prevent network loops. The switch uses BPDU (Bridge Protocol Data Unit) frames to exchange information 
with other switches and determine the best path to the root bridge, thus preventing loops by blocking redundant paths. 
For this implementation, I chose to use a different BPDU structure than the one provided in the requirements because 
I considered that not all those fields contain useful information to demonstrate STP functionality.
Therefore, I used a simplified structure containing only the information I deemed necessary.
The root bridge periodically sends BPDU frames to announce its presence. A new BPDU unit is created and sent every second.
When a BPDU frame is received, the switch checks if the received BPDU indicates a better path to the root bridge. 
If so, it updates the information regarding root_bridge_id, root_path_cost, and root_port.
The function update_ports is used to block redundant paths, thereby preventing network loops.
