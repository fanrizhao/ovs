- Building:

$ ./configure --with-debug --enable-blueswitch
$ make && make install

- Configuration

$ ovs-vsctl add-br br0 \
         -- set bridge br0 datapath_type=blueswitch fail-mode=secure

For each port:
$ ovs-vsctl add-port br0 nf0 -- set interface nf0 type=netfpga ofport_request=1
$ ovs-vsctl add-port br0 nf1 -- set interface nf1 type=netfpga ofport_request=2
$ ovs-vsctl add-port br0 nf2 -- set interface nf2 type=netfpga ofport_request=4
$ ovs-vsctl add-port br0 nf3 -- set interface nf3 type=netfpga ofport_request=6

- Interaction

Use the ovs-ofctl command with protocol version 1.3 enabled:

$ ovs-ofctl -OOpenFlow13 [cmd] [args ...]

NOTE: Use the flow-mod 'priority' to specify the index of the rule entry in the switch table.

Example:
$ ovs-ofctl add-flow  -OOpenFlow13 br0 "table=0, priority=0, ip, nw_dst=192.168.1.1, actions=output=2"
$ ovs-ofctl del-flows -OOpenFlow13 br0 "table=0, ip, nw_dst=192.168.1.1"
