- Building:

$ ./configure --with-debug --enable-blueswitch
$ make && make install

- Configuration

[$OVS_RUN is the run directory for OvS, usually /var/run/openvswitch.]

$ alias vsctl="ovs-vsctl --db=unix:$OVS_RUN/db.sock"

$ vsctl add-br br0 \
     -- set bridge br0 datapath_type=blueswitch fail-mode=secure

For each port:
$ vsctl add-port br0 nf0 -- set interface nf0 type=netfpga ofport_request=1
$ vsctl add-port br0 nf1 -- set interface nf1 type=netfpga ofport_request=2
$ vsctl add-port br0 nf2 -- set interface nf2 type=netfpga ofport_request=4
$ vsctl add-port br0 nf3 -- set interface nf3 type=netfpga ofport_request=6

- Interaction

Use the ovs-ofctl command with protocol version 1.3 enabled:

$ alias ofctl="ovs-ofctl -OOpenFlow13"

NOTE: Use the flow-mod 'priority' to specify the index of the rule entry in the switch table.

Example:
$ ofctl add-flow  br0 "table=0, priority=0, ip, nw_dst=192.168.1.1, actions=output=2"
$ ofctl del-flows br0 "table=0, ip, nw_dst=192.168.1.1"
$ ofctl dump-ports unix:$OVS_RUN/br0.mgmt

