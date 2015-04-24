- Building:

$ ./configure --with-debug --enable-blueswitch --prefix=$OVS_INSTALL_ROOT
$ make && make install

- Configure shell environment

$ export OVS=$OVS_INSTALL_ROOT
$ export OVS_BIN=$OVS/sbin
$ export OVS_RUN=$OVS/var/run/openvswitch
$ alias vsctl="ovs-vsctl --db=unix:$OVS_RUN/db.sock"

- Starting OvS

# Start the DB server.

$ $OVS_BIN/ovsdb-server $OVS/etc/openvswitch/conf.db \
                      --remote=punix:$OVS_RUN/db.sock \
                      --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                      --pidfile=$OVS_RUN/ovsdb-server.pid \
                      --log-file=$OVS_RUN/ovsdb-server.log -v \
                      --unixctl=none

# Start OVS switch daemon.

$ $OVS_BIN/ovs-vswitchd --pidfile --log-file -v

- Initial system configuration

  In the below commands below, if just 'br0' does not work, you might need to
  add the full path to the control socket, i.e. 'unix:$OVS_RUN/br0.mgmt'.)

  In addition, if you see vsctl hang, add --no-wait as its first option.

$ vsctl add-br br0 \
     -- set bridge br0 datapath_type=blueswitch fail-mode=secure protocols=OpenFlow13

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
$ ofctl dump-ports br0

