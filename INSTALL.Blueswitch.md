- Building:

$ ./configure --with-debug --enable-blueswitch
$ make && make install

- Configuration

$ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=blueswitch fail-mode=secure -- add-port br0 nf1

- Interaction

Use the ovs-ofctl command with protocol version 1.3 enabled:

$ ovs-ofctl -OOpenFlow13 [cmd] [args ...]
