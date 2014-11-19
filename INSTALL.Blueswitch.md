- Building:

 ./configure --with-debug --enable-blueswitch
 make && make install

- Configuration

ovs-vsctl add-br br0 -- set bridge br0 datapath_type=blueswitch -- add-port br0 nf1
