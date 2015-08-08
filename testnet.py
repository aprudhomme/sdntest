#!/usr/bin/env python

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.log import setLogLevel

class VLANHost( Host ):
    def config( self, vlan=5, ipoct=2, **params ):
        r = super( VLANHost, self ).config( **params )
        intf = self.defaultIntf()
        self.cmd( 'ip link add link %s name eth.%d type vlan id %d' % ( intf, vlan, vlan ) )
        self.cmd( 'ifconfig eth.%d 192.168.1.%d netmask 255.255.255.0 broadcast 192.168.1.255 up' % ( vlan, ipoct))
        return r

class TowerTopo( Topo ):
    """Create a tower topology"""

    def build( self, k=2, h=1 ):
        spines = []
        leaves = []
        hosts = []

        # Create the two spine switches
        spines.append(self.addSwitch('s1'))
        spines.append(self.addSwitch('s2'))

        # Create two links between the spine switches
        self.addLink(spines[0], spines[1])
        #TODO add second link between spines when multi-link topos are supported
        #self.addLink(spines[0], spines[1])
        
        # Now create the leaf switches, their hosts and connect them together
        i = 1
        c = 0
        while i <= k:
            leaves.append(self.addSwitch('s1%d' % i))
            for spine in spines:
                self.addLink(leaves[i-1], spine)

            j = 1
            while j <= h:
                hosts.append(self.addHost('h%d%d' % (i, j), cls=VLANHost, vlan=((c+1)*5), ipoct=(c+2)))
                self.addLink(hosts[c], leaves[i-1])
                j+=1
                c+=1

            i+=1

topos = { 'tower': TowerTopo }

def run():
    topo = TowerTopo()
    net = Mininet( topo=topo, controller=RemoteController, autoSetMacs=True )
    net.start()
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
