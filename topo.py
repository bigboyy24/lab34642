from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.link import Intf

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        
        firstHost = self.addHost( 'h1' )
        secondHost = self.addHost( 'h2' )
        thirdHost = self.addHost( 'h3' )
        fourthHost= self.addHost( 'h4' )

        mainSwitch = self.addSwitch( 's1' )
 #       self.Intf('eth0', node = mainSwitch)
       

        # Add links
        self.addLink( firstHost, mainSwitch)
        self.addLink( secondHost, mainSwitch)
        self.addLink( thirdHost, mainSwitch)
        self.addLink( fourthHost, mainSwitch)


topos = { 'mytopo': ( lambda: MyTopo() ) }

def main():
    setLogLevel('info')
    tp = MyTopo()
    net = Mininet(tp, controller=RemoteController(ip='127.0.0.1', name='RyuController'), autoStaticArp=True)
    net.addNAT().configDefault()
    net.start()

    dumpNodeConnections(net.hosts)
    # net.staticArp()  # Not needed if autoStaticArp=True
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
