from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

class IDSTopo(Topo):
    def build(self):
        s1= self.addSwitch("s1",protocols="OpenFlow13")

        h1= self.addHost("h1", ip = "10.0.0.1/24") # server / victim
        h2= self.addHost("h2", ip = "10.0.0.2/24") # normal client
        h3= self.addHost("h3", ip = "10.0.0.3/24") # normal client
        h4= self.addHost("h4", ip = "10.0.0.4/24") # attacker

        for h in [h1,h2,h3,h4]:
            self.addLink(h,s1, bw=10 )

def run():
    net = Mininet(topo=IDSTopo(), controller=None, switch=OVSSwitch, link=TCLink)
    net.addController("c0",controller=RemoteController,ip="127.0.0.1",port=6653)
    net.start()
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    run()