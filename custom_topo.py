#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time

def create_star_topology():
    """Create custom star topology with 4 switches and 12 hosts"""
    
    # Create Mininet object with remote controller
    net = Mininet(
        controller=RemoteController,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )
    
    info('*** Adding ONOS controller\n')
    # Add ONOS controller (replace with your EC2 instance IP if running separately)
    c0 = net.addController('c0', controller=RemoteController, 
                          ip='13.217.164.96', port=6653)
    
    info('*** Adding switches\n')
    # Add switches
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    
    info('*** Adding hosts\n')
    # Add hosts for each switch (3 hosts per switch)
    # Switch s1 hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    
    # Switch s2 hosts
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')
    
    # Switch s3 hosts
    h7 = net.addHost('h7', ip='10.0.0.7/24', mac='00:00:00:00:00:07')
    h8 = net.addHost('h8', ip='10.0.0.8/24', mac='00:00:00:00:00:08')
    h9 = net.addHost('h9', ip='10.0.0.9/24', mac='00:00:00:00:00:09')
    
    # Switch s4 hosts
    h10 = net.addHost('h10', ip='10.0.0.10/24', mac='00:00:00:00:00:10')
    h11 = net.addHost('h11', ip='10.0.0.11/24', mac='00:00:00:00:00:11')
    h12 = net.addHost('h12', ip='10.0.0.12/24', mac='00:00:00:00:00:12')
    
    info('*** Creating links\n')
    # Create star topology links (s2->s1, s3->s1, s4->s1)
    net.addLink(s2, s1)
    net.addLink(s3, s1)
    net.addLink(s4, s1)
    
    # Connect hosts to their respective switches
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    
    net.addLink(h4, s2)
    net.addLink(h5, s2)
    net.addLink(h6, s2)
    
    net.addLink(h7, s3)
    net.addLink(h8, s3)
    net.addLink(h9, s3)
    
    net.addLink(h10, s4)
    net.addLink(h11, s4)
    net.addLink(h12, s4)
    
    info('*** Starting network\n')
    net.start()
    
    # Wait for network to stabilize
    info('*** Waiting for network to stabilize...\n')
    time.sleep(3)
    
    # Start DNP3 outstations automatically
    info('*** Starting DNP3 outstations on h2-h12...\n')
    start_all_outstations(net)
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()
    
def start_all_outstations(net):
    """Start DNP3 outstations on hosts h2-h12"""
    
    outstation_configs = [
        ('h2', 2), ('h3', 3), ('h4', 4), ('h5', 5), ('h6', 6),
        ('h7', 7), ('h8', 8), ('h9', 9), ('h10', 10), ('h11', 11), ('h12', 12)
    ]
    
    for host_name, station_id in outstation_configs:
        host = net.get(host_name)
        cmd = f'/home/ubuntu/dnp3_env/bin/python3 /home/ubuntu/dnp3_scripts/dnp3_outstation.py --station-id {station_id}'
        
        info(f'*** Starting outstation on {host_name} (station {station_id})\\n')
        host.cmd(f'{cmd} &')
        time.sleep(0.3)
    
    info('*** Waiting for outstations to initialize...\\n')
    time.sleep(5)
    info('*** ✅ All outstations started\\n')

if __name__ == '__main__':
    setLogLevel('info')
    create_star_topology()