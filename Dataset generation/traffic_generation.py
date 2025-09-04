from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from datetime import datetime
from random import randrange, choice, sample, random, randint

class MyTopo(Topo):

    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h1 = self.addHost('h1', cpu=1.0/20, mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost('h2', cpu=1.0/20, mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost('h3', cpu=1.0/20, mac="00:00:00:00:00:03", ip="10.0.0.3/24")

        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h4 = self.addHost('h4', cpu=1.0/20, mac="00:00:00:00:00:04", ip="10.0.0.4/24")
        h5 = self.addHost('h5', cpu=1.0/20, mac="00:00:00:00:00:05", ip="10.0.0.5/24")
        h6 = self.addHost('h6', cpu=1.0/20, mac="00:00:00:00:00:06", ip="10.0.0.6/24")

        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h7 = self.addHost('h7', cpu=1.0/20, mac="00:00:00:00:00:07", ip="10.0.0.7/24")
        h8 = self.addHost('h8', cpu=1.0/20, mac="00:00:00:00:00:08", ip="10.0.0.8/24")
        h9 = self.addHost('h9', cpu=1.0/20, mac="00:00:00:00:00:09", ip="10.0.0.9/24")

        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h10 = self.addHost('h10', cpu=1.0/20, mac="00:00:00:00:00:10", ip="10.0.0.10/24")
        h11 = self.addHost('h11', cpu=1.0/20, mac="00:00:00:00:00:11", ip="10.0.0.11/24")
        h12 = self.addHost('h12', cpu=1.0/20, mac="00:00:00:00:00:12", ip="10.0.0.12/24")

        s5 = self.addSwitch('s5', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h13 = self.addHost('h13', cpu=1.0/20, mac="00:00:00:00:00:13", ip="10.0.0.13/24")
        h14 = self.addHost('h14', cpu=1.0/20, mac="00:00:00:00:00:14", ip="10.0.0.14/24")
        h15 = self.addHost('h15', cpu=1.0/20, mac="00:00:00:00:00:15", ip="10.0.0.15/24")

        s6 = self.addSwitch('s6', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h16 = self.addHost('h16', cpu=1.0/20, mac="00:00:00:00:00:16", ip="10.0.0.16/24")
        h17 = self.addHost('h17', cpu=1.0/20, mac="00:00:00:00:00:17", ip="10.0.0.17/24")
        h18 = self.addHost('h18', cpu=1.0/20, mac="00:00:00:00:00:18", ip="10.0.0.18/24")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)

        self.addLink(h7, s3)
        self.addLink(h8, s3)
        self.addLink(h9, s3)

        self.addLink(h10, s4)
        self.addLink(h11, s4)
        self.addLink(h12, s4)

        self.addLink(h13, s5)
        self.addLink(h14, s5)
        self.addLink(h15, s5)

        self.addLink(h16, s6)
        self.addLink(h17, s6)
        self.addLink(h18, s6)

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)

def ip_generator():
    """Generates a random IP address within the 10.0.0.x subnet."""
    return "10.0.0." + str(randrange(1, 19))

def attackGeneration(net):
    """Generates different types of attack traffic in the network"""
    # Write label=1 to indicate attack traffic
    with open("traffic_label.txt", "w") as f:
        f.write("1")
        
    print("Generating attack traffic ...")
    # Get all hosts
    hosts = []
    for i in range(1, 19):
        hosts.append(net.get(f'h{i}'))

    # Setup web server
    h1 = net.get('h1')
    h1.cmd('cd /home/spc/master/webserver')
    h1.cmd('python3 -m http.server 80 &')

    # Generate different attacks
    print("--------------------------------------------------------------------------------")
    
    # Smurf Attack / ICMP Flood
    src, dst_host = sample(hosts, 2)
    dst = dst_host.IP()
    print("Performing Smurf")  
    print("--------------------------------------------------------------------------------")   
    src.cmd("timeout 20s hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood {}".format(dst))  
    sleep(100)
    
    # UDP-Flood Attack
    src, dst_host = sample(hosts, 2)
    dst = dst_host.IP()   
    print("--------------------------------------------------------------------------------")
    print("Performing UDP-Flood")  
    print("--------------------------------------------------------------------------------")   
    src.cmd("timeout 20s hping3 -2 -V -d 120 -w 64 --rand-source --flood {}".format(dst))    
    sleep(100)
    
    # SIDDOS Attack
    src, dst_host = sample(hosts, 2)
    dst = dst_host.IP()    
    print("--------------------------------------------------------------------------------")
    print("Performing SIDDOS")  
    print("--------------------------------------------------------------------------------")
    src.cmd('timeout 20s hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood {}'.format(dst))
    sleep(100)
    
    # BOTNET Attack
    src, dst_host = sample(hosts, 2)
    dst = dst_host.IP()   
    print("--------------------------------------------------------------------------------")
    print("Performing BOTNET")  
    print("--------------------------------------------------------------------------------")   
    src.cmd("timeout 20s hping3 -1 -V -d 120 -w 64 --flood -a {} {}".format(dst,dst))
    # src.cmd("timeout 20s hping3 -S -f -p 80 {}".format(dst))
    sleep(100)

    # FIN attack
    src, dst_host = sample(hosts, 2)
    dst = dst_host.IP()   
    print("--------------------------------------------------------------------------------")
    print("Performing FIN")  
    print("--------------------------------------------------------------------------------")   
    src.cmd("timeout 20s hping3 -F -V -d 120 -w 64 --flood {}".format(dst))
    sleep(100)
    print("--------------------------------------------------------------------------------")

    


def normalTrafficGeneration(net):
    """Generates normal traffic patterns in the network"""
    # Write label=0 to indicate normal traffic
    with open("traffic_label.txt", "w") as f:
        f.write("0")
    
    # Get all hosts
    hosts = []
    for i in range(1, 19):
        hosts.append(net.get(f'h{i}'))
    
    print("--------------------------------------------------------------------------------")    
    print("Generating normal traffic ...")    
    sleep(2)
    
    # Setup iperf servers on all hosts
    for h in hosts:
        h.cmd('cd /home/spc/master/Downloads')
        h.cmd('iperf -s -p 5050 &')
        h.cmd('iperf -s -u -p 5051 &')
    
    # Generate traffic for iterations
    for i in range(9):
        # print("--------------------------------------------------------------------------------")    
        # print("Normal iteration n {} ...".format(i+1))
        # print("--------------------------------------------------------------------------------") 
        
        total_wait_time = 0
        for j in range(10):
            wait_time = randint(1,10)
            total_wait_time += wait_time
            
            # Select random source and destination for ICMP
            icmp_src = choice(hosts)
            icmp_dst_host = choice(hosts)
            while icmp_dst_host == icmp_src:
                icmp_dst_host = choice(hosts)
            icmp_dst = icmp_dst_host.IP()

            # Select random source and destination for TCP/UDP
            src = choice(hosts)
            dst_host = choice(hosts)
            while dst_host == src:
                dst_host = choice(hosts)
            dst = dst_host.IP()

            # Randomly choose protocol
            proto = choice(['tcp','udp', 'icmp'])

            if proto == 'icmp':
                print("generating ICMP traffic between %s and h%s" % (icmp_src,((icmp_dst.split('.'))[3])))
                icmp_src.cmd("ping {} -c 100 &".format(icmp_dst))
            elif proto == 'tcp':
                print("generating TCP traffic between %s and %s" % (src,dst))
                src.cmd(f"iperf -p 5050 -t {wait_time} -c {dst}")
            elif proto == 'udp':
                print("generating UDP traffic between %s and %s" % (src,dst))
                src.cmd(f"iperf -p 5051 -t {wait_time} -u -c {dst}")

        dst_host.cmd("rm -f *.* /home/mininet/Downloads")
        sleep(total_wait_time)
    print("--------------------------------------------------------------------------------")

def startNetwork():
    topo = MyTopo()
    c0 = RemoteController('c0', ip='10.0.2.15', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)
    
    net.start()

    for i in range(8):

        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")    
        print("Whole iteration n {} ...".format(i+1))
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    
        # Generate normal traffic first
        normalTrafficGeneration(net)
        
        # Then generate attack traffic
        attackGeneration(net)

        # Generate normal traffic again
        normalTrafficGeneration(net)
        
    
     # CLI(net)  # Uncomment if you want CLI access
    
    net.stop()

if __name__ == '__main__':
    start = datetime.now()
    setLogLevel('info')
    startNetwork()
    end = datetime.now()
    print(end-start)

