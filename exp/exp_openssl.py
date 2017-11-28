#!/usr/bin/python
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch # , KernelSwitch
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import CPULimitedHost
from mininet.util import custom, pmonitor
from signal import SIGINT
from time import time
import os
import time
import re
import sys

def dumpHost(popens, exec_time):
	beg_time = time.time()

	for host, line in pmonitor(popens):
		if host and line.strip() != '':
			if re.match("Avg", line.strip()) != None:
				print "<%s>: %s" %(host.name, line.strip())
			if re.match("transmission throughput", line.strip()) != None:
				print "<%s>: %s" %(host.name, line.strip())
			
			sys.stdout.flush()
				
			if re.match("CLIENT STOP", line.strip()) != None:
				print "<%s>: %s" %(host.name, line.strip())
				print
				sys.stdout.flush()
				return
		if time.time() - beg_time > exec_time:
			return

class SingleSwitchTopo(Topo):
	#Build the topology here.
	#We will use a simple star topology for this assignment.
	#If you want to build more complex topologies
	# such as a tree, fat-tree or jelly-fish, you can do this here.
	#Single switch connected to 4 hosts.
	def __init__(self, opts, n=4):
		Topo.__init__(self)
		leftHost = self.addHost('hs')
		rightHost = self.addHost('hc')
		switch = self.addSwitch('s1')
		
		self.addLink(leftHost, switch, **opts[0])
		self.addLink(rightHost, switch, **opts[1])

def pingTest(net):
	popens = {}
	for host in net.hosts:
		popens[host] = host.popen("ping -c2 %s" % host.IP())
		last = host

	dumpHost(popens, 1)		
	
def initNet(opts):
	os.system('pkill -f controller')
	os.system('pkill -f runSSL')
	os.system('pkill -f myhttpd')
	os.system('pkill -f clg')
	os.system('mn -c')
	switch = OVSKernelSwitch
	topo = SingleSwitchTopo(opts)
	network = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, switch = switch)

	return network

def bandwidth(httpVer, cipherID, procNum, bandwidth, dl):
	linkopts = []
	for i in range(2):
		linkopts.append(dict())

	linkopts[1] = dict(bw=bandwidth, delay=dl)

	net = initNet(linkopts)
	popens = {}
	
	net.start()

	for host in net.hosts:
		if host.name == 'hs':
			hs = host
		if host.name == 'hc':
			hc = host
	
	popens[hs] = hs.popen("./runSSL r_server -port 5678 -cert cert.pem -http %d -openssl"
		%(httpVer))
	popens[hc] = hc.popen("./runSSL r_client -ip %s -port 5678 -http %d -cipher %d -proc %d -openssl"
		%(hs.IP(), httpVer, cipherID, procNum))

	dumpHost(popens, 3600)

	net.stop()

def bandwidthNoSSL(httpVer, timeout, procNum, bandwidth, dl):
	linkopts = []
	for i in range(2):
		linkopts.append(dict())

	linkopts[1] = dict(bw=bandwidth, delay=dl)

	net = initNet(linkopts)
	popens = {}
	
	net.start()

	for host in net.hosts:
		if host.name == 'hs':
			hs = host
		if host.name == 'hc':
			hc = host
	
	popens[hs] = hs.popen("./myhttpd %s 5678 %d" %(httpVer, timeout))
	popens[hc] = hc.popen("./clg %s 5678 %s %d"
		%(hs.IP(), httpVer, procNum))

	dumpHost(popens, 3600)

	net.stop()

	
if __name__ == '__main__':
	setLogLevel('info')
	print "0 MS DELAY-----------------------------------------------"
	bandwidthNoSSL("1.1", 10, 1, 512, '0ms')
	bandwidthNoSSL("1.1", 10, 1, 256, '0ms')
	bandwidthNoSSL("1.1", 10, 1, 128, '0ms')
	bandwidthNoSSL("1.1", 10, 1, 64, '0ms')
	bandwidthNoSSL("1.1", 10, 1, 32, '0ms')

	print "---------------------------------------------------------"

	bandwidth(11, 1, 1, 512, '0ms')
	bandwidth(11, 1, 1, 256, '0ms')
	bandwidth(11, 1, 1, 128, '0ms')
	bandwidth(11, 1, 1, 64, '0ms')
	bandwidth(11, 1, 1, 32, '0ms')

	print "---------------------------------------------------------"
	
	bandwidth(11, 2, 1, 512, '0ms')
	bandwidth(11, 2, 1, 256, '0ms')
	bandwidth(11, 2, 1, 128, '0ms')
	bandwidth(11, 2, 1, 64, '0ms')
	bandwidth(11, 2, 1, 32, '0ms')

	print "---------------------------------------------------------"
	
	bandwidth(11, 3, 1, 512, '0ms')
	bandwidth(11, 3, 1, 256, '0ms')
	bandwidth(11, 3, 1, 128, '0ms')
	bandwidth(11, 3, 1, 64, '0ms')
	bandwidth(11, 3, 1, 32, '0ms')

	print "---------------------------------------------------------"

	bandwidth(11, 4, 1, 512, '0ms')
	bandwidth(11, 4, 1, 256, '0ms')
	bandwidth(11, 4, 1, 128, '0ms')
	bandwidth(11, 4, 1, 64, '0ms')
	bandwidth(11, 4, 1, 32, '0ms')

	print "5 MS DELAY-----------------------------------------------"
	bandwidthNoSSL("1.1", 10, 1, 512, '5ms')
	bandwidthNoSSL("1.1", 10, 1, 256, '5ms')
	bandwidthNoSSL("1.1", 10, 1, 128, '5ms')
	bandwidthNoSSL("1.1", 10, 1, 64, '5ms')
	bandwidthNoSSL("1.1", 10, 1, 32, '5ms')

	print "---------------------------------------------------------"

	bandwidth(11, 1, 1, 512, '5ms')
	bandwidth(11, 1, 1, 256, '5ms')
	bandwidth(11, 1, 1, 128, '5ms')
	bandwidth(11, 1, 1, 64, '5ms')
	bandwidth(11, 1, 1, 32, '5ms')

	print "---------------------------------------------------------"
	
	bandwidth(11, 2, 1, 512, '5ms')
	bandwidth(11, 2, 1, 256, '5ms')
	bandwidth(11, 2, 1, 128, '5ms')
	bandwidth(11, 2, 1, 64, '5ms')
	bandwidth(11, 2, 1, 32, '5ms')

	print "---------------------------------------------------------"
	
	bandwidth(11, 3, 1, 512, '5ms')
	bandwidth(11, 3, 1, 256, '5ms')
	bandwidth(11, 3, 1, 128, '5ms')
	bandwidth(11, 3, 1, 64, '5ms')
	bandwidth(11, 3, 1, 32, '5ms')

	print "---------------------------------------------------------"

	bandwidth(11, 4, 1, 512, '5ms')
	bandwidth(11, 4, 1, 256, '5ms')
	bandwidth(11, 4, 1, 128, '5ms')
	bandwidth(11, 4, 1, 64, '5ms')
	bandwidth(11, 4, 1, 32, '5ms')
