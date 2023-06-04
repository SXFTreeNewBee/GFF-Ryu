#!/usr/bin/env python
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import  RemoteController
from mininet.node import  Host
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from subprocess import Popen
from multiprocessing import Process
import numpy as np
import time
import os
import sys
import signal as sig
import random
import  iperf_peers
import ele_jitter
class fattree(Topo):
    host = []
    acc_num=8
    agg_num=8
    core_num=4
    acc_sw=[]
    agg_sw=[]
    core_sw=[]
    sw = []
    hn = 16
    def create_hosts(self):
        info('*** Add %d Hosts\n'%fattree.hn)
        # fattree.hosts=['h1','h2',.....,'hn']
        for i in range(fattree.hn):
            fattree.host.append('h' + str(i + 1))
    def create_acc_sw(self):
        for i in range(fattree.acc_num):
            fattree.acc_sw.append('3%d'%(i+1))
    def create_agg_sw(self):
        for i in range(fattree.agg_num):
            fattree.agg_sw.append('2%d'%(i+1))
    def create_core_sw(self):
        for i in range(fattree.core_num):
            fattree.core_sw.append('1%d'%(i+1))
    def setHostIP(self):
        info('*** Setting Hosts\'IP\n')
        k=0
        for i in range(len(fattree.acc_sw)):
            for j in range(2) :
                fattree.host[k]=self.addHost(fattree.host[k],cls=Host,ip='10.'+str(i+1)+'.0.'+str(j+1),defaultRoute=None)
                k+=1
    def setSwitches(self):
        info('*** Setting Switches\n')
        for acc in fattree.acc_sw:
            acc=self.addSwitch(acc, cls=OVSKernelSwitch)
        for agg in fattree.agg_sw:
            agg=self.addSwitch(agg, cls=OVSKernelSwitch)
        for core in fattree.core_sw:
            core = self.addSwitch(core, cls=OVSKernelSwitch)
    def setlink(self):
        info('*** Add Acc_Links\n')
        self.addLink(fattree.acc_sw[0], fattree.host[0], 3, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[0], fattree.host[1], 4, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[1], fattree.host[2], 3, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[1], fattree.host[3], 4, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[2], fattree.host[4], 3, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[2], fattree.host[5], 4, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[3], fattree.host[6], 3, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[3], fattree.host[7], 4, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[4], fattree.host[8], 3, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[4], fattree.host[9], 4, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[5], fattree.host[10], 3, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[5], fattree.host[11], 4, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[6], fattree.host[12], 3, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[6], fattree.host[13], 4, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[7], fattree.host[14], 3, 0, cls=TCLink, bw=10)
        self.addLink(fattree.acc_sw[7], fattree.host[15], 4, 0, cls=TCLink, bw=10)
        info('*** Add Agg_Links\n')
        self.addLink(fattree.agg_sw[0],fattree.acc_sw[0],3,1, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[0], fattree.acc_sw[1], 4, 1, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[1], fattree.acc_sw[0], 3, 2, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[1], fattree.acc_sw[1], 4, 2, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[2], fattree.acc_sw[2], 3, 1, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[2], fattree.acc_sw[3], 4, 1, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[3], fattree.acc_sw[2], 3, 2, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[3], fattree.acc_sw[3], 4, 2, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[4], fattree.acc_sw[4], 3, 1, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[4], fattree.acc_sw[5], 4, 1, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[5], fattree.acc_sw[4], 3, 2, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[5], fattree.acc_sw[5], 4, 2, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[6], fattree.acc_sw[6], 3, 1, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[6], fattree.acc_sw[7], 4, 1, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[7], fattree.acc_sw[6], 3, 2, cls=TCLink, bw=10)
        self.addLink(fattree.agg_sw[7], fattree.acc_sw[7], 4, 2, cls=TCLink, bw=10)
        info('*** Add Core_Links\n')
        self.addLink(fattree.core_sw[0], fattree.agg_sw[0], 1, 1, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[0], fattree.agg_sw[2], 2, 1, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[0], fattree.agg_sw[4], 3, 1, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[0], fattree.agg_sw[6], 4, 1, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[1], fattree.agg_sw[0], 1, 2, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[1], fattree.agg_sw[2], 2, 2, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[1], fattree.agg_sw[4], 3, 2, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[1], fattree.agg_sw[6], 4, 2, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[2], fattree.agg_sw[1], 1, 1, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[2], fattree.agg_sw[3], 2, 1, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[2], fattree.agg_sw[5], 3, 1, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[2], fattree.agg_sw[7], 4, 1, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[3], fattree.agg_sw[1], 1, 2, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[3], fattree.agg_sw[3], 2, 2, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[3], fattree.agg_sw[5], 3, 2, cls=TCLink, bw=10)
        self.addLink(fattree.core_sw[3], fattree.agg_sw[7], 4, 2, cls=TCLink, bw=10)
    def build(self):
        self.create_hosts()
        self.create_acc_sw()
        self.create_agg_sw()
        self.create_core_sw()
        self.setHostIP()
        self.setSwitches()
        self.setlink()
def normal_traffic(net):
    host_list=['h'+str(i) for i in range(1,17)]
    for i in range(len(host_list)):
        command="bash /home/ryu/sdncode/hedera/hedera_flows/%d.sh &" % (i + 1)
        host=net.get(host_list[i])
        host.cmd(command)
def iperf_single(net,server_client,port):
    server,client=net.get(server_client[0]),net.get(server_client[1])
    serverIP=server.IP()
    server.cmd('iperf3 -s -p %d &'%port)
    info('*** IperfTest: Client: %s ====> Server: %s  \n' %(client,server))
    client.cmd('iperf3 -c %s -u -p %d -b 10m -t 1000  > /dev/null &'%(serverIP,port))
def iperfmulti(net):
    port=5202
    fname = '/home/ryu/monitor_info/hedera/throughput'
    for peer in iperf_peers.peers:
        client = peer[0]
        server=peer[1]
        iperf_single(net=net,server_client=[server,client],port=port)
        time.sleep(0.1)
        port+=1
    print('=======等待流量稳定30s=======')
    time.sleep(30)
    print('=======开启监控子进程=======')
    monitor = Process(target=bwm(fname=fname))
    monitor.start()
    time.sleep(60)
    monitor.terminate()
    print('=======关闭监控子进程=======')
    os.system('sudo killall bwm-ng')
    os.system('sudo killall iperf3')
    print('=========监控结束==========')
    calc_thoughput(fname=fname)
def calc_thoughput(fname):
    with open(fname,'r') as f:
        message=f.readlines()
        message_list=[]
        for mess in message:
            message_list.append(mess.split('-'))
        throughput={}
        for info in message_list:
            if info[1].startswith('3'):
                if info[2]=='eth3' or info[2] == 'eth4':
                    key=int(info[0].split('.')[0])
                    if key not in throughput.keys():
                        throughput[key]=float(info[3])
                    else:
                        throughput[key]+=float(info[3])
        duration= len(throughput)-1
        output=0
        for v in throughput.values():
            output+=v
        print('平均吞吐率：',(round(output/duration/1024/1024*8)))
        print('标准化平均吞吐率：',(round(output / duration / 1024 / 1024 * 8)/160))
def bwm(fname):
    cmd = "bwm-ng -t %s -o csv -u bits -T rate -C '-' > %s" % (1000, fname)
    Popen(cmd,shell=True)
def run():
    global LOOP
    Test_name='hedera'
    topo = fattree()
    c1 = RemoteController('c1', ip='127.0.0.1')
    net = Mininet(topo=topo, controller=c1)
    net.start()
    LOOP=True
    info('*** >>>>>Initiating Topology<<<<< \n')
    info('*** >>>>>Initiate Done<<<<< \n')
    info('*** >>>>>This is %s Test<<<<< \n'%Test_name)
    info('*** >>>>>CommandList<<<<< \n')
    info(' +-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+\n')
    CommandList=['pingall','a','cli','ping']
    info('*** Input Command : ')
    Args=input().split()
    while LOOP:
        if Args[0]=='pingall':
            info('*** >>>>>Command: %s Processing<<<<<\n'%Args[0].upper())
            net.pingAll()
            info('*** Command : ')
            Args=input().split()
        if Args[0]=='cli':
            info('*** >>>>>Command: %s Processing<<<<<\n'%Args[0].upper())
            CLI(net)
            break
        if Args[0] not in CommandList:
            info('*** >>>>>Wrong Command<<<<<\n')
            info('*** Command : ')
            Args = input().split()
        if Args[0]=='a':
            info('*** >>>>>Command: %s Processing<<<<<\n'%Args[0].upper())
            iperfmulti(net=net)

            info('*** Command : ')
            Args = input().split()
        if Args[0]=='ping':
            info('*** >>>>>Command: %s Processing<<<<<\n'%Args[0].upper())
            normal_traffic(net=net)
            info('*** >>>>>Normal_Traffic Has Been Injected<<<<<\n: ')
            info('*** Command : ')
            Args = input().split()
if __name__ == '__main__':
    setLogLevel( 'info' )
    run()




