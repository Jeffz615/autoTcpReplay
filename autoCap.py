# -*- coding:utf-8 -*-
from scapy.all import *
from hexdump import hexdump
import re
import sys
import re
import requests
import time
import string
import threading
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def read_pcap(filename, count=-1):
    """Read a pcap file, return a packet list and close the file
count: read only <count> packets"""
    pcap_reader = PcapReader(filename)
    packets = pcap_reader.read_all(count=count)
    pcap_reader.close()
    return packets


def fenliu(file_data):
    port = []
    l = len(file_data)
    for i in range(0, l):
        try:
            # syn包的tcp标志位为0x02,跟据syn包先将源端口组成列表，返回port列表
            if file_data[i]['TCP'].flags == 0x02:
                port.append(file_data[i]['TCP'].sport)
        except Exception as e:
            log.error(e)
            pass
    return port


def fenbao(file_data):
    port = fenliu(file_data)
    l1 = len(port)
    data_list = [[] for _ in range(l1)]
    # data_list=[[]]*l1  不能这样创建多维列表，会出问题，应该用上面的方式
    l = len(file_data)
    for i in range(0, l):
        try:
            # 源端口在port列表里，则端口获取在列表中的索引，放入对应的data_list中
            if file_data[i]['TCP'].sport in port:
                j = port.index(file_data[i]['TCP'].sport)
                data_list[j].append(file_data[i])
            # 目的端口在port列表里，则端口获取在列表中的索引，放入对应的data_list中
            elif file_data[i]['TCP'].dport in port:
                j = port.index(file_data[i]['TCP'].dport)
                data_list[j].append(file_data[i])
        except Exception as e:
            log.error(e)
            pass
    return data_list


# def save_file(data_list):
#     l = len(data_list)
#     print '开始保存pcap，共有'+str(l)+'个pcap包'
#     for i in range(0, l):
#         name = 'ips'+str(i)+'.pcap'
#         wrpcap(name, data_list[i])
#     print '保存完成'

def getPayloads(file_name=None, src_port=None, check=True):
    if file_name and src_port:
        # file_name = "test.pcap"
        file_data = read_pcap(file_name)
        data = fenbao(file_data)
        payloads = []
        # save_file(data)
        i = 0
        with open('autoCapPayloads.txt', 'w') as f:
            for datai in data:
                tmp = []
                attack_ip = ''
                attack_port = 0
                for pkt in datai:
                    try:
                        a = pkt['TCP'].payload.original
                        port = pkt['TCP'].sport
                        ip = pkt['IP'].src
                        if port in src_port:
                            attack_ip = ip
                            attack_port = port
                            tmp.append(('D', a))
                        else:
                            tmp.append(('A', a))
                    except Exception as e:
                        print(e)
                        continue
                checkStrA = b''
                checkStrD = b''
                for x in tmp:
                    if x[0] == 'A':
                        checkStrA += x[1]
                    elif x[0] == 'D':
                        checkStrD += x[1]
                payload = [x[1] for x in tmp if x[0] == 'A']
                if checkStrA and attack_port and ((attack_ip, attack_port, payload) not in payloads) and ((not check) or (check and re.findall(r'f.*?l.*?a.*?g.*?{.+?}', checkStrD))):
                    print('')
                    print('[+]攻击流量'+str(i))
                    for x in tmp:
                        if x[0] == 'A':
                            print('\033[91m' + x[1] + '\033[0m'),
                            # hexdump(x[1])
                            # print(x[1].encode('hex')),
                        elif x[0] == 'D':
                            print('\033[94m' + x[1] + '\033[0m'),
                            # print(x[1].encode('hex')),
                    raw_input()
                    i += 1
                    payloads.append((attack_ip, int(attack_port), payload))
                    # hexdump(tmp.encode('utf-8'))
                    f.write(str(payload)+'\n')
        return payloads
    else:
        payloads = []
        with open('autoCapPayloads.txt', 'r') as f:
            tmp = f.readlines()
            for h in tmp:
                payload = eval(h)
                if payload:
                    payloads.append(payload)
                    print(payload)
                    print('')
        return payloads


payloads = []
caps = []
if __name__ == "__main__":
    # file_name = 'test.cap'
    # src_port = [16957, 12214, 14640, 17066]
    # src_port = [16957, 14640, 17066]
    src_port = [17066]
    getPayloads('test.cap', src_port)
    # while True:
    # ls = os.listdir('./cap/')
    # for cap in ls:
    # if (not cap.endswith('cap')) or (cap in caps):
    # continue
    # print(cap)
    # payloads += getPayloads('./cap/'+cap, src_port)
    # caps.append(cap)
