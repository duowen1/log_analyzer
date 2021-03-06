#-*- coding: UTF-8 -*- 
import argparse
from eventanalyze import eventlistanalyze
import vulnerability

event_memoryaccess=0
event_syscall=2
event_trap2b=3
event_trap2e=4
event_retuser=5
event_probeaccess=6
event_ProbeRead=7
event_probewrite=8
event_getpebteb=9
event_allocvirtualmemory=10


parser=argparse.ArgumentParser(description='Process the log created by MemoryMon Hypervisor')
parser.add_argument('-p','--path',help='the path of log')
parser.add_argument('-d','--doublefetch',action='store_true',help='analyze DoubleFetch Vulnerabilities form the log')
parser.add_argument('-u','--unprobe',action='store_true',help='analyze Unprobe Vulnerabilities from the log')
args=parser.parse_args()

if args.path:
    filepath=args.path
else:
    filepath="C:\\Users\\xsw\\Desktop\\logs\\MemoryMonRWE.log"

print(filepath)

filehandle=open(filepath)

#Ӧ�����Ƚ���Ԥ����ȥ������ȱҳ�жϵ��µ�����������ͬ����־
eventlist=[]
linenumber=0

first=filehandle.readline()
while True:
    line=filehandle.readline()
    if not line:#�ļ�β
        break

    linenumber+=1

    if line==first:#�����������־��ͬ��ֱ�ӿ����´�ѭ��
        continue
    
    event=eventlistanalyze(line,linenumber)

    if event:
        eventlist.append(event)
        
    first=line

filehandle.close()

if args.doublefetch:
    print('analyze doublefetch')
    vulnerability.doublefetchanalyzer(eventlist)

if args.unprobe:
    print('analyze Unprobe')
    vulnerability.unprobeanalyzer(eventlist)