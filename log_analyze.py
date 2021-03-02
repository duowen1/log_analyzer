#-*- coding: UTF-8 -*- 
from eventanalyze import eventlistanalyze
from vulnerability import vulnerabilityanalyzer

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

filepath="C:\\Users\\xsw\\Desktop\\logs\\MemoryMonRWE.log"

filehandle=open(filepath)
eventlist=[]
linenumber=0


while True:
    line=filehandle.readline()
    if not line:
        break
    linenumber+=1
    event=eventlistanalyze(line,linenumber)
    if event:
        eventlist.append(event)

filehandle.close()

vulnerabilityanalyzer(eventlist)