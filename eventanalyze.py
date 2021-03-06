#-*- coding: UTF-8 -*-

memoryaccesslist=['mov','cmp','add','sub','test']
event_memoryaceess=0
event_probeaccess=6
kernelspacestart=0xffff000000000000
rcx=0
rdx=0
r8=0

def eventdirectanalyze(line):#直接事件分析
    #todo
    #需要判断是否在该应用程序中
    s=line.split()[1]

    if s=='ProbeForRead' or s=='ProbeForWrite':#检查路径
        details=(rcx,rdx,r8)
        event=event_probeaccess
        return evetn,details

    




    pass

def updateregister(line):    
    #todo
    s=line.split()[-1]
    s=s.split(',')
    global rcx
    global rdx
    global r8
    rcx = int(s[1],16)
    rdx = int(s[2],16)
    r8 = int(s[3],16)
    
def addressanalyze(opr):
    if '[' not in opr:
        return None
    s=opr.split(' ',2)

    if s[0]=='byte':
        lenth=1
    elif s[0]=='word':
        lenth=2
    elif s[0]=='dword':
        lenth=4
    elif s[0]=='qword':
        lenth=8
    express=s[2].strip('[')
    express=express.strip(']')
    address=eval(express)
    
    addresslist=list(range(address,address+4))
    
    return addresslist
    
def switch(op):
    if op in memoryaccesslist:
        return True
    else:
        return False

def stringsclear(s):
    s=s.strip()
    s=s.strip('=')
    s=s.strip(',')
    s=s.strip()
    return s

def eventlistanalyze(line,linenumber):#处理字符串
    if '[call]' in line:#找到[call]标记，说明是为了函数跳转而保留的寄存器信息，将信息从字符串中提取出即可
        updateregister(line)
        print(rcx,rdx,r8)
        return None
    if '[event]' in line:#找到[event]标记，说明命中了某种事件
        event,details = eventdirectanalyze(line) 
        return (linenumber,event,details)
    if 'op_code' not in line:#其他日志信息，无意义直接过滤
        return None
    
    #提取命令符
    s=line.split('op_code')[1]
    m=s.split('opred1')
    op=stringsclear(m[0])

    if 'opred2' not in line:#没有第二个操作符
        return None

    last=m[1].split('opred2')
    op1=stringsclear(last[0])
    op2=stringsclear(last[1])

    #print(op,op1,op2)
    #此处得到了op op1,op2的指令形式

    if switch(op):#判断是否为内存访问指令
        
        op1_memoryaddress=addressanalyze(op1)#提取访问的地址
        op2_memoryaddress=addressanalyze(op2)

        if (not op1_memoryaddress) and (not op2_memoryaddress):
            return None

        if not op1_memoryaddress:#操作数1不含有地址访问
            if op2_memoryaddress[0]<kernelspacestart:#访问的地址是否位于用户地址空间中
                details=(True,op2_memoryaddress)
            else:
                details=(False,op2_memoryaddress)
        else:
            if op1_memoryaddress[0]<kernelspacestart:
                details=(True,op1_memoryaddress)
            else:
                details=(False,op1_memoryaddress)
        
        return (linenumber,event_memoryaceess,details)#event由行号、事件类型以及该事件的详细组成
    else:
        return None


if __name__=="__main__":
    line="15:30:39.391	DBG	#0	 4308	 4944	Pocfordoublefe 	op_code = mov,opred1 = rax ,opred2 =  qword ptr [0xFFFFDD803AFC5F40 + 0x850]"
    line2="12:48:48.943	INF	#0	 2780	 5064	Pocfordoublefe 	[call],0000020700C10000,0000000000000010,0000000000000001"
    line3="12:48:48.943	INF	#0	 2780	 5064	Pocfordoublefe 	[event] ProbeForRead Access"
    event=eventlistanalyze(line2,0)
    print('event:',event)