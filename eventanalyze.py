#-*- coding: UTF-8 -*-

memoryaccesslist=['mov','cmp','add','sub','test']
event_memoryaceess=0
kernelspacestart=0xffff000000000000

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


def eventlistanalyze(line,linenumber):#�����ַ���
    if 'op_code' not in line:
        return None
    s=line.split('op_code')[1]
    m=s.split('opred1')
    op=stringsclear(m[0])

    if 'opred2' not in line:#û�еڶ���������
        return None

    last=m[1].split('opred2')
    op1=stringsclear(last[0])
    op2=stringsclear(last[1])

    #print(op,op1,op2)
    
    if switch(op):
        
        op1_memoryaddress=addressanalyze(op1)
        op2_memoryaddress=addressanalyze(op2)

        if (not op1_memoryaddress) and (not op2_memoryaddress):
            return None

        if not op1_memoryaddress:#������1�����е�ַ����
            if op2_memoryaddress[0]<kernelspacestart:#���ʵĵ�ַ�Ƿ�λ���û���ַ�ռ���
                details=(True,op2_memoryaddress)
            else:
                details=(False,op2_memoryaddress)
        else:
            if op1_memoryaddress[0]<kernelspacestart:
                details=(True,op1_memoryaddress)
            else:
                details=(False,op1_memoryaddress)
        
        return (linenumber,event_memoryaceess,details)#event���кš��¼������Լ����¼�����ϸ���
    else:
        return None


if __name__=="__main__":
    line="15:30:39.391	DBG	#0	 4308	 4944	Pocfordoublefe 	op_code = mov,opred1 = rax ,opred2 =  qword ptr [0xFFFFDD803AFC5F40 + 0x850]"
    event=eventlistanalyze(line,0)
    print(event)