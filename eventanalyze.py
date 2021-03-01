#-*- coding: UTF-8 -*-

memoryaccesslist=['mov','cmp','add','sub','test']

def addressanalyze(opr):
    if '[' not in opr:
        return None
    s=opr.split(' ',2)
    print(s)
    lenth=s[0]
    express=s[2].strip('[')
    express=express.strip(']')
    address=eval(express)
    
    s=list(range(address,address+4))
    print(s)
    return [1]
    


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


def eventlistanalyze(line,linenumber):#´¦Àí×Ö·û´®
    s=line.split('op_code')[1]
    m=s.split('opred1')
    op=stringsclear(m[0])

    last=m[1].split('opred2')
    op1=stringsclear(last[0])
    op2=stringsclear(last[1])

    print(op,op1,op2)
    
    if switch(op):
        
        op1_memoryaddress=addressanalyze(op1)
        op2_memoryaddress=addressanalyze(op2)

        if (not op1_memoryaddress) and (not op2_memoryaddress):
            return None 

        details=0
        return (linenumber,0,details)
    else:
        return None


line="15:30:39.391	DBG	#0	 4308	 4944	Pocfordoublefe 	op_code = mov,opred1 = rax ,opred2 =  qword ptr [0xFFFFDD803AFC5F40 + 0x850]"
eventlistanalyze(line,0)