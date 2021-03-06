#-*- coding: UTF-8 -*-
filepath="C:\\Users\\xsw\\Desktop\\log\\MemoryMonRWE.log"

filehandle=open(filepath)

first=filehandle.readline()
linenumber=1

while True:
    second=filehandle.readline()
    if not second:
        break
    linenumber+=1
    if second == first:
        print(linenumber,"repeated logs")
    first = second

filehandle.close()