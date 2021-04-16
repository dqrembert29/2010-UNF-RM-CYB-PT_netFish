#!/usr/bin/env python3

import sys
import re

f = open('ufw_example.log')

#example = 'Apr 6 20:27:06 ghost kernel: [11541.394069] [UFW BLOCK] IN=eth1 OUT= MAC=08:00:27:ac:e0:62:0a:00:27:00:00:04:08:00 SRC=192.168.56.1 DST=192.168.56.102 LEN=52 TOS=0x00 PREC=0x00 TTL=128 ID=24059 DF PROTO=TCP SPT=53042 DPT=6000 WINDOW=64240 RES=0x00 SYN URGP=0 '

#helper function
#def createDict(pattern):
#    patDict = {}
#    for string in pattern:
#        key = string
#
#        if not key in patDict:
#            patDict[key] = 1
#        else:
#            patDict[key] += 1
#
#    return patDict 

def pro_list(log):
    lines = f.readlines()
    # these varibles are matched based on the pattern 
    pro = (r'(PROTO=\w+)')
    # read each line in log for pattern put in a list
    for line in log:
      r = re.compile(pro)
      proto = r.findall(line)
      for c in proto:
        print('|' + c + '|')
        #return c
def src_list(log):
    lines = f.readlines()
    src = (r'(SRC=\d+\.\d+\.\d+\.\d+)')
    for line in log:
      s = re.compile(src)
      slist = s.findall(line)
      for st in slist:
          new_st = st.ljust(19)
          print('|' + new_st+ '|' )

def dst_list(log):
    lines = f.readlines()
    dst = (r'(DST=\d+\.\d+\.\d+\.\d+)')
    for line in log:
      d = re.compile(dst)
      dlist = d.findall(line)
      for st in dlist:
          new_st = st.ljust(19)
          print('|' + new_st + '|')

def spt_list(log):
    lines = f.readlines()
    spt = (r'(SPT=\d+)')
    for line in log:
      a = re.compile(spt)
      sport = a.findall(line)
      for st in sport:
          new_st = st.ljust(9)
          print('|' + new_st + '|')


def dpt_list(log):
    lines = f.readlines()
    dpt = (r'(DPT=\d+)')
    for line in log:
      b = re.compile(dpt)
      dport = b.findall(line)
      for st in dport:
          new_st = st.ljust(9)
          print('|' + new_st + '|')

def print_header():
    




def main(arg):

    f = open(arg)
    
    pro_list(f)
    src_list(f)
    dst_list(f)
    spt_list(f)
    dpt_list(f)

    f.close()

# Dunder check
if __name__=='__main__':

    file_to_open = sys.argv[1]

    main(file_to_open)
