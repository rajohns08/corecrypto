# Copyright (c) (2015,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
from aetypes import Enum


sRSAmodulus = "n = "
sP = "p = "
sQ = "q = "
sResult = "Result"
sDi = "SHAAlg"
#number
ntags = [(sRSAmodulus, "\t\t.mod"),
		(sP, "\t\t//.p"),
		(sQ, "\t\t//.q"),
        ("e = ", "\t\t.exp"),
        ("d = ", "\t\t//.d"),
        ("Msg = ", "\t\t.msg"),
        ("S = ", "\t\t.sig"),
        ("SaltVal = ", "\t\t.salt"),
        ]
#strings
stags = [
		(sDi, "\t\t.di"),
        (sResult, "\t\t.valid")
        ]

class state(Enum):
    read = 1
    number = 2
    string = 3


class data_state(Enum):
    param_start = 1
    ex_start = 2
    param_end = 3
    ex_end = 5
    param = 6
    example = 7


st = state.read
data_st = data_state.param_start
value = ""
curr_tag = ntags[0]
prev_tag = curr_tag
n_mod = 0
n_msg = 0
fin = open("SigVerPSS_186-3.rsp", "r")
fot = open("SigVerPSS_186-3.inc", "w")

for line in fin:
	st = state.read
	p = ""
	value = ""
	for tag in ntags:
		if line.lower().startswith(tag[0].lower()):
			curr_tag = tag
			st = state.number
			l = line.strip()
			l = line.split('=', 1)[-1]
			l = l.strip().upper()
			value = "\\x" + '\\x'.join(a+b for a,b in zip(l[::2], l[1::2]))
			#value = value + "\\x"+l.strip().replace(" ", "\\x")
			a = curr_tag[1] + " = \"" + value + "\""
			b = curr_tag[1] + "_nbytes = " + str(len(value)/4)
			p = b + ",\n" + a
			
	for tag in stags:
		if line.lower().startswith(tag[0].lower()):
			curr_tag = tag
			st = state.string
			l = line.strip()
			value = l.split('=', 1)[-1]
			comment = value.split('(', 1)
			if (len(comment)>1): p = p + curr_tag[1] +  " =" + comment[0] + "/*(" + comment[1] + "*/"
			else: p = p + curr_tag[1] +  " =" + value
			
	if st != state.read:
		
		if curr_tag[0] == sRSAmodulus:
			n_mod+=1
			lastMod = p
			continue
		elif curr_tag[0] == sP:
			lastP = p
			continue
		elif curr_tag[0] == sQ:
			lastQ = p	
			continue
		elif curr_tag[0] == sDi:
			if (n_msg>0): p = "},\n{ /* i = " + str(n_msg) + " */\n" + p
			else: p = "{ /* i = 0 */\n" + p
			p = p + ",\n" + lastMod + ",\n" + lastP + ",\n" + lastQ + ",\n"
			n_msg +=1
		else:
			p = p + ",\n"
	elif (line.strip()):
		p = "// " + line
		 	
	prev_tag = curr_tag
	fot.write(p)

fot.write("}\n")
print "number of modulus = ", n_mod
fot.close()
fin.close()
