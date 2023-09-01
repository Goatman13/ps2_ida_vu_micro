from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc
import binascii

MAKE_CREFS = 1

def get_special_bit(instruction):

	sbits = (instruction >> 27) & 0xF
	string = ""
	if ((sbits >> 3) & 1):
		string += "[E]"
	if ((sbits >> 2) & 1):
		string += "[M]"
	if ((sbits >> 1) & 1):
		string += "[D]"
	if (sbits & 1):
		string += "[T]"

	return string
	
def get_2bit_field(bc):

	if (bc == 0):
		return "x"
	if (bc == 1):
		return "y"
	if (bc == 2):
		return "z"
	if (bc == 3):
		return "w"	

def get_4bit_field(field):

	if (field == 1):
		return "w"
	elif (field == 2):
		return "z"
	elif (field == 4):
		return "y"
	elif (field == 8):
		return "x"
	elif (field == 3):
		return "zw"
	elif (field == 5):
		return "yw"
	elif (field == 6):
		return "yz"
	elif (field == 9):
		return "xw"
	elif (field == 10):
		return "xz"
	elif (field == 12):
		return "xy"
	elif (field == 7):
		return "yzw"
	elif (field == 11):
		return "xzw"
	elif (field == 13):
		return "xyw"			
	elif (field == 14):
		return "xyz"
	elif (field == 15):
		return "xyzw"
	else:
		warning("Opcode is missing field!")
		return "xyzw"

def itof(address, instr, dest, source, field, sbits):
	
	field2 = get_4bit_field(field)
	
	while len(instr + "." + field2) < 13:
		field2 += " "
	
	string  = instr + "." + field2 + " vf{:d}, vf{:d}" + sbits
	set_manual_insn(address, string.format(dest, source))

def vu_bc(address, instr, dest, reg1, reg2, field, bc, sbits):
	
	bc2 = get_2bit_field(bc)
	field2 = get_4bit_field(field)
	
	if (dest == 34):
		dest_str = " ACC, "
	else: 
		dest_str = " vf{:d}, "
	
	while len(instr + bc2 + "." + field2) < 13:
		field2 += " "
	
	string  = instr + bc2 + "." + field2 + dest_str + "vf{:d}, vf{:d}" + bc2 + sbits
	if (dest == 34): 
		string  = string.format(reg1, reg2)
	else:
		string  = string.format(dest, reg1, reg2)
	
	set_manual_insn(address, string)

def vu_dr1r2f(address, instr, dest, reg1, reg2, field, sbits):
	
	field2 = get_4bit_field(field)
	
	if (reg2 == 32):
		reg2_str = ", Q"
	elif (reg2 == 33):
		reg2_str = ", I"
	else:
		reg2_str = ", vf{:d}"
		
	if (dest == 34):
		dest_str = " ACC, "
	else: 
		dest_str = " vf{:d}, "
		
	while len(instr + "." + field2) < 13:
		field2 += " "
		
	string  = instr + "." + field2 + dest_str + "vf{:d}" + reg2_str + sbits
	
	if (reg2 >= 32 and dest == 34):
		string  = string.format(reg1)
	elif (reg2 >= 32 and dest != 34):
		string  = string.format(dest, reg1)
	elif (reg2 < 32 and dest == 34):
		string  = string.format(reg1, reg2)
	else:
		string  = string.format(dest, reg1, reg2)
		
	set_manual_insn(address, string)	

def upper(address, instruction):

	if ((instruction >> 31) == 1):
		loi_addr = address - 4
		val = get_dword(loi_addr)
		val = struct.pack('>I', val)
		val = struct.unpack('>f', val)[0]
		val = str(val)
		#print(val)
		string = "loi           " + val
		set_manual_insn(loi_addr, string)

	op = instruction & 0x3F

	if (op <= 0x03):
		addbc(address, instruction)
	elif (op >= 0x04 and op <= 0x07):
		subbc(address, instruction)
	elif (op >= 0x08 and op <= 0x0B):
		maddbc(address, instruction)
	elif (op >= 0x0C and op <= 0x0F):
		msubbc(address, instruction)
	elif (op >= 0x10 and op <= 0x13):
		maxbc(address, instruction)
	elif (op >= 0x14 and op <= 0x17):
		minibc(address, instruction)
	elif (op >= 0x18 and op <= 0x1B):
		mulbc(address, instruction)
	elif (op == 0x1C):
		mulq(address, instruction)
	elif (op == 0x1D):
		maxi(address, instruction)
	elif (op == 0x1E):
		muli(address, instruction)
	elif (op == 0x1F):
		minii(address, instruction)
	elif (op == 0x20):
		addq(address, instruction)
	elif (op == 0x21):
		maddq(address, instruction)
	elif (op == 0x22):
		addi(address, instruction)
	elif (op == 0x23):
		maddi(address, instruction)
	elif (op == 0x24):
		subq(address, instruction)
	elif (op == 0x25):
		msubq(address, instruction)
	elif (op == 0x26):
		subi(address, instruction)
	elif (op == 0x27):
		msubi(address, instruction)
	elif (op == 0x28):
		add(address, instruction)
	elif (op == 0x29):
		madd(address, instruction)
	elif (op == 0x2A):
		mul(address, instruction)
	elif (op == 0x2B):
		_max(address, instruction)
	elif (op == 0x2C):
		sub(address, instruction)
	elif (op == 0x2D):
		msub(address, instruction)
	elif (op == 0x2E):
		opmsub(address, instruction)
	elif (op == 0x2F):
		mini(address, instruction)
	elif (op >= 0x3C and op <= 0x3F):
		upper_special(address, instruction)

def addbc(address, instruction):

	bc = instruction & 0x3
	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "add", dest, source, bc_reg, field, bc, sbits)


def subbc(address, instruction):

	bc = instruction & 0x3
	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "sub", dest, source, bc_reg, field, bc, sbits)

def maddbc(address, instruction):

	bc = instruction & 0x3
	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "madd", dest, source, bc_reg, field, bc, sbits)

def msubbc(address, instruction):

	bc = instruction & 0x3
	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "msub", dest, source, bc_reg, field, bc, sbits)

def maxbc(address, instruction):

	bc = instruction & 0x3
	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "max", dest, source, bc_reg, field, bc, sbits)

def minibc(address, instruction):

	bc = instruction & 0x3
	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "mini", dest, source, bc_reg, field, bc, sbits)

def mulbc(address, instruction):

	bc = instruction & 0x3
	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "mul", dest, source, bc_reg, field, bc, sbits)

def mulq(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "mulq", dest, source, 32, field, sbits)

def maxi(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "maxi", dest, source, 33, field, sbits)

def muli(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "muli", dest, source, 33, field, sbits)

def minii(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "minii", dest, source, 33, field, sbits)

def addq(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "addq", dest, source, 32, field, sbits)

def maddq(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "maddq", dest, source,32, field, sbits)

def addi(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "addi", dest, source, 33, field, sbits)

def maddi(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "maddi", dest, source, 33, field, sbits)

def subq(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "subq", dest, source, 32, field, sbits)

def msubq(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "msubq", dest, source, 32, field, sbits)

def subi(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "subi", dest, source, 33, field, sbits)

def msubi(address, instruction):

	dest = (instruction >> 6) & 0x1F
	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "msubi", dest, source, 33, field, sbits)

def add(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "add", dest, reg1, reg2, field, sbits)

def madd(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "madd", dest, reg1, reg2, field, sbits)

def mul(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "mul", dest, reg1, reg2, field, sbits)

def _max(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "max", dest, reg1, reg2, field, sbits)

def sub(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "sub", dest, reg1, reg2, field, sbits)

def msub(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "msub", dest, reg1, reg2, field, sbits)

def opmsub(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	string = "opmsub.xyz    vf{:d}, vf{:d}, vf{:d}"
	string += get_special_bit(instruction)
	set_manual_insn(address, string.format(dest, reg1, reg2))	

def mini(address, instruction):

	dest = (instruction >> 6) & 0x1F
	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "mini", dest, reg1, reg2, field, sbits)
	
##########################################################
def iadd(address, instruction):

	dest = (instruction >> 6) & 0xF
	reg1 = (instruction >> 11) & 0xF
	reg2 = (instruction >> 16) & 0xF
	string = "iadd          vi{:d}, vi{:d}, vi{:d}"
	set_manual_insn(address, string.format(dest, reg1, reg2))	

def isub(address, instruction):

	dest = (instruction >> 6) & 0xF
	reg1 = (instruction >> 11) & 0xF
	reg2 = (instruction >> 16) & 0xF
	string = "isub          vi{:d}, vi{:d}, vi{:d}"
	set_manual_insn(address, string.format(dest, reg1, reg2))	

def iaddi(address, instruction):

	reg1 = (instruction >> 11) & 0xF
	dest = (instruction >> 16) & 0xF
	imm5 = (instruction >> 6) & 0x1F
	sign = ""
	if imm5 > 0xF:
		imm5 = ~imm5
		imm5 &= 0xF
		imm5 += 1
		sign = "-"
	string = "iaddi         vi{:d}, vi{:d}, " + sign + "0x{:X}"
	set_manual_insn(address, string.format(dest, reg1, imm5))	

def iand(address, instruction):

	dest = (instruction >> 6) & 0xF
	reg1 = (instruction >> 11) & 0xF
	reg2 = (instruction >> 16) & 0xF
	string = "iand          vi{:d}, vi{:d}, vi{:d}"
	set_manual_insn(address, string.format(dest, reg1, reg2))

def ior(address, instruction):

	dest = (instruction >> 6) & 0xF
	reg1 = (instruction >> 11) & 0xF
	reg2 = (instruction >> 16) & 0xF
	string = "ior           vi{:d}, vi{:d}, vi{:d}"
	set_manual_insn(address, string.format(dest, reg1, reg2))	

def upper_special(address, instruction):

	op = (instruction & 0x3) | ((instruction >> 4) & 0x7C)
	
	if (op <= 0x03):
		addabc(address, instruction)
	elif (op >= 0x04 and op <= 0x07):
		subabc(address, instruction)
	elif (op >= 0x08 and op <= 0x0B):
		maddabc(address, instruction)
	elif (op >= 0x0C and op <= 0x0F):
		msubabc(address, instruction)
	elif (op == 0x10):
		itof0(address, instruction)
	elif (op == 0x11):
		itof4(address, instruction)
	elif (op == 0x12):
		itof12(address, instruction)
	elif (op == 0x13):
		itof15(address, instruction)
	elif (op == 0x14):
		ftoi0(address, instruction)
	elif (op == 0x15):
		ftoi4(address, instruction)
	elif (op == 0x16):
		ftoi12(address, instruction)
	elif (op == 0x17):
		ftoi15(address, instruction)
	elif (op >= 0x18 and op <= 0x1B):
		mulabc(address, instruction)
	elif (op == 0x1C):
		mulaq(address, instruction)
	elif (op == 0x1D):
		_abs(address, instruction)
	elif (op == 0x1E):
		mulai(address, instruction)
	elif (op == 0x1F):
		clip(address, instruction)
	elif (op == 0x20):
		addaq(address, instruction)
	elif (op == 0x21):
		maddaq(address, instruction)
	elif (op == 0x22):
		addai(address, instruction)
	elif (op == 0x23):
		maddai(address, instruction)
	elif (op == 0x25):
		msubaq(address, instruction)
	elif (op == 0x26):
		subai(address, instruction)
	elif (op == 0x27):
		msubai(address, instruction)
	elif (op == 0x28):
		adda(address, instruction)
	elif (op == 0x29):
		madda(address, instruction)
	elif (op == 0x2A):
		mula(address, instruction)
	elif (op == 0x2C):
		suba(address, instruction)
	elif (op == 0x2D):
		msuba(address, instruction)
	elif (op == 0x2E):
		opmula(address, instruction)
	elif (op == 0x2F):
		nop(address,instruction)
		

def lower(address, instruction):

	if (instruction == 0x8000033C):
		set_manual_insn(address,"nop")
		return
	if (instruction & (1 << 31)):
		lower1(address, instruction)
	else:
		lower2(address, instruction)

def lower1(address, instruction):
	
	op = (instruction & 0x3F)
	
	if (op == 0x30):
		iadd(address, instruction)
	elif (op == 0x31):
		isub(address, instruction)
	elif (op == 0x32):
		iaddi(address, instruction)
	elif (op == 0x34):
		iand(address, instruction)
	elif (op == 0x35):
		ior(address, instruction)
	elif (op >= 0x3C and op <= 0x3F):
		lower1_special(address, instruction)
	else:
		print("[unknown lower1]")

def lower1_special(address, instruction):	

	op = (instruction & 0x3) | ((instruction >> 4) & 0x7C)
	
	if (op == 0x30):
		move(address, instruction)
	elif (op == 0x31):
		mr32(address, instruction)
	elif (op == 0x34):
		lqi(address, instruction)
	elif (op == 0x35):
		sqi(address, instruction)
	elif (op == 0x36):
		lqd(address, instruction)
	elif (op == 0x37):
		sqd(address, instruction)
	elif (op == 0x38):
		div(address, instruction)
	elif (op == 0x39):
		sqrt(address, instruction)
	elif (op == 0x3A):
		rsqrt(address, instruction)
	elif (op == 0x3B):
		waitq(address, instruction)
	elif (op == 0x3C):
		mtir(address, instruction)
	elif (op == 0x3D):
		mfir(address, instruction)
	elif (op == 0x3E):
		ilwr(address, instruction)
	elif (op == 0x3F):
		iswr(address, instruction)
	elif (op == 0x40):
		rnext(address, instruction)
	elif (op == 0x41):
		rget(address, instruction)
	elif (op == 0x42):
		rinit(address, instruction)
	elif (op == 0x43):
		rxor(address, instruction)
	elif (op == 0x64):
		mfp(address, instruction)
	elif (op == 0x68):
		xtop(address, instruction)
	elif (op == 0x69):
		xitop(address, instruction)
	elif (op == 0x6C):
		xgkick(address, instruction)
	elif (op == 0x70):
		esadd(address, instruction)
	elif (op == 0x71):
		ersadd(address, instruction)
	elif (op == 0x72):
		eleng(address, instruction)
	elif (op == 0x73):
		erleng(address, instruction)
	elif (op == 0x74): 
		eatanxy(address, instruction)
	elif (op == 0x75):
		eatanxz(address, instruction)
	elif (op == 0x76):
		esum(address, instruction)
	elif (op == 0x78):
		esqrt(address, instruction)
	elif (op == 0x79):
		ersqrt(address, instruction)
	elif (op == 0x7A):
		ercpr(address, instruction)
	elif (op == 0x7B):
		set_manual_insn(address, "waitp")
	elif (op == 0x7D):
		eatan(address, instruction)
	elif (op == 0x7E):
		eexp(address, instruction)
	else:
		print("Bad op cop2_special2")

def mfp(address, instruction):

	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)
	
	while len("mfp." + field2) < 13:
		field2 += " "	
	
	string = "mfp." + field2 + " vf{:d}, P"
	set_manual_insn(address, string.format(dest))


def xtop(address, instruction):

	it = (instruction >> 16) & 0x1F
	string = "xtop          vi{:d}"
	set_manual_insn(address, string.format(it))


def xitop(address, instruction):

	it = (instruction >> 16) & 0x1F
	string = "xitop         vi{:d}"
	set_manual_insn(address, string.format(it))


def xgkick(address, instruction):

	_is = (instruction >> 11) & 0x1F
	string = "xgkick        vi{:d}"
	set_manual_insn(address, string.format(_is))


def esadd(address, instruction):

	source = (instruction >> 11) & 0x1F
	string = "esadd         P, vf{:d}"
	set_manual_insn(address, string.format(source))


def ersadd(address, instruction):

	source = (instruction >> 11) & 0x1F
	string = "ersadd        P, vf{:d}"
	set_manual_insn(address, string.format(source))


def eleng(address, instruction):

	source = (instruction >> 11) & 0x1F
	string = "eleng         P, vf{:d}"
	set_manual_insn(address, string.format(source))


def esum(address, instruction):

	source = (instruction >> 11) & 0x1F
	string = "esum          P, vf{:d}"
	set_manual_insn(address, string.format(source))


def ercpr(address, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "ercpr         P, vf{:d}." + fsf2
	set_manual_insn(address, string.format(source))


def erleng(address, instruction):

	source = (instruction >> 11) & 0x1F
	string = "erleng        P, vf{:d}"
	set_manual_insn(address, string.format(source))


def esqrt(address, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "esqrt         P, vf{:d}." + fsf2
	set_manual_insn(address, string.format(source))


def ersqrt(address, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "ersqrt        P, vf{:d}." + fsf2
	set_manual_insn(address, string.format(source))


def esin(address, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "esin          P, vf{:d}." + fsf2
	set_manual_insn(address, string.format(source))


def eatan(address, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "eatan         P, vf{:d}." + fsf2
	set_manual_insn(address, string.format(source))


def eatanxy(address, instruction):

	source = (instruction >> 11) & 0x1F
	string = "eatanxy       P, vf{:d}"
	set_manual_insn(address, string.format(source))


def eatanxz(address, instruction):

	source = (instruction >> 11) & 0x1F
	string = "eatanxz       P, vf{:d}"
	set_manual_insn(address, string.format(source))


def eexp(address, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "eexp          P, vf{:d}." + fsf2
	set_manual_insn(address, string.format(source))


def lower2(address, instruction):

	op = ((instruction >> 25) & 0x7F)
	
	if (op == 0x00):
		lq(address, instruction)
	elif (op  == 0x01):
		sq(address, instruction)
	elif (op  == 0x04):
		loadstore_imm(address, "ilw", instruction)
	elif (op  == 0x05):
		loadstore_imm(address, "isw", instruction)
	elif (op  == 0x08):
		arithu(address, "iaddiu", instruction)
	elif (op  == 0x09):
		arithu(address, "isubiu", instruction)
	elif (op  == 0x10):
		fceq(address, instruction)
	elif (op  == 0x11):
		fcset(address, instruction)
	elif (op  == 0x12):
		fcand(address, instruction)
	elif (op  == 0x13):
		fcor(address, instruction)
	elif (op  == 0x14):
		fseq(address, instruction)
	elif (op  == 0x15):
		fsset(address, instruction)
	elif (op  == 0x16):
		fsand(address, instruction)
	elif (op  == 0x17):
		fsor(address, instruction)
	elif (op  == 0x18):
		fmeq(address, instruction)
	elif (op  == 0x1A):
		fmand(address, instruction)
	elif (op  == 0x1B):
		fmor(address, instruction)
	elif (op  == 0x1C):
		fcget(address, instruction)
	elif (op  == 0x20):
		b(address, instruction)
	elif (op  == 0x21):
		bal(address, instruction)
	elif (op  == 0x24):
		jr(address, instruction)
	elif (op  == 0x25):
		jalr(address, instruction)
	elif (op  == 0x28):
		branch(address, "ibeq", instruction)
	elif (op  == 0x29):
		branch(address, "ibne", instruction)
	elif (op  == 0x2C):
		branch_zero(address, "ibltz", instruction)
	elif (op  == 0x2D):
		branch_zero(address, "ibgtz", instruction)
	elif (op  == 0x2E):
		branch_zero(address, "iblez", instruction)
	elif (op  == 0x2F):
		branch_zero(address, "ibgez", instruction)
	else:
		print("[unknown lower2]")
	


def loadstore_imm(address, string, instruction):

	sign = ""
	imm = instruction & 0x7FF
	if (imm > 0x3FF):
		imm = ~imm
		imm &= 0x3FF
		imm += 1
		sign = "-"
	imm *= 16 
	_is = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)
	
	while len(string + "." + field2) < 13:
		field2 += " "	
	
	string = string + "." + field2 + " vi{:d}, " + sign + "0x{:X}(vi{:d})"
	set_manual_insn(address, string.format(it, imm, _is))


def arithu(address, string, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	imm = instruction & 0x7FF
	imm |= ((instruction >> 21) & 0xF) << 11
	while len(string) < 13:
		string += " "
	
	string = string + " vi{:d}, vi{:d}, 0x{:X}"
	set_manual_insn(address, string.format(dest, source, imm))


def branch(address, string, instruction):

	imm = instruction & 0x7FF
	_is = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	if (imm > 0x3FF):
		imm &= 0x3FF
		imm = ~imm
		imm &= 0x3FF
		imm *= 8
		addr = (address - imm)
		addr -= skip_vif_data(addr, address)
		
		while len(string) < 13:
			string += " "
		
		string = string + " vi{:d}, vi{:d}, 0x{:X}"
		set_manual_insn(address, string.format(it, _is, addr))
		if(MAKE_CREFS == 1):
			add_cref(address, addr, fl_JN | XREF_USER)
		return
		
	imm *= 8
	addr = address + imm + 8
	addr += skip_vif_data(address, addr)
	if(MAKE_CREFS == 1):
		add_cref(address, addr, fl_JN | XREF_USER)
	while len(string) < 13:
		string += " "	
	
	string = string + " vi{:d}, vi{:d}, 0x{:X}"
	set_manual_insn(address, string.format(it, _is, addr))


def branch_zero(address, string, instruction):

	imm = instruction & 0x7FF
	reg = (instruction >> 11) & 0x1F
	if (imm > 0x3FF):
		imm &= 0x3FF
		imm = ~imm
		imm &= 0x3FF
		imm *= 8
		addr = (address - imm) #+ 8
		addr -= skip_vif_data(addr, address)
	
		while len(string) < 13:
			string += " "
		
		string = string + " vi{:d}, 0x{:X}"
		set_manual_insn(address, string.format(reg, addr))
		if(MAKE_CREFS == 1):
			add_cref(address, addr, fl_JN | XREF_USER)
		return
	
	imm *= 8
	addr = address + imm + 8
	addr += skip_vif_data(address, addr)
	if(MAKE_CREFS == 1):
		add_cref(address, addr, fl_JN | XREF_USER)	
	while len(string) < 13:
		string += " "
	
	string = string + " vi{:d}, 0x{:X}"
	set_manual_insn(address, string.format(reg, addr))


def lq(address, instruction):

	sign = ""
	imm = instruction & 0x7FF
	if (imm > 0x3FF):
		imm = ~imm
		imm &= 0x3FF
		imm += 1
		sign = "-"
	imm *= 16 
	_is = (instruction >> 11) & 0x1F
	ft = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)	

	while len("lq." + field2) < 13:
		field2 += " "
		
	string = "lq." + field2 + " vf{:d}, " + sign + "0x{:X}(vi{:d})"
	set_manual_insn(address, string.format(ft, imm, _is))


def sq(address, instruction):

	sign = ""
	imm = instruction & 0x7FF
	if (imm > 0x3FF):
		imm = ~imm
		imm &= 0x3FF
		imm += 1
		sign = "-"
	imm *= 16 
	fs = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)

	while len("sq." + field2) < 13:
		field2 += " "
		
	string = "sq." + field2 + " vf{:d}, " + sign + "0x{:X}(vi{:d})"
	set_manual_insn(address, string.format(fs, imm, it))


def fceq(address, instruction):

	imm = instruction & 0xFFFFFF
	string = "fceq          vi1, 0x{:X}"
	set_manual_insn(address, string.format(imm))


def fcset(address, instruction):

	imm = instruction & 0xFFFFFF
	string = "fcset         0x{:X}"
	set_manual_insn(address, string.format(imm))


def fcand(address, instruction):

	imm = instruction & 0xFFFFFF
	string = "fcand         vi1, 0x{:X}"
	set_manual_insn(address, string.format(imm))


def fcor(address, instruction):

	imm = instruction & 0xFFFFFF
	string = "fcor          vi1, 0x{:X}"
	set_manual_insn(address, string.format(imm))


def fseq(address, instruction):

	imm = ((instruction >> 10) & 0x800) | (instruction & 0x7FF)
	dest = (instruction >> 16) & 0x1F
	string = "fseq          vi{:d}, 0x{:X}"
	set_manual_insn(address, string.format(dest, imm))


def fsset(address, instruction):

	imm = ((instruction >> 10) & 0x800) | (instruction & 0x7FF)
	string = "fsset         0x{:X}"
	set_manual_insn(address, string.format(imm))


def fsand(address, instruction):

	imm = ((instruction >> 10) & 0x800) | (instruction & 0x7FF)
	dest = (instruction >> 16) & 0x1F
	string = "fsand         vi{:d}, 0x{:X}"
	set_manual_insn(address, string.format(dest, imm))


def fsor(address, instruction):

	imm = ((instruction >> 10) & 0x800) | (instruction & 0x7FF)
	dest = (instruction >> 16) & 0x1F
	string = "fsor          vi{:d}, 0x{:X}"
	set_manual_insn(address, string.format(dest, imm))


def fmeq(address, instruction):

	_is = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	string = "fmeq          vi{:d}, vi{:d}"
	set_manual_insn(address, string.format(it, _is))


def fmand(address, instruction):

	_is = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	string = "fmand         vi{:d}, vi{:d}"	
	set_manual_insn(address, string.format(it, _is))


def fmor(address, instruction):

	_is = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	string = "fmor          vi{:d}, vi{:d}"	
	set_manual_insn(address, string.format(it, _is))


def fcget(address, instruction):

	it = (instruction >> 16) & 0x1F
	string = "fcget         vi{:d}"
	set_manual_insn(address, string.format(it))


def b(address, instruction):

	imm = instruction & 0x7FF
	if (imm > 0x3FF):
		imm &= 0x3FF
		imm = ~imm
		imm &= 0x3FF
		imm *= 8
		addr = (address - imm)
		addr -= skip_vif_data(addr, address)
		if(MAKE_CREFS == 1):
			add_cref(address, addr, fl_JN | XREF_USER)
		string = "b             0x{:X}"
		set_manual_insn(address, string.format(addr))
		return
	
	imm *= 8
	addr = address + imm + 8
	addr += skip_vif_data(address, addr)
	if(MAKE_CREFS == 1):
		add_cref(address, addr, fl_JN | XREF_USER)	
	string = "b             0x{:X}"
	set_manual_insn(address, string.format(addr))


def bal(address, instruction):

	imm = instruction & 0x7FF
	link_reg = (instruction >> 16) & 0x1F
	if (imm > 0x3FF):
		imm &= 0x3FF
		imm = ~imm
		imm &= 0x3FF
		imm *= 8
		addr = (address - imm)
		addr -= skip_vif_data(addr, address)
		if(MAKE_CREFS == 1):
			add_cref(address, addr, fl_CN | XREF_USER)		
		string = "bal           vi{:d} 0x{:X}"
		set_manual_insn(address, string.format(link_reg, addr))
		return
	
	imm *= 8	
	addr = address + imm + 8
	addr += skip_vif_data(address, addr)
	
	string = "bal           vi{:d} 0x{:X}"
	set_manual_insn(address, string.format(link_reg, addr))


def jr(address, instruction):

	addr_reg = (instruction >> 11) & 0x1F
	#if(MAKE_CREFS == 1):
	#	add_cref(address, addr, fl_JN | XREF_USER)
	string = "jr            vi{:d}"
	set_manual_insn(address, string.format(addr_reg))


def jalr(address, instruction):

	addr_reg = (instruction >> 11) & 0x1F
	link_reg = (instruction >> 16) & 0x1F
	#if(MAKE_CREFS == 1):
	#	add_cref(address, addr, fl_CN | XREF_USER)
	string = "jalr          vi{:d}, vi{:d}"
	set_manual_insn(address, string.format(link_reg, addr_reg))


def skip_vif_data(start, end):
	
	to_skip = 0
	while (start < end):
		if start < ida_idaapi.BADADDR:
			if ((is_code(ida_bytes.get_flags(start)) == 1)):
				print("wrong branch address, wrap?")
				return to_skip
			instruction = get_dword(start)
			end_instr = get_dword(end)
			while end_instr == 0x70000000 or end_instr == 0:
				end += 4
				end_instr = get_dword(end)
			if instruction == 0x70000000 or instruction == 0 and start < end:
				if get_dword(start + 4) >> 31 == 1:# and get_manual_insn(start)[0:3] == "loi":
				#if get_manual_insn(start) == "loi           0.0":
					start += 4
					continue
				while (get_dword(start) >> 24) != 0x4A and start < end:
					start += 4
					to_skip += 4
					if ((is_code(ida_bytes.get_flags(start)) == 1)):
						print("wrong branch address, wrap?")
						return to_skip
				start += 4
				#to_skip += 4
				continue
	
		start += 4

	return to_skip

#####################################################
def addabc(address, instruction):

	bc = instruction & 0x3
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "adda", 34, source, bc_reg, field, bc, sbits)

def subabc(address, instruction):

	bc = instruction & 0x3
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "suba", 34, source, bc_reg, field, bc, sbits)

def maddabc(address, instruction):

	bc = instruction & 0x3
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "madda", 34, source, bc_reg, field, bc, sbits)

def msubabc(address, instruction):

	bc = instruction & 0x3
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "msuba", 34, source, bc_reg, field, bc, sbits)

def itof0(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "itof0", dest, source, field, sbits)

def itof4(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "itof4", dest, source, field, sbits)

def itof12(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "itof12", dest, source, field, sbits)

def itof15(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "itof15", dest, source, field, sbits)

def ftoi0(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "ftoi0", dest, source, field, sbits)

def ftoi4(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "ftoi4", dest, source, field, sbits)

def ftoi12(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "ftoi12", dest, source, field, sbits)

def ftoi15(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "ftoi15", dest, source, field, sbits)

def mulabc(address, instruction):

	bc = instruction & 0x3
	source = (instruction >> 11) & 0x1F
	bc_reg = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_bc(address, "mula", 34, source, bc_reg, field, bc, sbits)

def mulaq(address, instruction):

	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "mulaq", 34, source, 32, field, sbits)

def _abs(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	itof(address, "abs", dest, source, field, sbits)

def mulai(address, instruction):

	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "mulai", 34, source, 33, field, sbits)

def clip(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	string = "clipw.xyz     vf{:d}, vf{:d}w"
	set_manual_insn(address, string.format(reg1, reg2))	

def addaq(address, instruction):

	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "addaq", 34, source, 32, field, sbits)

def maddaq(address, instruction):

	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "maddaq", 34, source, 32, field, sbits)

def maddai(address, instruction):

	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "maddai", 34, source, 33, field, sbits)

def msubaq(address, instruction):

	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "msubaq", 34, source, 32, field, sbits)

def subai(address, instruction):

	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "subai", 34, source, 33, field, sbits)

def msubai(address, instruction):

	source = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "msubai", 34, source, 33, field, sbits)

def adda(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "adda", 34, reg1, reg2, field, sbits)

def addai(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "addai", 34, reg1, 33, field, sbits)

def madda(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "madda", 34, reg1, reg2, field, sbits)

def mula(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "mula", 34, reg1, reg2, field, sbits)

def suba(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "suba", 34, reg1, reg2, field, sbits)

def msuba(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	sbits = get_special_bit(instruction)
	vu_dr1r2f(address, "msuba", 34, reg1, reg2, field, sbits)

def opmula(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	string = "opmula.xyz    ACC, vf{:d}, vf{:d}"
	set_manual_insn(address, string.format(reg1, reg2))

def nop(address, instruction):

	sbits = get_special_bit(instruction)
	string = "nop           " + sbits
	set_manual_insn(address, string)

def move(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	itof(address, "move", dest, source, field, "")

def mr32(address, instruction):

	source = (instruction >> 11) & 0x1F
	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	itof(address, "mr32", dest, source, field, "")

def lqi(address, instruction):

	_is = (instruction >> 11) & 0xF
	ft = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)
	
	while len("lqi." + field2) < 13:
		field2 += " "	
	
	string = "lqi." + field2 + " vf{:d}, (vi{:d}++)"
	set_manual_insn(address, string.format(ft, _is))

def sqi(address, instruction):

	fs = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0xF
	dest_field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(dest_field)
	
	while len("sqi." + field2) < 13:
		field2 += " "	
	
	string = "sqi." + field2 + " vf{:d}, (vi{:d}++)"
	set_manual_insn(address, string.format(fs, it))

def lqd(address, instruction):

	_is = (instruction >> 11) & 0xF
	ft = (instruction >> 16) & 0x1F
	dest_field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(dest_field)
	
	while len("lqd." + field2) < 13:
		field2 += " "	
	
	string = "lqd." + field2 + " vf{:d}, (--vi{:d})"
	set_manual_insn(address, string.format(ft, _is))

def sqd(address, instruction):

	fs = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0xF
	dest_field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(dest_field)
	
	while len("sqd." + field2) < 13:
		field2 += " "	
	
	string = "sqd." + field2 + " vf{:d}, (--vi{:d})"
	set_manual_insn(address, string.format(fs, it))

def div(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	fsf = (instruction >> 21) & 0x3
	ftf = (instruction >> 23) & 0x3	
	fsf2 = get_2bit_field(fsf)
	ftf2 = get_2bit_field(ftf)
	string = "div           Q, vf{:d}" + fsf2 + " vf{:d}" + ftf2
	
	set_manual_insn(address, string.format(reg1, reg2))

def sqrt(address, instruction):

	source = (instruction >> 16) & 0x1F
	ftf = (instruction >> 23) & 0x3	
	ftf2 = get_2bit_field(ftf)
	string = "sqrt          Q, vf{:d}" + ftf2

	set_manual_insn(address, string.format(source))

def rsqrt(address, instruction):

	reg1 = (instruction >> 11) & 0x1F
	reg2 = (instruction >> 16) & 0x1F
	fsf = (instruction >> 21) & 0x3
	ftf = (instruction >> 23) & 0x3
	fsf2 = get_2bit_field(fsf)
	ftf2 = get_2bit_field(ftf)
	string = "rsqrt         Q, vf{:d}" + fsf2 + " vf{:d}" + ftf2
	
	set_manual_insn(address, string.format(reg1, reg2))

def waitq(address, instruction):

	set_manual_insn(address, "waitq")

def mtir(address, instruction):

	fs = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0xF
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "mtir          vi{:d}, vf{:d}" + fsf2
	set_manual_insn(address, string.format(it, fs))

def mfir(address, instruction):

	_is = (instruction >> 11) & 0x1F
	ft = (instruction >> 16) & 0x1F
	dest_field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(dest_field)
	
	while len("mfir." + field2) < 13:
		field2 += " "	
	
	string = "mfir." + field2 + " vf{:d}, vi{:d}"
	set_manual_insn(address, string.format(ft, _is))

def ilwr(address, instruction):

	_is = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)
	
	while len("ilwr." + field2) < 13:
		field2 += " "		
	
	string = "ilwr." + field2 + " vi{:d}, (vi{:d})" + field2
	set_manual_insn(address, string.format(it, _is))

def iswr(address, instruction):

	_is = (instruction >> 11) & 0x1F
	it = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)
	
	while len("iswr." + field2) < 13:
		field2 += " "		
	
	string = "iswr." + field2 + " vi{:d}, (vi{:d})" + field2
	set_manual_insn(address, string.format(it, _is))

def rnext(address, instruction):

	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)
	
	while len("rnext." + field2) < 13:
		field2 += " "		
	
	string = "rnext." + field2 + " vf{:d}, R"
	set_manual_insn(address, string.format(dest))

def rget(address, instruction):

	dest = (instruction >> 16) & 0x1F
	field = (instruction >> 21) & 0xF
	field2 = get_4bit_field(field)
	
	while len("rget." + field2) < 13:
		field2 += " "			
	
	string = "rget." + field2 + " vf{:d}, R"
	set_manual_insn(address, string.format(dest))

def rinit(address, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "rinit         R, vf{:d}." + fsf2
	set_manual_insn(address, string.format(source))

def rxor(address, instruction):

	source = (instruction >> 11) & 0x1F
	fsf = (instruction >> 21) & 0x3
	fsf2 = get_2bit_field(fsf)
	string = "rxor          R, vf{:d}." + fsf2
	set_manual_insn(address, string.format(source))

def calculate_mpg_size(start):
	print("Entering calculate_mpg_size")
	address = start
	size = 0
	while 1:
		if (get_dword(address) >> 24) == 0x4A:
			add_size = (get_dword(address) >> 16) & 0xFF
			if add_size == 0:
				add_size = 0x100
			add_size *= 8
			size += add_size
			size += 8
			#address = address + size
			#print(hex(size))
			#print(hex(address))
			address = start + size
			continue
		else:
			stopper = address + 0x50
			counter = 0
			while address < stopper:
				if ((get_dword(address) >> 24) & 0xFF) == 0x4A:
					size += counter
					#print(hex(address))
					#print("2")
					break
				else:
					if ((get_dword(address) >> 24) & 0xFF) == 0x4A: 
						tpr = get_dword(address) >> 16 & 0xFF
						#print("tpr %x", tpr)
						counter += 4
						break
					address += 4
					counter += 4
					#print(hex(address))
					#print("3")
					if address == stopper - 4:
						#print(hex(address))
						#print("4")
						return size

	#return size
			
def mark_code(address, end):
	
	print("Entering mark_code")
	counter = 0
	while (address < end):
		if address < ida_idaapi.BADADDR:	
			if ((address & 3) != 0):
				address = ((address & 0xFFFFFFFC) + 4)
				continue
			
			#print(hex(address))
			#if ((is_code(ida_bytes.get_flags(address)) == 1)):
			instruction = get_dword(address)
			old = address
			if (instruction >> 24) == 0x70 or (instruction >> 24) == 0x60:
				while (get_dword(address) >> 24) != 0x4A and address <= end:
					create_dword(address)
					address += 4
				continue
				
			if instruction == 0 :
				create_dword(address)
				address += 4
				continue
				
			if (instruction >> 24) == 0x4A:
				create_dword(address)
				address += 4
				continue
			
			del_items(address)
			create_dword(address)
			if ((address & 4) == 4):
				set_color(address, CIC_ITEM, 0x383838)
				#print(hex(color))
				upper(address, instruction)
			else:
				set_color(address, CIC_ITEM, 0x2B2B2B)
				lower(address, instruction)
			
		address += 4
	return 0

def vu_helper(start):
	
	end = start + calculate_mpg_size(start)
	print(hex(start))
	print(hex(end))
	mark_code(start, end)

def vu_single_line():
	
	start_addr = read_selection_start()
	end_addr = read_selection_end()
	if(start_addr == BADADDR):
		start_addr = get_screen_ea();
		end_addr = start_addr + 4;
		
	mark_code(start_addr, end_addr)

def vu_mpg_4A():
	
	ea = get_screen_ea()
	if (get_dword(ea) >> 24) == 0x4A:
		vu_helper(get_screen_ea())
		
	else:
		print("To start plugin you need to specify line with VIF MPG command")

class ActionHandler(idaapi.action_handler_t):

    def __init__(self, callback):
        
        idaapi.action_handler_t.__init__(self)
        self.callback = callback
    
    def activate(self, ctx):

        self.callback()
        return 1

    def update(self, ctx):
        
        return idaapi.AST_ENABLE_ALWAYS

def register_actions():   

    actions = [
        {
            'id': 'start:vu_single_line',
            'name': 'Disassemble Marked VU Code',
            'hotkey': 'F10',
            'comment': 'Disassemble Marked VU Code',
            'callback': vu_single_line,
            'menu_location': ''
        },
        {
            'id': 'start:vu_mpg_4A',
            'name': 'Disassemble VU Code using VIF MPG',
            'hotkey': 'Alt-Shift-5',
            'comment': 'Disassemble VU Code using VIF MPG',
            'callback': vu_mpg_4A,
            'menu_location': ''
        }
    ]


    for action in actions:

        if not idaapi.register_action(idaapi.action_desc_t(
            action['id'], # Must be the unique item
            action['name'], # The name the user sees
            ActionHandler(action['callback']), # The function to call
            action['hotkey'], # A shortcut, if any (optional)
            action['comment'] # A comment, if any (optional)
        )):

            print('Failed to register ' + action['id'])

        #if not idaapi.attach_action_to_menu(
        #    action['menu_location'], # The menu location
        #    action['id'], # The unique function ID
        #    0):
		#
        #    print('Failed to attach to menu '+ action['id'])

class vu_helper_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = "VU. "
	help = "Analyze VU"
	wanted_name = "Start VUE Analyze"
	wanted_hotkey = "Alt-Shift-5"

	def init(self):
		if (idaapi.ph.id == idaapi.PLFM_MIPS and ida_ida.inf_get_procname() == 'r5900l'):
			register_actions()
			idaapi.msg("Analyze VU loaded.\n")
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP
	
	def run(self, arg):
		idaapi.msg("Analyze VU run.\n")
	
	def term(self):
		pass

def PLUGIN_ENTRY():
	return vu_helper_t()