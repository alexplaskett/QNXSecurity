
import os
import random
import sys

from ctypes import *
import glob
import shutil

import devrandom

# Script for fuzzing IPC endpoints on QNX
# Uses /dev/name/local to get endpoints
# Monitors /var/log/ for crashes
#_tracelog crashes with 28 bytes on the device
# phone-service crashes with 142 bytes or 2025 2777810.bin (can't repro)

# Some endpoints perform blocking (led_control and battmgr_monitor)
# Sim: Battmgr dies with this fuzzing too (kernel panic?) and I can't crash log it.

# Endpoints Exposed
# VirtualEventServer
# battmgr (0x200, 0x203)
# csm 
# phone-service | 0x1000 - 0x8000 | 0x8002 | 0x8011 | 0x8010 | 0x9000, 0x9001, 0x10 Size 0x1C  
# publisher-channel size 

# <alex.plaskett@mwrinfosecurity.com>

class ClientMsg(Structure):
	_fields_ = [("msg_no", c_short), ("buffer", c_char * 1024)]


class IPCFuzz:
	def __init__(self):
		self.libc = CDLL("libc.so")
		self.coids = []
		self.init_endpoints()
		self.nto_side_channel= 1073741824 # nto_side_channel (not sure this is correct)
		self.crash_dir = "./crashes/"
		self.dr = devrandom.devrandom()
		self.is_simulator = False
		self.clean_corefile()

	""" Remove any core files from the directory before fuzzing """
	def clean_corefile(self):
		os.system("mkdir crashes")
		os.system("rm -rf /var/log/*.core")

	""" The IPC endpoints we don't want to fuzz """ 
	def create_blacklist(self):
		blacklist = ["battmgr_monitor",  		# Causes blocking 
					"battmgr", 
					"led_control", 				# Also blocks
					"VirtualEventServer",
					"svga_ch", 					# Simulator only
					"slogger2",
					# Device
					"io-asr-bb10", 			# blocks
					"dsi_server_primary", 	# blocks
					"phone-service" 		# Crashes on both the sim and phone
					]

		return blacklist

	def init_endpoints(self):
		self.endpoints = os.listdir("/dev/name/local")
		bl = self.create_blacklist()

		for endpoint in self.endpoints:
			# These two cause the fuzzer to block
			#print(endpoint)
			if endpoint in bl and len(sys.argv) == 1:
				continue
			#if "battmgr_monitor" in endpoint or "led_control" in endpoint:
			#	continue
			coid = self.get_coid(endpoint)
			self.coids.append((coid,endpoint))

		print("coids are: ")
		for coid in self.coids:
			print(coid)

	def random_endpoint(self):
		endpoint = random.choice(self.endpoints)
		print("endpoint selected = ", endpoint)
		return endpoint

	def random_coid(self):
		coid = random.choice(self.coids)
		print("coid selected = ", coid[0])
		print("endpoint = ", coid[1])
		return coid

	# Unicode str needs converted to byte string literal 
	#coid = libc.name_open(b"MercuryComponent",0)
	def get_coid(self,name):
		coid = self.libc.name_open(bytes(name, encoding='utf-8'),0)
		print("coid = ", coid)
		return coid

	# /proc/mount stuff
	def proc_mount_list(self):
		arr = os.listdir("/proc/mount")
		for a in arr:
			try:
				# ND, ProcessId, ChannelId, Handle, FileType
				a.split(',')
			except:
				pass

	# Stock set of message lengths (should reverse out lengths expected)
	def message_size(self):
		size = self.dr.R(3000)

		if self.dr.chance(3):
			arr = [0x1c,512,1024,2046,4096]
			size = self.dr.choice(arr)

		size = 28

		print("msg size = ", size)
		return size

	def send_sync(self,coid,buf,size):
		ret = self.libc.MsgSend(coid,buf,size,0,0)
		if ret == -1:
			print("MsgSend failed")

	# Even the Async call blocks
	def send_async(self,coid,buf,size):
		ret = self.libc.MsgSendAsyncGbl(coid,buf,size,0)
		if ret == -1:
			print("MsgSendAsyncGbl failed")
		else:
			sys.exit(0)

	""" Sometimes be a bit more structually aware per service """
	def fuzz_smarter(self,endpoint,coid):
		if endpoint == "phone-service":
			self.fuzz_phone_service(coid)
		elif endpoint == "publisher_channel":
			self.fuzz_publisher_service(coid)

	""" /services/sys.service.phone/phone-service """
	def fuzz_phone_service(self,coid):
		data_len = 0x1C 
		low = 0x1000 
		high = 0x9000

		x = ClientMsg()
		x.msg_no = random.randint(low,high)
		self.libc.memset(x.buffer,0x44,1024)
		self.send_sync(coid,x,data_len)

	# First byte 0x20, 0x100, 0x33, 0x728 0x34, 
	def fuzz_publisher_service(self,coid):
		pass

	""" Base fuzzing function """
	def fuzz_message(self,coid,name):
		size = self.message_size()
		#size = 16537
		print("++ Fuzzing endpoint ++", name)

		try:
			buf = self.dr.fuzz(os.urandom(size))
			self.testcase = buf
		except:
			buf = b"AAAAAAAAAAAAA"
			self.testcase = buf
		
		self.send_sync(coid,buf,len(buf))
		#self.fuzz_pulse(coid)

	def save_testcase(self):
		fd = open(self.crash_dir + self.fn + ".bin","wb")
		fd.write(self.testcase)
		fd.close()

	def fuzz_pulse(self,coid):
		code = random.randint(0,127)
		print ("Pulse code = ", code)
		value = random.randint(0,127)
		ret = self.libc.MsgSendPulse(coid,0,code,value)
		print("Pulse ret = ", ret)
		if ret != -1:
			sys.exit(0)

	def fuzz_loop(self,name):

		if name != None:
			coid = (self.get_coid(name),name)

		while True:
			# Filename for the testcase to be saved to.
			self.fn = str(random.randint(0,0xffffff))

			if name == None:
				coid = self.random_coid()	
				self.fuzz_message(coid[0],coid[1])
			else:
				print(coid)
				self.fuzz_message(coid[0],coid[1])

			if self.is_simulator:
				if self.is_core_created():
					self.save_testcase()
			else:
				if not self.is_endpoint_ok("/dev/name/local/"+coid[1]):
					print("++ Endpoint seems to have died ++", coid[1])
					self.save_testcase()
					sys.exit(0)
			
	# The coid that is exposed to all processes
	def get_procmgr_sidechannel(self):
		pass
			
	def create_endpoint(self):
		buf = create_string_buffer(1024)
		self.libc.memset(buf,0x42,1024)
		libc.name_attach(0,buf,0)


	def is_core_created(self):
		arr = glob.glob('/var/log/*.core')
		if len(arr) != 0:
			print("++ Core file has been created ++", arr[0])
			shutil.move(arr[0],self.crash_dir + os.path.basename(arr[0]) + self.fn)
			return True
		return False

	""" Check to see if the endpoint is still there - indicative of crash """
	def is_endpoint_ok(self,endpoint):
		return os.path.exists(endpoint)


if __name__ == "__main__":
	fuzz = IPCFuzz()
	if len(sys.argv) > 1:
		fuzz.fuzz_loop(sys.argv[1])
	else:
		fuzz.fuzz_loop(None)

