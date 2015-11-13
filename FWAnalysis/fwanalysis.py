

""" Glorified grep script for an pre-extracted firmware image to prioritise interesting files for auditing
Written for QNX (BB10) initially to speed up reversing lots of binaries
Looks for defined symbols, therefore does not find runtime symbol resolutions (dlsym etc)
Works on POSIX functions + QNX specifics 
Prints to stdout..
al3x 2015
Add linker stuff and compile flags
"""

import os
import struct
from glob import glob
import subprocess
import sys

class FWAnalysis:

	def __init__(self,root_dir,out_dir,readelf,strings):
		self.root_dir = root_dir
		self.out_dir = out_dir
		self.analysis_file = ""
		self.readelf = readelf
		self.init_fs_listing()
		self.strings = strings
		self.exec_list = set()
		self.setuid_list = set()
		self.dangerous_list = set()
		self.perm_change_list = set()
		self.resmgrs = set()
		self.do_qnx_specific_checks = True
		self.int_strings = set()
		self.qnx_stuff = set()

	def init_fs_listing(self):
		self.files = [y for x in os.walk(self.root_dir) for y in glob(os.path.join(x[0], '*'))]

	def is_file_elf(self,path):
		if os.path.isdir(path):
			return False
		else:
			tmp = open(path,"rb")
			x = tmp.read(4)
			if x == b"\x7fELF":
				return True
			tmp.close()
		return False

	def dump_symbols(self,f):
		#of = open("outfile.txt","w")
		cmd = [self.readelf,"-s",f]
		#print(cmd)
		with subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as p:
			for line in p.stdout:
				#print(line, end='')
				tmp = line.split(" ")
				symbol = tmp[len(tmp)-1].strip()
				#print(symbol)
				self.contains_interesting_functions(symbol,f)
				if self.do_qnx_specific_checks:
					self.qnx_specific_checks(symbol,f)

	def contains_interesting_functions(self,symbol,f):
		exec_list = ["spawn","spawnl","posix_spawn","posix_spawnp","execl","execlp","execle","execv",
		"execvp","execvpe","system","dlopen","popen"]
		for elem in exec_list:
			if elem == symbol:
				#print(symbol)
				self.exec_list.add((f,symbol))
				return True

		# Contains typical unsafe functions
		# strcpy, sprintf, mktemp
		dang_list = ["strcpy","sprintf","strcat","gets","mktemp"]
		for elem in dang_list:
			if elem == symbol:
				self.dangerous_list.add((f,symbol))
				return True

		setuid_list = ["setuid", "seteuid", "setgid"]
		for elem in setuid_list:
			if elem == symbol:
				self.setuid_list.add((f,symbol))
				return True


		perm_changes = ["chmod","lchmod", "fchmod","chown","fchown","lchown"]
		for elem in perm_changes:
			if elem == symbol:
				self.perm_change_list.add((f,symbol))
				return True

		return False

	def dump_strings(self,f):
		cmd = [self.strings,f]
		with subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as p:
			for line in p.stdout:
				self.contains_interesting_strings(line,f)
				#print(line, end='')		

	def contains_interesting_strings(self,string,f):
		strings = ["tmp","devuser","msg::","msg:","dat","conf","LD_PRELOAD","/pps/","shared",".so","PATH","test","bluetooth","dumper"]
		for s in strings:
			if s in string:
				self.int_strings.add((f,string.strip()))


	########### QNX Specifics ##################

	def qnx_specific_checks(self,symbol,f):
		self.uses_procmgr_abilities(symbol,f)
		self.binds_to_resmgr_namespace(symbol,f)
		self.binds_to_resmgr_namespace(symbol,f)
		self.attaches_a_msghandler(symbol,f)
		self.does_receive_messages(symbol,f)

	# uses abilities
	def uses_procmgr_abilities(self,symbol,f):
		if "procmgr_ability" in symbol:
			self.qnx_stuff.add((f,symbol))

	# resmgr_attach
	def binds_to_resmgr_namespace(self,symbol,f):
		if "resmgr_attach" in symbol:
			self.qnx_stuff.add((f,symbol))

	# name_attach
	def binds_to_ipc_names(self,symbol,f):
		if "name_attach" in symbol:
			self.qnx_stuff.add((f,symbol))

	# message_attach
	def attaches_a_msghandler(self,symbol,f):
		if "message_attach" in symbol:
			self.qnx_stuff.add((f,symbol))

	def attaches_a_pulsehandler(self,symbol,f):
		if "pulse_attach" in symbol:
			self.qnx_stuff.add((f,symbol))			

	# MsgReceive
	def does_receive_messages(self,symbol,f):
		if "MsgReceive" in symbol:
			self.qnx_stuff.add((f,symbol))

	##########################################

	def pretty_print(self):
		print("++ Files which spawn child processes ++")
		for x in sorted(self.exec_list):
			t = x[0].split("\\")
			fn = t[len(t)-1]
			print(fn, x[1])

		print("++ Dangerous functions ++ ")
		for x in sorted(self.dangerous_list):
			t = x[0].split("\\")
			fn = t[len(t)-1]
			print(fn, x[1])

		print("++ Setuid list ++ ")
		for x in sorted(self.setuid_list):
			t = x[0].split("\\")
			fn = t[len(t)-1]
			print(fn, x[1])

		print("++ Perm change list ++ ")
		for x in sorted(self.perm_change_list):
			t = x[0].split("\\")
			fn = t[len(t)-1]
			print(fn, x[1])


		print("++ Interesting strings ++ ")
		for x in sorted(self.int_strings):
			t = x[0].split("\\")
			fn = t[len(t)-1]
			print(fn, x[1])

	def pretty_print_qnx(self):
		print("++ QNX specifics ++ ")
		for x in sorted(self.qnx_stuff):
			t = x[0].split("\\")
			fn = t[len(t)-1]
			print(fn, x[1])		


	def run_analysis(self,f):
		self.dump_symbols(f)
		self.dump_strings(f)

	def main_loop(self):
		for f in self.files:
			if self.is_file_elf(f):
				self.run_analysis(f)
				

if __name__ == "__main__":
	
	# set your paths to tools here
	root_dir = "C:\\Users\\user1\\Documents\\Research\\BB10\\Firmware\\ARM\\os.winchester.factory_sfi.10.3.1.2243.armle-v7\\"
	readelf = "C:\\Users\\user1\\Documents\\Research\\BB10\\Firmware\\ARM\\arm-unknown-nto-qnx8.0.0eabi-readelf.exe"
	objdump_path = "C:\\Users\\user1\\Documents\\Research\\BB10\\Firmware\\ARM\\arm-unknown-nto-qnx8.0.0eabi-objdump.exe"
	strings_path = "C:\\Users\\user1\\Documents\\Research\\BB10\\Firmware\\ARM\\arm-unknown-nto-qnx8.0.0eabi-strings.exe"
	out_dir = "outdir"

	fwa = FWAnalysis(root_dir,out_dir,readelf,strings_path)
	fwa.main_loop()
	fwa.pretty_print()
	fwa.pretty_print_qnx()