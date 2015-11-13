

""" Script to launch processes as devuser and monitor for crashes 
Supports GUI applications and console apps
<alex.plaskett@mwrinfosecurity.com> 

# Currently you need Momentics running for the USB connection.

TODO:
- Add application to monitor or install 

- Fix symbols and other stuff
- Add support for IPC Fuzzing?
- Add couchdb support?
- Determine how to prevent the screen from locking every 5mins
- Add simulator support 

(gdb) set solib-search-path  /base/usr/lib
"""

import time
import os
import subprocess
import signal
import sys
import httplib
import urllib2
import random

class BlackberryMonitor:

	def __init__(self):
		self.gdb_location = "aaa"
		self.blackberry_deploy = "C:\\bbndk\\host_10_3_0_2702\\win32\\x86\\usr\\bin\\blackberry-deploy.bat"
		self.gdb_path = "C:\\bbndk\\host_10_3_0_2702\\win32\\x86\\usr\\bin\\ntox86-gdb.exe"
		self.is_device = True # set to false for similator
		self.device_ip = "169.254.0.1"
		self.password = "1234"
		self.on_device_binary = ""
		self.timeout = 5000
		self.crashes_dir = "crashes/"

	""" Launches the application so it runs in the UI """
	def launch_application(self,name):
		deploy_args = ["-launchApp", "-debugNative",self.device_ip,"-password", self.password, "-package-fullname" ,name]
		cmd = [self.blackberry_deploy]
		for a in deploy_args:
			cmd.append(a)
		print cmd
		ps = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
		print("[+] Starting application process " + str(ps.pid))
		while True:
			out = ps.stdout.readline()
			#print out
			if out == '' and ps.poll() != None:
				break
			if out != '':
				sys.stdout.write(out)
				sys.stdout.flush()
				# Get the PID back from it in order to attach
				if "result" in out and "running" in out:
					# process already running
					tmp = out.split(",")
					self.pid = tmp[1]
					print("++ RUNNING PID FOUND ++ ", self.pid)
					return
				if "result" in out:
					tmp = out.split("::")
					self.pid = tmp[1]
					print("++ PID FOUND ++ ", self.pid)

	""" Pushes a binary to the device/sim for fuzzing """
	def deploy_binary(self):
		pass

	""" Launches a binary under GDB and runs it for fuzzing """
	def launch_binary_gdb(self):
		pass

	""" Uses the return code to determine if a process has crashed """ 
	def launch_binary_ret(self):
		pass

	def write_gdb_commands_attach(self):
		#self.pid = 1
		fd = open("gdbcmds","w")
		target = "target qnx " + self.device_ip + ":8000\n"
		fd.write(target)
		attach = "attach " + str(self.pid) + "\n"
		fd.write(attach)
		misc = "c\nset disassembly-flavor intel\nbt\ni r\nx/10i $eip\nq"

		fd.write(misc)
		fd.close()

	def write_gdb_commands_on_device(self):
		fd = open("gdbcmds","w")
		target = "target qnx " + self.device_ip + ":8000\n"
		binary = "file " + self.on_device_binary + "\n"
		cont = "c\n"

	def gdb_attach(self):
		gdb = self.gdb_path
		gdb_args = ["--quiet", "-batch", "-x", "gdbcmds"]
		cmd = [gdb]
		for a in gdb_args:
			cmd.append(a)
		return self.timed_test(cmd)

	def timed_test(self,cmd):
		ps = subprocess.Popen(cmd,stdout = open("outfile.txt","w"), stderr=subprocess.STDOUT, shell=False)
		print("[+] Starting monitoring process " + str(ps.pid))
		c=0
		crash = False
		while True:
			time.sleep(0.1)
			c += 100
			ps.poll()
			if ps.returncode != None:
				crash = True
				print("A crash has occured!")
				self.crash_has_occured()
				#sys.exit(0)
				break

			if (c % 90000 == 0):
				print("++ Restarting browser ++")
				break

		return crash

	def is_browser_hung(self):
		print("++ Checking if browser has hung ++")
		f = urllib2.urlopen("http://192.168.0.5:8080" + "/PING")
		resp = f.read(10)
		print("is_browser_hung: " + resp) 
		if "DEAD" in resp:
			sys.exit(0)

	# This cleanup method sucks, there must be a better way
	# Dont need to write this out every time, store in file
	def clean_up(self):
		fd = open("cleanup.txt","w")
		target = "target qnx " + self.device_ip + ":8000\n"
		# Connect to QCONN and run kill -9 on the old PID.
		stuff = "run /bin/slay -9 WebviewNav\nq"
		fd.write(target)
		fd.write(stuff)
		fd.close()

		gdb = self.gdb_path
		gdb_args = ["--quiet", "-batch", "-x", "cleanup.txt"]
		cmd = [gdb]
		for a in gdb_args:
			cmd.append(a)

		ps = subprocess.Popen(cmd,stdout = open("cleanup-out.txt","w"), stderr=subprocess.STDOUT, shell=False)
		print("[+] Starting cleanup process " + str(ps.pid))



	def crash_has_occured(self):
		# Save the crash state outfile
		fn = str(random.randint(0,0xffffff)) + ".txt"
		shutil.move("outfile.txt",self.crash_dir+fn)

		# Save the testcase causing the crash
		f = urllib2.urlopen("http://192.168.0.5:8080" + "/CRASH")
		# Get the crash data back from the server (as a zip)

	def fuzz_session(self):

		while True:
			# Kill all apps first
			self.clean_up()
			self.launch_application("com.example.WebviewNav.testDev__WebviewNavc6277f1b")
			self.write_gdb_commands_attach()
			self.gdb_attach()



if __name__ == "__main__":
	bm = BlackberryMonitor()
	bm.fuzz_session()
