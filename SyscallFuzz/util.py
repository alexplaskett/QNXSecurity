
import os
from struct import *

""" Fuzzing utility wrapper """

class Util:

	def __init__(self):
		if os.path.exists("/dev/urandom"):
			self.fd = open("/dev/urandom","rb")
			self.urandom = self.unixrandom
		else:
			self.urandom = self.winrandom

	def unixrandom(self, n):
		return self.fd.read(n)

	def winrandom(self, n):
		return os.urandom(n)	

	def R(self,n):
		return unpack("I", self.urandom(4))[0]%n

	def choice(self,arr):
		return arr[self.R(len(arr))]

	def chance(self,n):
		if self.R(n)==0:
			return True
		else:
			return False

	def randint(self):
		pass

	def corner_case(self):
		pass

	def get_all_chids(self):
		pass