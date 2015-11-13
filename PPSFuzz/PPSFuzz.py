
import os

""" Possibly move this to a bash script since its easier 
http://www.qnx.com/developers/docs/6.5.0/index.jsp?topic=%2Fcom.qnx.doc.neutrino_pps%2Fapi%2Fppsparse.html
"""

class PPSFuzz:

	def __init__(self):
		# Obtain a list of all the PPS endpoints
		self.endpoints = []

	def find_wr_pps_endpoints(self):
		for (dir, _, files) in os.walk("/pps"):
			for f in files:
				path = os.path.join(dir, f)
				#print(path)

				try:
					fd = open(path,"w")
					print("opened wr ", path)
					self.endpoints.append((path,fd))
					self.send_pps_message(fd)
				except:
					pass

	""" Create a malformed PPS message """
	def create_pps_message(self):
		data = ""
		# echo "msg::launchApp\ndat::sys.settings.gYABgFXZghhSmuJ6oBTACT1DwpQ" > /pps/system/navigator/control
		# echo "msg::lockDevice\ndat::Backup Interrupted at $(date)" >> /pps/system/navigator/background
		message = "msg::command" + "\ndat::" + data
		return message

	""" Send PPS message to endpoint """
	def send_pps_message(self,fd):
		print("sending pps message")
		msg = self.create_pps_message()
		print(msg)
		ret = fd.write(msg)
		print(ret)


if __name__ == "__main__":
	ppsfuzz = PPSFuzz()
	ppsfuzz.find_wr_pps_endpoints()