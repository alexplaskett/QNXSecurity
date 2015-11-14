
import os
from glob import glob

# Dirty script for doing application analysis for BB10 apps.

class AppAnalysis:

	def __init__(self):
		self.root_dir = "apps"
		self.files = [y for x in os.walk(self.root_dir) for y in glob(os.path.join(x[0], '*'))]

	def read_manifest(self):
		pass

	def parse_manifest(self,fn):
		tmp = open(fn,"r")
		data = tmp.readlines()
		#print(data)
		tmp.close()
		self.pull_uri_handlers(data)


	# connectResult = QObject::connect(&invokeManager, 
    #    SIGNAL(invoked(const bb::system::InvokeRequest&)),
    #    &myApp, SLOT(onInvoke(const bb::system::InvokeRequest&)));
     

	def pull_uri_handlers(self,data):
		# bb.action.VIEW
		for line in data:
			if "bb.action.VIEW" in line:
				print(line)

	def pull_mime_type(self):
		pass


	def http_links(self):
		pass

	def app_analysis(self):
		for f in self.files:
			#print(f)
			if "MANIFEST.MF" in f:
				print(f)
				self.parse_manifest(f)



if __name__ == "__main__":
	appa = AppAnalysis()
	appa.app_analysis()
