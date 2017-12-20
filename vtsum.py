#!/usr/bin/python

'''
vtsum

the equivalent of md5sum, but retrieves virustotal results as well

'''

import requests, hashlib, argparse

# add your api key:
vtkey = '' 

hashMD5 = hashlib.md5()
parser = argparse.ArgumentParser()
parser.add_argument('filename')
args = parser.parse_args()
sample = args.filename
sampleName = str(sample)

with open(sample, 'rb') as sample:
	buf = sample.read()
	hashMD5.update(buf)
	sample.close()
sampleMD5 = hashMD5.hexdigest()
print ("{} {}".format(sampleMD5,sampleName))

params = {'apikey': vtkey, 'resource': sampleMD5}
headers = {"User-Agent" : "User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14"}
r = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
data = r.json()
if data['response_code'] == 1:
	scanDate = data['scan_date']
	positives = data['positives']
	total = data['total']
	permalink = data['permalink']
	scans = data['scans']
	print ("Detection Ratio: {}/{}".format(positives,total))
	#print ("Detection Ratio: {}/{} | {}".format(positives,total,permalink)) # if you want to print the link as well
	exit()
else:
	print ("Not found on VT")
	exit()


