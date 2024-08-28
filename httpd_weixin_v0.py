#!/usr/bin/python
# encoding: utf-8

import sys
import os
import logging
import urllib,urllib2
import json
import SimpleHTTPServer  
import SocketServer  
import threading
import urlparse
from time import sleep

reload(sys)
sys.setdefaultencoding('utf-8')

#scriptpath='/usr/lib/zabbix/alertscripts/'
#proxy_handler = urllib2.ProxyHandler({"http" : "http://192.168.1.1:8080"})
#opener = urllib2.build_opener(proxy_handler)
#urllib2.install_opener(opener)

logging.basicConfig(
	level=logging.DEBUG,
	format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
	datefmt='%a, %d %b %Y %H:%M:%S',
	filename='/tmp/weixin.log',
	filemode='w'
)

def url2Dict(url):
	query = urlparse.urlparse(url).query
	return dict([(k, v[0]) for k, v in urlparse.parse_qs(query).items()])

class SETHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):  
	global config_file, config
#		def createHTML(self):  
#		html = file("index.html", "r")  
#		for line in html:  
#			self.wfile.write(line)  

	def do_GET(self):  
#		print "GET"  
#		logging.debug("Get=%s" % self.path)
#		print self.path
#		print self.headers; 
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.end_headers()
#		self.createHTML()
		parameter = url2Dict(self.path)
#		print "Request: %s " % parameter
		if parameter.has_key('usr') :
			userID = parameter['usr']
		else:
			userID = ""
		if parameter.has_key('msg'):
			message = parameter['msg']
		else:
			message = ""
		if len(userID)>0 and len(message)>0 :
#			logging.debug("Origenal message=%s: " % message)
			#CorpID是企业号的标识
			#CorpID='wx111111111111111111111111111111111111111111111'     #测试用企业号
			#corpsecret是管理组凭证密钥
			#corpsecret='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
			accesstoken = gettoken("/tmp/wx_token.txt")

			new_message='\n'
			new_message=message
		#	logging.debug("argv1=%s, argv2=%s" % (userID, subject))
		#	logging.debug("Message=%s" % new_message)
			senddata(accesstoken,userID,new_message)
			self.wfile.write("OK")
		else:
			self.wfile.write("Parameter error! need: usr=xxx&msg=xxx")

def gettoken(wx_file):
	token=""
	while len(token) == 0 :
		f = open(wx_file)
		token = f.read()
		f.close()

#	gettoken_url = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=' + corpid + '&corpsecret=' + corpsecret
#	try:
#		token_file = urllib2.urlopen(gettoken_url)
#	except urllib2.HTTPError as e:
#		logging.debug("gettoken error Message=%s, %s" % (e.code, e.read().decode('utf-8')))
#		sys.exit()
#	token_data = token_file.read().decode('utf-8')
#	token_json = json.loads(token_data)
#	token_json.keys()
#	token = token_json['access_token']

	logging.debug("Token=%s" % token)
	return token

def senddata(access_token,user,content):
	send_url = 'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=' + access_token
	send_values = {
		"touser":user,    #企业号中的用户帐号，在zabbix用户Media中配置，如果配置不正常，将按部门发送。
#		"toparty":"1",    #企业号中的部门id
		"msgtype":"text",  #企业号中的应用id，消息类型。
		"agentid":"1000003",    #测试agentid:5 生产agentid:8
		"text":{
			"content":content.encode('utf-8')
			},
		"safe":"0"
		}
	send_data = json.dumps(send_values, ensure_ascii=False).encode('utf-8')
#	logging.debug("Source message=%s" % send_data)
	send_data = send_data.replace('\\\\r\\\\\n','').replace('\r\n','')
	send_data = send_data.replace('\\\\n',chr(10)).replace('\\\\t',chr(7)).replace('\\\\"','"')
	send_request = urllib2.Request(send_url, send_data)
	response = json.loads(urllib2.urlopen(send_request).read())
	if response['errcode'] !=0 :
		logging.debug("Send message=%s" % send_data)
		logging.debug("Response=%s" % str(response))
	else:
		logging.debug("Send to %s with %s" %(user, content))

if __name__ == '__main__':
	gettoken("/tmp/wx_token.txt")
	Handler = SETHandler  
	HttpPORT = 8001
	httpd = SocketServer.TCPServer(("", HttpPORT), Handler)  
	print "serving at port", HttpPORT  
	server_thread = threading.Thread(target=httpd.serve_forever)
	server_thread.daemon = True
	server_thread.start()
	print "Server loop running in thread:", server_thread.name

	while True:
		sleep(300)
		gettoken("/tmp/wx_token.txt")
		if not server_thread.isAlive() :
			print "\nRestart httpd thread @ %s" % (ctime())
			telnet_thread = threading.Thread(target=httpd.serve_forever)
			telnet_thread.start()
#			print "\nChecking threading %s" % ctime()
		continue
		
