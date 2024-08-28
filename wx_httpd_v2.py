#!/usr/bin/python3.8
# encoding: utf-8

import socket
import urllib.parse
import urllib.request
from time import sleep,ctime
import os
import threading
import json

def handle_request(client_connection, client_address):
	request = client_connection.recv(1024).decode()
	#print(f"Received request: {request}")

	# 解析请求行
	request_line = request.splitlines()[0]
	method, path, _ = request_line.split()

	if method == 'GET':
		# 解析 GET 请求参数
		parsed_url = urllib.parse.urlparse(path)
		query_params = urllib.parse.parse_qs(urllib.parse.unquote(parsed_url.query))
		usr = query_params.get('usr', [''])[0]
		msg = query_params.get('msg', [''])[0]
		source = query_params.get('from', [''])[0]
	elif method == 'POST':
		# 解析 POST 请求参数
		headers, body  = request.split('\r\n\r\n')
		post_params = urllib.parse.parse_qs(urllib.parse.unquote(body))
		usr = post_params.get('usr', [''])[0]
		msg = post_params.get('msg', [''])[0]
		source = post_params.get('from', [''])[0]
	else:
		usr = ''
		msg = ''
	if usr != "" and msg != "" :
		if source != '' :
			msg = source + "：" + msg
		else :
			msg = client_address[0] + "：" + msg
		response = senddata(usr,msg)
	else :
		print(u'Error request:\n%s' % request)
		response = "format : usr=xxxx&msg=123456&from=test <br/> Your request is : <pre>" + request + "</pre>"
	# 准备响应内容
	http_response = f"""\
HTTP/1.1 200 OK

<html>
<head>
	<title>Simple HTTP Server</title>
</head>
<body>
	<h1>Received Data</h1>
	<p>User: {usr}</p>
	<p>Message: {msg}</p>
	<p>Response : {response}</p>
</body>
</html>
"""
	# 发送响应
	client_connection.sendall(http_response.encode())
	client_connection.close()
	
def wechat_udp(host='0.0.0.0',port=8001):
	mSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	mSocket.bind((host,port))
	while True:
		result = "Error, message format : usr=1111&msg=2222&from=3333".encode("UTF-8")
		revcData, (remoteHost, remotePort) = mSocket.recvfrom(1024)
		try:
			query_string = revcData.decode("gb2312")
			revc_msg = {item.split('=')[0].lower(): item.split('=')[1] for item in query_string.split('&')}
			print("%s UDP receive : %s" % (ctime(),revc_msg))
			if revc_msg['usr'] != "" and revc_msg['msg'] != "" :
				if 'from' in revc_msg:
					revc_msg['msg'] = revc_msg['from'] + "：" + revc_msg['msg']
				else :
					revc_msg['msg'] = remoteHost + "：" + revc_msg['msg']
				senddata(revc_msg['usr'], revc_msg['msg'])
				result = "R".encode("UTF-8")
		except Exception as e :
			print("%s wechat UDP error : %s" % (ctime(),e))
		mSocket.sendto(result,(remoteHost, remotePort))
		
def senddata(user,content):
	global access_token
	send_url = 'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=' + access_token
	content = content.replace('\\\\r\\\\\n','').replace('\r\n','')
	content = content.replace('\\\\n',chr(10)).replace('\\\\t',chr(7)).replace('\\\\"','"')
	#print('%s user = %s, content = %s' % (ctime(),user, content))
	if len(content) >= 1000 or 1 :      #当内容大于1000字符时用文本消息，小于1000字符时用卡片式
		send_values = {
			"touser":user,	#企业号中的用户帐号，在zabbix用户Media中配置，如果配置不正常，将按部门发送。
	#		"toparty":"1",	#企业号中的部门id
			"msgtype":"text",  #企业号中的应用id，消息类型。
			"agentid":"1000003",	#测试agentid:5 生产agentid:8
			"text":{
				"content":content,
				},
			"safe":"0"
			}
	else :
		send_values = {
			"touser":user,	#企业号中的用户帐号，在zabbix用户Media中配置，如果配置不正常，将按部门发送。
	#		"toparty":"1",	#企业号中的部门id
			"msgtype":"textcard",  #企业号中的应用id，消息类型。
			"agentid":"1000003",	#测试agentid:5 生产agentid:8
			"textcard":{
				"title": "test",
#				"content":content.encode('utf-8')
				"description" : content,
				"url": "http://test:88/"
				},
			"safe":"0"
			}
	send_data = json.dumps(send_values, ensure_ascii=False)
	#send_data = urllib.parse.urlencode(send_values).encode('ascii')
	print("%s Sending message=%s" % (ctime(),send_data))
	try:
		send_response = urllib.request.urlopen(send_url, send_data.encode('utf-8')).read()
		response = json.loads(send_response.decode('utf-8'))
	except Exception as e:
		response = {u'errmsg': e}
		print("%s Send Error Response=%s" % (ctime(), response))
	return response

def wx_token() :
	global access_token
	if os.path.exists("/tmp/wx_token.txt") :
		with open("/tmp/wx_token.txt") as f :
			access_token = f.read()
		f.close()
	while True :
		get_token()
		sleep(1800)

def get_token(corpid="aaaaaaa",corpsecret="11111111111111111111111111111"):
	global access_token
	gettoken_url = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=' + corpid + '&corpsecret=' + corpsecret
	try:
		token_file = urllib.request.urlopen(gettoken_url)
	except urllib.error.HTTPError as e:
		print("%s Get token error Message=%s, %s" % (ctime(), e.code, e.reason))
		sleep(10)
#			sys.exit()
	else :
		token_data = token_file.read().decode('utf-8')
		token_json = json.loads(token_data)
		token_json.keys()
		access_token = token_json['access_token']
		print("%s Get token=%s" % (ctime(),access_token))
		with open("/tmp/wx_token.txt", 'w', encoding='utf-8') as f:
			f.write(access_token)
		f.close()
		

def run_server(host='0.0.0.0',port=8001):
	# 创建一个 socket 对象
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# 绑定主机和端口
	server_socket.bind((host, port))
	# 开始监听连接
	server_socket.listen(5)		# 最多允许5个连接排队
	print(f"Listening on {host}:{port}...")
	
	while True:
		# 接受客户端连接
		client_connection, client_address = server_socket.accept()
		print(f"Connection from {client_address}")
		# 处理客户端请求
		thread = threading.Thread(target=handle_request, args=(client_connection, client_address))
		thread.start()

## 线程状态管理
threads = {}
thread_targets = {
	'http_server': run_server,
	'udp_server': wechat_udp,
	'wx_token': wx_token,
}

# 启动线程
def start_thread(name, target):
	thread = threading.Thread(target=target, name=name)
	thread.setDaemon(True)  # 将线程设置为守护线程
	thread.start()
	threads[name] = thread
	print("%s Starting %s thread" % (ctime(),name))

# 检查线程状态
def check_threads():
	while True:
		for name, thread in threads.items():
			if not thread.is_alive():
				#print("%s : %s is not alive. Restarting..." % (ctime(),name))
				start_thread(name, thread_targets[name])
		sleep(5)  

if __name__ == '__main__':
	# 使用循环启动所有线程
	for name, target in thread_targets.items():
		start_thread(name, target)
	
	# 启动线程检查
	check_thread = threading.Thread(target=check_threads)
	check_thread.setDaemon(True)  # 将线程设置为守护线程
	check_thread.start()
	
	# 主线程保持运行
	try:
		while True:
			sleep(10)
	except KeyboardInterrupt:
		print("Shutting down...")
