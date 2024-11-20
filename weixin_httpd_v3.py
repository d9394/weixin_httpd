#!/usr/bin/python3.8
# encoding: utf-8

import socket
import urllib.parse
import urllib.request
from time import sleep,ctime
import os
import threading
import json
import imghdr

MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 限制最大上传文件大小为1MB
UPLOAD_DIR = '/tmp/html/'

def parse_headers(header_data):
	"""解析 HTTP 请求头"""
	headers = {}
	for line in header_data.split("\r\n"):
		if ": " in line:
			key, value = line.split(": ", 1)
			headers[key.lower()] = value
	return headers

def parse_urlencoded(body):
	"""解析 application/x-www-form-urlencoded 格式的 POST 数据"""
	return urllib.parse.parse_qs(body.decode('utf-8'))

def handle_multipart_form_data(body, boundary):
	"""处理 multipart/form-data 格式"""
	parts = body.split(f"--{boundary}".encode())
	form_data = {}
	file_data = None
	file_name = None

	for part in parts:
		if b"Content-Disposition" in part:
			headers, content = part.split(b"\r\n\r\n", 1)
			headers_str = headers.decode("utf-8")
			if 'filename="' in headers_str:
				# 处理文件
				file_name = headers_str.split('filename="')[-1].split('"')[0]
				file_data = content.strip(b"\r\n--")
			else:
				# 处理表单字段
				field_name = headers_str.split('name="')[-1].split('"')[0]
				form_data[field_name] = [content.decode("utf-8").strip()]
	return form_data, file_data, file_name

def save_file(file_data, filename):
	"""保存上传的文件"""
	if file_data and filename:
		file_path = os.path.join(UPLOAD_DIR, filename)
		with open(file_path, "wb") as f:
			f.write(file_data)
		print(f"File saved: {file_path}")

def extract_image(data):
	"""
	从二进制数据中提取 PNG 或 JPEG 图像。
	
	:param data: 二进制数据
	:return: 提取的图像二进制数据（如果存在），否则返回 None
	"""
	# PNG 文件的标志
	png_header = b'\x89PNG\r\n\x1a\n'
	png_end = b'IEND\xaeB`\x82'

	# JPEG 文件的标志
	jpeg_header = b'\xff\xd8'
	jpeg_end = b'\xff\xd9'

	# 尝试提取 PNG 图像
	png_start = data.find(png_header)
	if png_start != -1:
		png_end_idx = data.find(png_end, png_start)
		if png_end_idx != -1:
			png_end_idx += len(png_end)  # 包含结束标志
			return data[png_start:png_end_idx]

	# 尝试提取 JPEG 图像
	jpeg_start = data.find(jpeg_header)
	if jpeg_start != -1:
		jpeg_end_idx = data.find(jpeg_end, jpeg_start)
		if jpeg_end_idx != -1:
			jpeg_end_idx += len(jpeg_end)  # 包含结束标志
			return data[jpeg_start:jpeg_end_idx]

	# 如果没有找到 PNG 或 JPEG 图像
	return None

def handle_request(client_connection):
	#client_connection.settimeout(5)
	try:
		# 初始化请求接收
		request = b""
		while b"\r\n\r\n" not in request:
			chunk = client_connection.recv(1024)
			if not chunk:
				break
			request += chunk
		#print(f"Request length : {len(request)}")
		# 拆分请求头和请求体
		header_data, body = request.split(b"\r\n\r\n", 1)
		header_lines = header_data.decode("utf-8").split("\r\n")
		request_line = header_lines[0]
		headers = parse_headers("\r\n".join(header_lines[1:]))

		# 解析请求行
		method, path, _ = request_line.split()
		parsed_url = urllib.parse.urlparse(path)
		query_params = urllib.parse.parse_qs(parsed_url.query)

		usr = query_params.get("usr", [""])[0]
		msg = query_params.get("msg", [""])[0]
		source = query_params.get("from", [""])[0]
		image = None

		# 处理 GET 请求
		if method == "GET":
			response = f"GET received: usr={usr}, msg={msg}, from={source}"

		# 处理 POST 请求
		elif method == "POST":
		elif method == "POST":
			#print("POST request=%s" % request)
			# 确认 Content-Length
			content_length = int(headers.get("content-length", 0))
			if content_length > MAX_CONTENT_LENGTH:
				response = "Error: Content-Length exceeds the maximum allowed size."
			else:
				# 如果header有content_length信息，则按content_length接收
				if content_length > 0 :
					while len(body) < content_length:
						body += client_connection.recv(1024)
				else :
					while chunk:
						chunk = client_connection.recv(1024)
						body += chunk
				# 根据 Content-Type 处理不同的 POST 数据格式
				content_type = headers.get("content-type", "")
				if "multipart/form-data" in content_type:
					boundary = content_type.split("boundary=")[-1]
					form_data, file_data, file_name = handle_multipart_form_data(body, boundary)
					#if body :
					#	print("POST body : %s" % body)
					#if file_data :
					#	print("-X POST -F file= form=%s, file=%s" % (form_data, file_name))
					if not usr ：
						usr = form_data.get("usr", [""])[0]
					if not msg :
						msg = form_data.get("msg", [""])[0]
					if not source :
						source = form_data.get("from", [""])[0]
					#save_file(file_data, file_name)
					response = f"POST received: usr={usr}, msg={msg}, from={source}, file={file_name}"
					if file_data:
						response += f", {len(file_data)} bytes"
					image = file_data
				elif content_type == "application/x-www-form-urlencoded":
					body = extract_image(body)
					#if body :
					#	print("POST --post-file \theader=%s, \n\tbody=%d" % (header_data, len(body)))
					#form_data = parse_urlencoded(body)
					#usr = form_data.get("usr", [""])[0]
					#msg = form_data.get("msg", [""])[0]
					#source = form_data.get("from", [""])[0]
					#save_file(body, "uploaded_file.bin")
					response = f"POST received: usr={usr}, msg={msg}, from={source}, raw file saved."
					if body :
						response += f", {len(body)} bytes"
					image = body
				else:
					response = "Error: Unsupported Content-Type."
		else:
			response = "Error: Unsupported HTTP method."

		if usr and msg:
			msg_content = f"{source if source else client_address[0]}: {msg}"
			response = senddata(usr, msg_content, image)  # 确保senddata函数存在
		else:
			print('Error request:\n%s' % request.decode())
			response = "Format: usr=xxxx&msg=123456 <br/> Your request is: <pre>" + ', '.join(header_lines) + "</pre>"
		
		# 返回 HTTP 响应
		http_response = f"""\
HTTP/1.1 200 OK
Content-Type: text/plain

{response}
"""
	except Exception as e:
		print("Error handling request:", e)
		http_response = f"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nServer error: {e}"
	finally:
		client_connection.sendall(http_response.encode())
		client_connection.close()

def wechat_udp(host='0.0.0.0',port=8001):
	mSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	mSocket.bind((host,port))
	while True:
		result = "Error, message format : usr=1111&msg=2222&from=3333".encode("UTF-8")
		revcData, (remoteHost, remotePort) = mSocket.recvfrom(1024)
		try:
			query_string = revcData.decode("gb2312", errors='ignore')
			revc_msg = {item.split('=')[0].lower(): item.split('=')[1] for item in query_string.split('&')}
			print("%s UDP receive : %s" % (ctime(),revc_msg))
			if revc_msg['usr'] != "" and revc_msg['msg'] != "" :
				if 'from' in revc_msg:
					revc_msg['msg'] = revc_msg['from'] + "：" + revc_msg['msg']
				else :
					revc_msg['msg'] = remoteHost + "：" + revc_msg['msg']
				senddata(revc_msg['usr'], revc_msg['msg'], None)
				result = "R".encode("UTF-8")
		except Exception as e :
			print("%s wechat UDP error : %s" % (ctime(),e))
		mSocket.sendto(result,(remoteHost, remotePort))
		
def senddata(user,content, image):
	global access_token
	send_url = 'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=' + access_token
	content = content.replace('\\\\r\\\\\n','').replace('\r\n','')
	content = content.replace('\\\\n',chr(10)).replace('\\\\t',chr(7)).replace('\\\\"','"')
	#print('%s user = %s, content = %s' % (ctime(),user, content))
	if image :		#如果是带图片的信息，需先上传图片
		media_id = upload_image(access_token, image)
		if media_id[:4] != "err:" :
			send_values = {
				"touser": user, # 用户ID
				"msgtype": "image",
				"agentid": "1",
				"image": {
					"media_id": media_id
				},
				"safe": 0
				}
		else :
			send_values = None
			response = {media_id}
	elif len(content) >= 1000 or 1 :
		send_values = {
			"touser":user,	#企业号中的用户帐号，在zabbix用户Media中配置，如果配置不正常，将按部门发送。
	#		"toparty":"1",	#企业号中的部门id
			"msgtype":"text",  #企业号中的应用id，消息类型。
			"agentid":"1",	#测试agentid:5 生产agentid:8
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
			"agentid":"1",	#测试agentid:5 生产agentid:8
			"textcard":{
				"title": "test",
#				"content":content.encode('utf-8')
				"description" : content,
				"url": "http://www.test.com/"
				},
			"safe":"0"
			}
	if send_values :
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

def upload_image(access_token, image_data):
	url = f"https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type=image"
	image_type = imghdr.what(None, image_data)
	if image_type not in ["jpeg", "png"]:
		print("Unsupported image format %s. Only PNG and JPEG are allowed." % image_type)
		return u"err:Unsupported image format."

	mime_type = f"image/{image_type}"  # e.g., image/jpeg or image/png
	file_extension = "jpg" if image_type == "jpeg" else "png"

	# 构建 multipart/form-data 请求
	boundary = '------------------------boundary------------------------'
	body = []
	body.append(f'--{boundary}')
	body.append('Content-Disposition: form-data; name="media"; filename="image.%s"' % file_extension)
	body.append('Content-Type: application/octet-stream')
	body.append('')
	body.append(image_data)  # 直接使用图片二进制数据
	body.append(f'--{boundary}--')
	body.append('')
	
	body = b'\r\n'.join([part.encode('utf-8') if isinstance(part, str) else part for part in body])
	
	headers = {
		'Content-Type': f'multipart/form-data; boundary={boundary}',
		'Content-Length': str(len(body))
	}
	
	req = urllib.request.Request(url, data=body, headers=headers, method='POST')
	
	try:
		with urllib.request.urlopen(req) as response:
			result = json.loads(response.read().decode('utf-8', errors='ignore'))
			if 'media_id' in result:
				return result['media_id']
			else:
				print("上传图片失败: ", result)
				return u"err:上传图片失败," + str(result)
	except urllib.error.URLError as e:
		print(f"上传图片请求失败: {e}")
		return u"err:上传图片请求失败," + e

def wx_token() :
	global access_token
	if os.path.exists("/tmp/wx_token.txt") :
		with open("/tmp/wx_token.txt") as f :
			access_token = f.read()
		f.close()
	while True :
		get_token()
		sleep(1800)

def get_token(corpid="12345678901234567890",corpsecret="abcdefghijklmnopqrstuvwxyz"):
	global access_token
	gettoken_url = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=' + corpid + '&corpsecret=' + corpsecret
	try:
		token_file = urllib.request.urlopen(gettoken_url)
	except urllib.error.HTTPError as e:
		print("%s Get token error Message=%s, %s" % (ctime(), e.code, e.reason))
		sleep(10)
#			sys.exit()
	else :
		token_data = token_file.read().decode('utf-8', errors='ignore')
		token_json = json.loads(token_data)
		token_json.keys()
		access_token = token_json['access_token']
		print("%s Get token=%s" % (ctime(),access_token))
		with open("/tmp/wx_token.txt", 'w', encoding='utf-8') as f:
			f.write(access_token)
		f.close()
		

def run_server(host='0.0.0.0',port=8001):
	try :
		# 创建一个 socket 对象
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# 绑定主机和端口
		server_socket.bind((host, port))
		# 开始监听连接
		server_socket.listen(5)		# 最多允许5个连接排队
		print(f"Listening on {host}:{port}...")

		try:
			while True:
				client_connection, client_address = server_socket.accept()
				print(f"Connection from {client_address}")
				handle_request(client_connection)
		except KeyboardInterrupt:
			print("Shutting down server...")
		finally:
			server_socket.close()
	except Exception as e :
		print('HTTPD服务器监听失败：%s' % e)


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
				print("%s : %s is not alive. Restarting..." % (ctime(),name))
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
