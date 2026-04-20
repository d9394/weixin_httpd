#!/usr/bin/python3.8
# encoding: utf-8

import socket
import urllib.parse
import urllib.request
from time import sleep, ctime
import os
import threading
import json
import base64

# --- 配置区 ---
MAX_CONTENT_LENGTH = 10 * 1024 * 1024
UPLOAD_DIR = '/tmp/html/'
AGENT_ID = "1000003"
CORP_ID = "aaaaaa"     # 替换为你的 CorpID
CORP_SECRET = "bbbbbbbb"  # 替换为你的 Secret

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

access_token = ""

# --- 1. 企业微信 API 交互逻辑 ---

def get_token():
    """获取并缓存 Access Token"""
    global access_token
    url = f'https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORP_ID}&corpsecret={CORP_SECRET}'
    try:
        with urllib.request.urlopen(url, timeout=20) as f:
            data = json.loads(f.read().decode('utf-8'))
            if 'access_token' in data:
                access_token = data['access_token']
                with open("/tmp/wx_token.txt", 'w') as tf:
                    tf.write(access_token)
                print(f"{ctime()} Token updated: {access_token[:10]}...")
    except Exception as e:
        print(f"{ctime()} Get Token Error: {e}")

def upload_media(file_data, filename):
    """上传文件/媒体至企业微信，自动识别类型"""
    global access_token
    ext = filename.split('.')[-1].lower()
    # 微信要求：图片格式走 image，其他所有格式（pdf, doc, txt等）走 file
    media_type = "image" if ext in ['jpg', 'jpeg', 'png', 'gif'] else "file"
    
    url = f"https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type={media_type}"
    boundary = '----Boundary' + ctime().replace(' ','')
    
    body = [
        f'--{boundary}'.encode(),
        f'Content-Disposition: form-data; name="media"; filename="{filename}"'.encode(),
        b'Content-Type: application/octet-stream',
        b'',
        file_data,
        f'--{boundary}--'.encode(),
        b''
    ]
    payload = b'\r\n'.join(body)
    headers = {'Content-Type': f'multipart/form-data; boundary={boundary}', 'Content-Length': str(len(payload))}
    
    try:
        req = urllib.request.Request(url, data=payload, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=30) as res:
            ret = json.loads(res.read().decode('utf-8'))
            return ret.get('media_id'), media_type
    except Exception as e:
        print(f"Upload Error: {e}")
        return None, None

def senddata(user, content, file_data=None, filename="file.txt"):
    """发送消息的核心函数"""
    global access_token
    response_log = ""

    # 处理文件发送
    if file_data:
        media_id, m_type = upload_media(file_data, filename)
        if media_id:
            msg_vals = {
                "touser": user, "msgtype": m_type, "agentid": AGENT_ID,
                m_type: {"media_id": media_id}, "safe": 0
            }
            res = send_to_wx(msg_vals)
            response_log += f"File:{res.get('errmsg')} "
        else:
            response_log += "File:UploadFailed "

    # 处理文本发送
    if content.strip():
        # 兼容你原有的回车换行替换逻辑
        content = content.replace('\\\\r\\\\\n','').replace('\r\n','').replace('\\\\n','\n')
        msg_vals = {
            "touser": user, "msgtype": "text", "agentid": AGENT_ID,
            "text": {"content": content}, "safe": 0
        }
        res = send_to_wx(msg_vals)
        response_log += f"Text:{res.get('errmsg')}"
    
    return response_log

def send_to_wx(send_values):
    url = 'https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=' + access_token
    try:
        data = json.dumps(send_values, ensure_ascii=False).encode('utf-8')
        with urllib.request.urlopen(url, data, timeout=30) as res:
            return json.loads(res.read().decode('utf-8'))
    except Exception as e:
        return {"errmsg": str(e)}

# --- 2. 服务守听逻辑 (TCP/HTTP & UDP) ---

def handle_http_request(conn, addr):
    """TCP/HTTP 请求处理"""
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(1024)
            if not chunk: break
            data += chunk
        
        header_part, body = data.split(b"\r\n\r\n", 1)
        lines = header_part.decode("utf-8").split("\r\n")
        method, path, _ = lines[0].split()
        
        # 解析参数
        query = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        usr = query.get("usr", [""])[0]
        msg = query.get("msg", [""])[0]
        source = query.get("from", [""])[0]
        
        file_bytes, file_name = None, "upload.bin"
        
        if method == "POST":
            headers = {l.split(": ")[0].lower(): l.split(": ")[1] for l in lines if ": " in l}
            content_len = int(headers.get("content-length", 0))
            while len(body) < content_len:
                body += conn.recv(4096)
            
            if "multipart/form-data" in headers.get("content-type", ""):
                boundary = headers["content-type"].split("boundary=")[-1]
                # 借用你之前的解析逻辑，但确保返回 file_bytes
                from_data, file_bytes, file_name = handle_multipart_body(body, boundary)
                usr = from_data.get("usr", [usr])[0]
                msg = from_data.get("msg", [msg])[0]

        if usr and (msg or file_bytes):
            res_text = senddata(usr, f"{source or addr[0]}: {msg}", file_bytes, file_name)
        else:
            res_text = "Format: usr=xxx&msg=xxx"

        conn.sendall(f"HTTP/1.1 200 OK\r\n\r\n{res_text}".encode())
    finally:
        conn.close()

def handle_multipart_body(body, boundary):
    """解析 Multipart 数据"""
    parts = body.split(f"--{boundary}".encode())
    form, f_data, f_name = {}, None, "file.dat"
    for part in parts:
        if b"Content-Disposition" in part:
            h, c = part.split(b"\r\n\r\n", 1)
            h_str = h.decode("utf-8")
            if 'filename="' in h_str:
                f_name = h_str.split('filename="')[-1].split('"')[0]
                f_data = c.rstrip(b"\r\n--")
            elif 'name="' in h_str:
                name = h_str.split('name="')[-1].split('"')[0]
                form[name] = [c.decode("utf-8").strip()]
    return form, f_data, f_name

def udp_server(host='0.0.0.0', port=8001):
    """UDP 守听逻辑"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"UDP Server listening on {port}...")
    while True:
        data, addr = sock.recvfrom(65535)
        try:
            # 格式：usr=xxx&msg=xxx&filename=test.pdf&file=BASE64...
            query_str = data.decode("gb2312", errors='ignore')
            params = {k.lower(): v for k, v in [item.split('=') for item in query_str.split('&') if '=' in item]}
            
            usr = params.get('usr')
            msg = params.get('msg', '')
            f_name = params.get('filename', 'file.txt')
            f_bytes = base64.b64decode(params['file']) if 'file' in params else None
            
            if usr:
                senddata(usr, f"{params.get('from', addr[0])}: {msg}", f_bytes, f_name)
                sock.sendto(b"OK", addr)
        except Exception as e:
            print(f"UDP Error: {e}")

def tcp_server(host='0.0.0.0', port=8001):
    """TCP/HTTP 守听逻辑"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(10)
    print(f"TCP Server listening on {port}...")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_http_request, args=(conn, addr), daemon=True).start()

# --- 3. 线程管理与自修复 ---

thread_targets = {
    'token_manager': lambda: [get_token() or sleep(7000) for _ in iter(int, 1)],
    'tcp_http': tcp_server,
    'udp_worker': udp_server
}
threads = {}

def start_thread(name):
    t = threading.Thread(target=thread_targets[name], name=name, daemon=True)
    t.start()
    threads[name] = t
    print(f"{ctime()} Started thread: {name}")

def monitor_threads():
    while True:
        for name in thread_targets:
            if name not in threads or not threads[name].is_alive():
                print(f"{ctime()} Thread {name} is dead. Restarting...")
                start_thread(name)
        sleep(10)

if __name__ == '__main__':
    # 初始启动
    get_token() # 先获取一次token
    monitor_thread = threading.Thread(target=monitor_threads, daemon=True)
    monitor_thread.start()
    
    try:
        while True: sleep(1)
    except KeyboardInterrupt:
        print("Shutdown.")
