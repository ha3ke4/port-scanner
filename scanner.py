import nmap

scanner = nmap.PortScanner()

print("welcome to the simple automatation tool")
print("-------------------------------------------")

ip_addr = input("entre the ip adderess you want to scan >>")
print("your entered ip address is :" , ip_addr)
type(ip_addr)

resp = input("""\nentre the type of scan you want
                1)SYN ACK Scan
                2)UDP scan
                3)xmas scan\n""")
print("you have selected the scan" , resp)

if resp == '1':
    print("nmap Version" , scanner.nmap_version())
    scanner.scan(ip_addr , '1-1024' , '-v -sS')
    print(scanner.scaninfo())
    print("IP status:" , scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:" , scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("nmap Version" , scanner.nmap_version())
    scanner.scan(ip_addr , '1-1024' , '-v -sU')
    print(scanner.scaninfo())
    print("IP status:" , scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:" , scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("nmap Version" , scanner.nmap_version())
    scanner.scan(ip_addr , '1-1024' , '-v -sX')
    print(scanner.scaninfo())
    print("IP status:" , scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:" , scanner[ip_addr]['tcp'].keys())
else:
    print("you have not selected any option")
    

