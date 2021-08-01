
import nmap3

ipAddress = '192.168.1.1'
nmap = nmap3.Nmap()
results = nmap.scan_top_ports(ipAddress)



print(results[ipAddress]['ports'])

for port in range(0,len(results[ipAddress]['ports'])):
    parsedReturn = {'ports' : { 'protocol': results[ipAddress]['ports'][port]['protocol'], 'portid': results[ipAddress]['ports'][port]['portid'], 'state': results[ipAddress]['ports'][port]['state'], 'reason': results[ipAddress]['ports'][port]['reason']}}
    print(parsedReturn)

