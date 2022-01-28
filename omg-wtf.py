import boto3
import boto.ec2
from botocore.exceptions import ClientError
from boto3 import resource, client
from boto3 import ec2
import declxml as xml
import xml.etree.ElementTree as ET
from xml.dom import minidom
from pandevice import panorama
from pandevice import firewall
from pandevice import network
from pandevice import device
from pandevice import policies
import sys
import pan.xapi


#Tunnel 1 Variables
tunnelinsidecidr1 = '169.254.100.12/30'
psk1 = '1234567890'

#Tunnel 2 Variables
tunnelinsidecidr2 = '169.254.100.16/30'
psk2 = '1234567890'

device_group = "DG-TECHNOLOGY-MFD612"

template = 'T-DEVICE-AWS-TRANSIT'

aws_pan = panorama.Panorama('18.214.36.168', 'admin', '5yru5H(W')

transit_asn = 65472
vpc_asn = 64512

tunnel_int1 = "tunnel.107"
tunnel_int2 = "tunnel.108"

ec2 = boto3.resource('ec2')

xml_doc = []

operation_result = ec2.meta.client.describe_vpn_gateways()

vgw = operation_result['VpnGateways'][0]

count = len(vgw['Tags'])

gw_list = []


security_zone = []

for tags in range(0,count):
        tag = vgw['Tags'][tags]
        #print(tag)
        palo_transit = tag['Key']
        #print(palo_transit)
        palo_true = tag['Value']
        #print(palo_true)
        if palo_transit == "transit:palo" and palo_true == "true":
                gw_id = vgw['VpnGatewayId']
                #print(gw_id)
                gw_list.append(gw_id)
                #print(vgw)
                name =[]
                for tags in range(0,count):
                        #print(tags)
                        tag = vgw['Tags'][tags]
                        environment = tag['Key']
                        if environment == "Name":
                               name.append(tag['Value'])
                print(name)
                env = name[0].split('-VGW')
                #print(security_zone[0])
                gateway_id = gw_id
                security_zone.append(env[0])



                cgw = ec2.meta.client.create_customer_gateway(BgpAsn=transit_asn, \
                        PublicIp='18.215.13.215', \
                        Type='ipsec.1', \
                        DryRun=False)


                cgw_id = cgw['CustomerGateway']['CustomerGatewayId']


                response = ec2.meta.client.create_vpn_connection(
                CustomerGatewayId=cgw_id,
                Type='ipsec.1',
                VpnGatewayId= gateway_id,
                Options={
                        'StaticRoutesOnly': False,
                        'TunnelOptions': [
                        {
                                'TunnelInsideCidr': tunnelinsidecidr2,
                                'PreSharedKey': psk2
                        },
                        {
                                'TunnelInsideCidr': tunnelinsidecidr1,
                                'PreSharedKey': psk1
                        },
                        ],
                },
                )

                vpn_id = response['VpnConnection']['VpnConnectionId']

                xml_file = response['VpnConnection']['CustomerGatewayConfiguration']
                xml_doc.append(xml_file)

                response = ec2.meta.client.create_tags(
                        DryRun=False,
                        Resources=[
                                gateway_id,
                        ],
                        Tags=[
                                {
                                'Key': 'transit:palo',
                                'Value': 'configured'
                                },
                        ]
                        )

                vpn_name = '{0}{1}'.format(env[0] , "-LE-TRANSIT-VPN")        

                response = ec2.meta.client.create_tags(
                        DryRun=False,
                        Resources=[
                                vpn_id
                        ],
                        Tags=[
                                {
                                'Key': 'Name',
                                'Value': vpn_name
                                },
                        ]
                        )

                cgw_name = '{0}{1}'.format(env[0] , "-LE-TRANSIT-CGW")        

                response = ec2.meta.client.create_tags(
                        DryRun=False,
                        Resources=[
                                cgw_id,
                        ],
                        Tags=[
                                {
                                'Key': 'Name',
                                'Value': cgw_name
                                },
                        ]
                        ) 

#print(xml_doc)

xml_file = xml_doc[0]
#print(xml_file)

tree = ET.fromstring(xml_file)
t = []  #aws inside tunnel cidr
w = []  #customer insdie tunnel cidr
x = []  #Customer outside tunnel IP
y = []  #AWS outside tunnel IP
z = []  #PSK for VPN tunnels

for item in tree.findall('./ipsec_tunnel/customer_gateway/tunnel_outside_address'):
    for child in item:
        if child.tag == 'ip_address':
            ip_add = child.text
            x.append(ip_add)

print(x)

for item in tree.findall('./ipsec_tunnel/vpn_gateway/tunnel_outside_address'):
    for child in item:
        if child.tag == 'ip_address':
            ip_add = child.text
            y.append(ip_add)

print(y)

for item in tree.findall('./ipsec_tunnel/ike'):
    for child in item:
        if child.tag == 'pre_shared_key':
            psk = child.text
            z.append(psk)

print(z)
   
for item in tree.findall('./ipsec_tunnel/customer_gateway/tunnel_inside_address'):
    for child in item:
        if child.tag == 'ip_address':
            ip_add = child.text
            w.append(ip_add)

print(w)

for item in tree.findall('./ipsec_tunnel/vpn_gateway/tunnel_inside_address'):
    for child in item:
        if child.tag == 'ip_address':
            ip_add = child.text
            t.append(ip_add)

print(t)


#Start Panorama Configuration

bgp_neighbor = t[0].split('/')
bgp_nei_ip = bgp_neighbor[0]



template = panorama.Template(template)
aws_pan.add(template)
#print(template)


vpn_tunnel_ip = '{0}{1}'.format(w[0], '/30')

# creates AWS tunnel 1
tunnel_int = network.TunnelInterface(tunnel_int1, \
        ip = vpn_tunnel_ip, \
        ipv6_enabled = False)

template.add(tunnel_int)
tunnel_int.create()

vpn_tunnel_ip = '{0}{1}'.format(w[1], '/30')
# creates AWS tunnel 2
tunnel_int = network.TunnelInterface(tunnel_int2, \
        ip = vpn_tunnel_ip, \
        ipv6_enabled = False)

template.add(tunnel_int)
tunnel_int.create()

#Create Security zones

#Creates trust_fwh_vpn secuirty zone
vpn_zone = network.Zone(security_zone[0], \
        mode = "layer3", \
        interface = [tunnel_int1, tunnel_int2])

template.add(vpn_zone)
vpn_zone.create()

#Creates master routing instance which will contain VPN, trust, and management
vr_master = network.VirtualRouter("vr_master", \
        interface = [tunnel_int1, tunnel_int2])

template.add(vr_master)
vr_master.create()


#Configures VPN
#Will build out IKE crypto profile in defined template
ike_crypto = network.IkeCryptoProfile("ICP-DH_G2-AUTH_SHA256-EN_AES256", \
        dh_group = "group2", \
        authentication = "sha1", \
        encryption = "aes-256-cbc", \
        lifetime_hours = "8")

template.add(ike_crypto)
ike_crypto.create()

#Will build out IPSEC crypto profile in defined template
ipsec_crypto = network.IpsecCryptoProfile('IPCP-EN-AES256_AU-AES256_DH_G2', \
        esp_encryption = "aes-256-cbc", \
        esp_authentication = "sha256", \
        dh_group = "group5", \
        lifetime_seconds = "3600")

template.add(ipsec_crypto)
ipsec_crypto.create()

remote_vpn_ip = y[0]
untrust_cidr = x[0]
pre_shared_key = z[0] 

#Will AWS VPN 1 Gaewtway
gw1_name = '{0}{1}{2}'.format("IKE-GATE-", security_zone[0], "-1")
ike_gw = network.IkeGateway(gw1_name, \
        version = "ikev2", \
        peer_ip_type = "ip", \
        peer_ip_value = remote_vpn_ip, \
        interface = "ethernet1/1", \
        local_ip_address = untrust_cidr, \
        auth_type = "pre-shared-key", \
        pre_shared_key = pre_shared_key, \
        local_id_type = "ipaddr", \
        local_id_value = untrust_cidr, \
        peer_id_type = "ipaddr", \
        peer_id_value = remote_vpn_ip, \
        ikev2_crypto_profile = "ICP-DH_G2-AUTH_SHA256-EN_AES256")

template.add(ike_gw)
ike_gw.create()        

# Create IPSec tunnel
tun1_name = '{0}{1}{2}'.format("IPSEC-TUN-", security_zone[0], "-1")
ipsec_tun = network.IpsecTunnel(tun1_name, \
        tunnel_interface = tunnel_int1, \
        anti_replay = True, \
        type = "auto-key", \
        ak_ike_gateway = gw1_name, \
        ak_ipsec_crypto_profile = 'IPCP-EN-AES256_AU-AES256_DH_G2', \
        enable_tunnel_monitor = True, \
        tunnel_monitor_dest_ip = bgp_nei_ip, \
        tunnel_monitor_profile = "default")

template.add(ipsec_tun)
ipsec_tun.create()

remote_vpn_ip = y[1]
untrust_cidr = x[1]
pre_shared_key = z[1]

#Will AWS VPN 2 Gaewtway
gw2_name = '{0}{1}{2}'.format("IKE-GATE-", security_zone[0], "-2")
ike_gw = network.IkeGateway(gw2_name, \
        version = "ikev2", \
        peer_ip_type = "ip", \
        peer_ip_value = remote_vpn_ip, \
        interface = "ethernet1/1", \
        local_ip_address = untrust_cidr, \
        auth_type = "pre-shared-key", \
        pre_shared_key = pre_shared_key, \
        local_id_type = "ipaddr", \
        local_id_value = untrust_cidr, \
        peer_id_type = "ipaddr", \
        peer_id_value = remote_vpn_ip, \
        ikev2_crypto_profile = "ICP-DH_G2-AUTH_SHA256-EN_AES256")

template.add(ike_gw)
ike_gw.create() 

# Create IPSec tunnel
tun2_name = '{0}{1}{2}'.format("IPSEC-TUN-", security_zone[0], "-2")
ipsec_tun = network.IpsecTunnel(tun2_name, \
        tunnel_interface = tunnel_int2, \
        anti_replay = True, \
        type = "auto-key", \
        ak_ike_gateway = gw2_name, \
        ak_ipsec_crypto_profile = 'IPCP-EN-AES256_AU-AES256_DH_G2', \
        enable_tunnel_monitor = True, \
        tunnel_monitor_dest_ip = bgp_nei_ip, \
        tunnel_monitor_profile = "default")

template.add(ipsec_tun)
ipsec_tun.create()




devicegroup = panorama.DeviceGroup(device_group)

#Create SSH policy for Guest Wireless
devicegroup = panorama.DeviceGroup(device_group)
aws_pan.add(devicegroup)

postrulebase = policies.PostRulebase()
devicegroup.add(postrulebase)


sec_rule_name = '{0}{1}{2}'.format("R_ALLOW_", security_zone[0], "_BGP")
sec_rule = policies.SecurityRule(sec_rule_name, \
                fromzone = [security_zone[0]], \
                tozone = [security_zone[0]], \
                source = [t[0], t[1], w[0], w[1]], \
                destination = [t[0], t[1], w[0], w[1]], \
                application = "bgp", \
                service = "application-default", \
                action = "allow", \
                log_end = True, \
                )

postrulebase.add(sec_rule)
sec_rule.create()

#Start VPN configuration

local_address1 =  '{0}{1}'.format(w[0], "/30")
local_address2 =  '{0}{1}'.format(w[1], "/30")
peer_address1 =  '{0}'.format(t[0])
peer_address2 =  '{0}'.format(t[1])


peer1_bgp_xml = '{0}{1}{2}{3}{4}{5}{6}{7}{8}'.format("<peer-address><ip>", peer_address1, "</ip></peer-address><local-address><ip>", local_address1, "</ip><interface>", tunnel_int1, "</interface></local-address><peer-as>", vpc_asn, "</peer-as>")
xpath1 = '{0}{1}{2}'.format("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='T-DEVICE-AWS-TRANSIT']/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='vr_master']/protocol/bgp/peer-group/entry[@name='AWS-Neghbor']/peer/entry[@name='", peer_address1, "']")


xapi = pan.xapi.PanXapi(api_username = "admin", \
        api_password = "5yru5H(W", \
        hostname='18.214.36.168')


xapi.set(xpath = xpath1, \
                element = peer1_bgp_xml)


peer2_bgp_xml = '{0}{1}{2}{3}{4}{5}{6}{7}{8}'.format("<peer-address><ip>", peer_address2, "</ip></peer-address><local-address><ip>", local_address2, "</ip><interface>", tunnel_int2, "</interface></local-address><peer-as>", vpc_asn, "</peer-as>")
xpath2 = '{0}{1}{2}'.format("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='T-DEVICE-AWS-TRANSIT']/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='vr_master']/protocol/bgp/peer-group/entry[@name='AWS-Neghbor']/peer/entry[@name='", peer_address2, "']")

xapi.set(xpath = xpath2, \
                element = peer2_bgp_xml)


print(name)



