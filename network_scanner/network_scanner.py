from scapy.all import *
import argparse
import netaddr
import time

def usage():
    print("[*] Usage: ")
    print("sudo python3 network_scanner.py <arguments>")
    print("-c (--cidr):              specify the CIDR (e. g. 192.168.0.1/24)")
    print("-w (--wait)[optional]:    specify the wait time until a timeout")
    print("-t (--ttl)[optional]:     specify the TTL (time to live)")

def network_scan(cidr : str, wait : float, timetolive : int):
    delay = 0.75
    print("<< network_scanner.py by rdbo >>")
    time.sleep(delay)
    ip_list = valid_ip_list = []
    try:
        ip_list = [str(ip) for ip in netaddr.IPNetwork(cidr)]
    except:
        print(f"[!] Unable to parse IP address range of {cidr}")
        exit(0)
    print(f"[*] Target: {cidr.split('/')[0]}")
    time.sleep(delay)
    print(f"[*] Scan range: {ip_list[0]} - {ip_list[-1]}")
    time.sleep(delay)
    print(f"[*] Time to Live (TTL): {timetolive}")
    time.sleep(delay)
    print(f"[*] Timeout: {wait}")
    print("--------------------")
    time.sleep(0.5)
    bcounter = time.perf_counter()
    for ip in ip_list:
        try:
            print(f"[*] Scanning {ip}...")
            packet = IP(dst=ip, ttl=timetolive)/ICMP()
            reply = sr1(packet, timeout=wait, verbose=False)
            if(reply is not None):
                valid_ip_list.append(ip)
        except KeyboardInterrupt:
            print()
            print(f"[!] Interrupted")
            break
        except:
            print(f"[!] Exception during scan")

    ecounter = time.perf_counter()
    scan_time = round(ecounter - bcounter, 2)
    print("--------------------")
    print(f"[*] Scan finished in {scan_time} second(s)")
    print(f"[*] Valid IP(s): {['%s' %ip for ip in valid_ip_list]}")

if(__name__ == "__main__"):
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cidr", type=str, action="store", dest="cidr", help="cidr", default="")
    parser.add_argument("-w", "--wait", type=float, action="store", dest="wait", help="timeout delay", default="1")
    parser.add_argument("-t", "--ttl", type=int, action="store", dest="ttl", help="timetolive", default="64")
    args = parser.parse_args()
    cidr = ""
    wait = 1
    ttl = 64
    try:
        cidr = args.cidr
        wait = args.wait
        ttl = args.ttl
        if (len(cidr) < 1 or wait < 0 or not wait or ttl <= 0):
            usage()
            exit(0)
            
    except SystemExit:
        exit(0)
    except:
        print("[!] Unable to parse arguments")
        usage()
        exit(0)
    
    network_scan(cidr, wait, ttl)
