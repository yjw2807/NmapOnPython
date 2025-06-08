import nmap

# Define a class to store host information as an object
class HostInfo:
    def __init__(self, hostname, ip, open_ports, os_info, mac_address):
        self.HostName = hostname
        self.Ip = ip
        self.OpenPorts = open_ports
        self.Os = os_info
        self.MacAddress = mac_address

    # Getter for HostName
    @property
    def HostName(self):
        return self._hostname

    # Setter for HostName
    @HostName.setter
    def HostName(self, value):
        if not isinstance(value, str):
            raise ValueError("HostName must be a string")
        self._hostname = value

    # Getter for Ip
    @property
    def Ip(self):
        return self._ip

    # Setter for Ip
    @Ip.setter
    def Ip(self, value):
        if not isinstance(value, str):
            raise ValueError("Ip must be a string")
        self._ip = value

    # Getter for OpenPorts
    @property
    def OpenPorts(self):
        return self._open_ports

    # Setter for OpenPorts
    @OpenPorts.setter
    def OpenPorts(self, value):
        if not isinstance(value, list):
            raise ValueError("OpenPorts must be a list")
        self._open_ports = value

    # Getter for Os
    @property
    def Os(self):
        return self._os

    # Setter for Os
    @Os.setter
    def Os(self, value):
        if not isinstance(value, str):
            raise ValueError("Os must be a string")
        self._os = value

    # Getter for MacAddress
    @property
    def MacAddress(self):
        return self._mac_address

    # Setter for MacAddress
    @MacAddress.setter
    def MacAddress(self, value):
        if not isinstance(value, str):
            raise ValueError("MacAddress must be a string")
        self._mac_address = value

    def __str__(self):
        return f"IP: {self.Ip}, Hostname: {self.HostName}, OS: {self.Os}, MAC Address: {self.MacAddress}, Open Ports: {self.OpenPorts}"

# Initialize a list to store HostInfo objects
host_info_list = []

try:
    # Initialize the Nmap PortScanner
    nm = nmap.PortScanner()
    #IP ADDRESS NEED TO WRITE HERE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    ip_add = "192.168.0.100"  
    nm.scan(ip_add, arguments="-p- -sV -O -R")  # -p- scans all ports, -sV enables service detection, -O enables OS detection, -R enables DNS resolution
    
    for host in nm.all_hosts():
        # Get hostname (reverse DNS lookup result)
        hostname = nm[host].hostname() if nm[host].hostname() else "Unknown"
        
        # Get OS details
        os_info = nm[host].get('osmatch', [{}])[0].get('name', 'Unknown') if nm[host].get('osmatch') else 'Unknown'
        
        # Get MAC address and vendor (if available)
        mac_address = "Unknown"
        if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
            mac_address = nm[host]['addresses']['mac']
            if 'vendor' in nm[host] and nm[host]['vendor']:
                vendor = nm[host]['vendor'].get(mac_address, 'Unknown Vendor')
                mac_address = f"{mac_address} ({vendor})"
        
        # Get open ports
        if 'tcp' in nm[host]:
            open_ports = [port for port in nm[host]['tcp'].keys() if nm[host]['tcp'][port]['state'] == 'open']
        else:
            open_ports = []
        
        # Create a HostInfo object and add it to the list
        host_obj = HostInfo(hostname=hostname, ip=host, open_ports=open_ports, os_info=os_info, mac_address=mac_address)
        host_info_list.append(host_obj)
    
    # Print the host information
    if host_info_list:
        print("Host information (IP, Hostname, OS, MAC Address, Open Ports):")
        for host_obj in host_info_list:
            print(host_obj)
    else:
        print("No hosts found.")

except nmap.PortScannerError as e:
    print(f"Error: {e}. Check the Nmap executable path.")
except Exception as e:
    print(f"Unexpected error: {e}")
