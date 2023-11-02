import xml.etree.ElementTree as ET

def get_plugin_info(nessus_file):
    """Parse the Nessus XML file and return a dictionary where keys are IP addresses, and values are lists of plugin information."""
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    results = {}  # Dictionary to store results with IP addresses as keys and lists of plugin information as values

    for report in root.findall("./Report"):
        for host in report.findall("./ReportHost"):
            host_ip = host.find("HostProperties/tag[@name='host-ip']").text

            for item in host.findall("./ReportItem"):
                severity = item.find("risk_factor").text
                if severity in ["Critical", "High", "Medium", "Low"]:
                    plugin_name = item.get("pluginName")
                    plugin_output = item.find("plugin_output")
                    port = item.get("port")

                    info = f"[+] Plugin Name: {plugin_name}\n"
                    if plugin_output is not None and port is not None:
                        info += f"[+] Port Number: {port}\n[+] Output: {plugin_output.text}\n"
                    elif port is not None:
                        info += f"[+] Port Number: {port}\n"
                    elif plugin_output is not None:
                        info += f"[+] Output: {plugin_output.text}"
                    else:
                        info += "No Plugin Output or Port Information available."

                    if host_ip in results:
                        results[host_ip].append(info)
                    else:
                        results[host_ip] = [info]

    return results

if __name__ == '__main__':
    nessus_file = input("Enter the path to your Nessus file: ")
    plugin_info = get_plugin_info(nessus_file)

    for host_ip, vulnerabilities in plugin_info.items():
        print("\n============================================================================\n")
        print(f"IP Address: {host_ip}")
        print("Vulnerabilities affecting this IP:\n")
        for vulnerability in vulnerabilities:
            print(vulnerability)
            
