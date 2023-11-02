import xml.etree.ElementTree as ET
from openpyxl import Workbook

def create_excel_report(nessus_file, output_file):
    """Parse the Nessus XML file and create an Excel report with IP addresses and vulnerabilities in a table."""
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    workbook = Workbook()
    worksheet = workbook.active

    # Add headers to the worksheet
    worksheet.append(["IP Address","Port", "Plugin Name", "Output"])

    for report in root.findall("./Report"):
        for host in report.findall("./ReportHost"):
            host_ip = host.find("HostProperties/tag[@name='host-ip']").text

            for item in host.findall("./ReportItem"):
                severity = item.find("risk_factor").text
                if severity in ["Critical", "High", "Medium", "Low"]:
                    plugin_name = item.get("pluginName")
                    plugin_output = item.find("plugin_output")
                    port = item.get("port")

                    # Split the plugin name at the first ':'
                    plugin_name_parts = plugin_name.split(":", 1)
                    if len(plugin_name_parts) > 1:
                        # Take everything after the ':' character
                        plugin_name = plugin_name_parts[1].strip()

                    output_text = plugin_output.text if plugin_output is not None else "No Plugin Output available"

                    # Append the information to the worksheet
                    worksheet.append([host_ip, port, plugin_name, output_text])

    workbook.save(output_file)
    print(f"Excel report saved to {output_file}")

if __name__ == '__main__':
    nessus_file = input("Enter the path to your Nessus file: ")
    output_file = input("Enter the output Excel file name (e.g., report.xlsx): ")
    create_excel_report(nessus_file, output_file)
