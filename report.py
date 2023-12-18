import json
import sys
from texttable import Texttable

def load_results(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def generate_report(results):
    table = Texttable()
    table.set_cols_dtype(['t', 't', 't', 't', 't', 't'])
    table.set_cols_align(['l', 'l', 'l', 'l', 'l', 'l'])

    # Add header
    table.add_row(['Domain', 'Scan Time', 'IPv4 Addresses', 'IPv6 Addresses', 'HTTP Server', 'Insecure HTTP'])

    for domain, data in results.items():
        scan_time = data.get('scan_time', '')
        ipv4_addresses = ', '.join(data.get('ipv4_addresses', []))
        ipv6_addresses = ', '.join(data.get('ipv6_addresses', []))
        http_server = data.get('http_server', '')
        insecure_http = data.get('insecure_http', '')

        table.add_row([domain, scan_time, ipv4_addresses, ipv6_addresses, http_server, insecure_http])

    return table.draw()

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 report.py [input_file.json] [output_file.txt]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    results = load_results(input_file)
    report_text = generate_report(results)

    with open(output_file, 'w') as f:
        f.write(report_text)

if __name__ == "__main__":
    main()
