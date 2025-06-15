import json
import sys
import subprocess

# Usage: python3 extract_suspect_pcaps.py <alert_file> <pcap_file> <output_file>

def main():
    if len(sys.argv) != 4:
        print('Usage: python3 extract_suspect_pcaps.py <alert_file> <pcap_file> <output_file>')
        sys.exit(1)
    alert_file, pcap_file, output_file = sys.argv[1:4]
    pairs = set()
    with open(alert_file, 'r') as f:
        for line in f:
            try:
                alert = json.loads(line.replace("'", '"'))
                src_ip = alert['src_ap'].split(':')[0]
                dst_ip = alert['dst_ap'].split(':')[0]
                pairs.add((src_ip, dst_ip))
            except Exception:
                continue
    if not pairs:
        print('Aucune paire suspecte trouvée.')
        sys.exit(0)
    filters = [f'(src {src} and dst {dst})' for src, dst in pairs]
    tcpdump_filter = ' or '.join(filters)
    cmd = [
        'tcpdump', '-r', pcap_file, tcpdump_filter, '-w', output_file
    ]
    print('Commande tcpdump générée:', ' '.join(cmd))
    subprocess.run(cmd, check=True)

if __name__ == '__main__':
    main() 