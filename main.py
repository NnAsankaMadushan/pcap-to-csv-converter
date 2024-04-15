import pyshark
import csv

def pcap_to_csv(pcap_file, csv_file):

    cap = pyshark.FileCapture(pcap_file)

    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['Time', 'Source', 'Destination', 'Protocol', 'Length'])

        for packet in cap:
            
            time = packet.sniff_time
            source = packet.ip.src if 'ip' in packet else ''
            destination = packet.ip.dst if 'ip' in packet else ''
            protocol = packet.transport_layer if 'tcp' in packet else ''
            length = packet.length

            writer.writerow([time, source, destination, protocol, length])

if __name__ == '__main__':
    pcap_to_csv('Test.pcap', 'output.csv')
