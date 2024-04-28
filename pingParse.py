import pyshark
import sys
import argparse
import logging

def extract_icmp_data(pcap_file, output_file=None):
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter='icmp')
        seen_lines = set()  # Create a set to store unique lines
        unique_count = 0  # Counter for unique lines
        output_lines = []  # List to store output lines
        output_lines.append("--- Unique ICMP Data Lines ---")  # Header
        for packet in cap:
            try:
                # Extracting ICMP data payload, which is in hex
                icmp_data_hex = packet.icmp.data
                # Convert hex to bytes then decode to ASCII
                icmp_data_ascii = bytes.fromhex(icmp_data_hex).decode('ascii', errors='ignore')
                # Split multiline text into individual lines
                lines = icmp_data_ascii.split('\n')
                for line in lines:
                    if line.strip() not in seen_lines:
                        unique_count += 1
                        output_line = f"{unique_count}. {line.strip()}"
                        output_lines.append(output_line)
                        seen_lines.add(line.strip())  # Add the line to the set
            except AttributeError:
                # In case the packet doesn't have ICMP data payload
                continue
        output_lines.append(f"--- End of Unique ICMP Data ({unique_count} lines) ---")  # Footer
        
        if output_file:
            with open(output_file, 'w') as file:
                file.write('\n'.join(output_lines))
                logging.info(f"Extracted ICMP data saved to '{output_file}'")
        else:
            for line in output_lines:
                print(line)
    except Exception as e:
        logging.error(f"An error occurred while processing the pcap file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Extract ICMP data from a pcap file")
    parser.add_argument("pcap_file", help="Path to the pcap file")
    parser.add_argument("--output-file", "-o", help="Path to save the extracted ICMP data (optional)")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S", filename="icmp_parser.log", filemode="w")

    try:
        extract_icmp_data(args.pcap_file, output_file=args.output_file)
    except FileNotFoundError:
        logging.error("The specified pcap file does not exist.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
