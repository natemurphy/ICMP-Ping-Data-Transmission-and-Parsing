# ICMP-Ping-Data-Transmission-and-Parsing

## Summary

This repository contains two Python scripts for transmitting data through ICMP ping packets and parsing the captured data from a pcap file. The `pingGen.py` script generates ICMP ping packets containing data from a specified file, while the `pingParse.py` script extracts and displays the ICMP data from a pcap file generated by the `pingGen.py` script.

## Setup Instructions

### 1.) Clone this repository to your local machine:
```
bash
git clone https://github.com/natemurphy/ICMP-Ping-Data-Transmission-and-Parsing.git
```
### 2.) Navigate to the repository directory:

```
cd ICMP-Ping-Data-Transmission-and-Parsing
```

### 3.) Requirments:
This project is designed to be ran on Linux.
Make sure Python3 is installed.

```
pip install scapy pyshark
```
Also make sure `tshark` is installed by doing `sudo apt-get install tshark`
Scapy requires sudo to run.

## Usage Instructions

### 1. Generating ICMP Ping Packets (pingGen.py)

To transmit data through ICMP ping packets, use the `pingGen.py` script with the following command:

```
sudo python3 pingGen.py receiver-IP-Address targetFile.txt
```

Replace `receiver-IP-Address` with the IP address of the receiver machine and `targetFile.txt` with the path to the file containing the data to be transmitted.

### 2. Parsing Captured Data (pingParse.py)

To parse the captured ICMP data from a pcap file, use the pingParse.py script with the following command:

```
sudo python3 pingParse.py pingGenOutput.pcap
```

Replace `pingGenOutput.pcap` with the path to the pcap file generated by the `pingGen.py` script.

#### Optional Flag for Output File

You can specify an output file to save the extracted ICMP data using the `--output-file` or `-o` flag:

```
sudo python3 pingParse.py pingGenOutput.pcap --output-file output.txt
```

Replace `output.txt` with the desired filename and path for the output file.

# Setting Up Wireshark for Packet Capture

## Installation

To install Wireshark on Linux, open a terminal and execute the following command:

```
sudo apt-get install wireshark
```

## Usage Instructions

Launch Wireshark in the terminal with superuser privileges. This opens the Wireshark GUI.

Capture ICMP Packets:

In Wireshark, select the network interface you want to capture packets from.
Apply a filter to display only ICMP traffic.
Start capturing packets by clicking the start button.

Once you have sent the ping packets using `pingGen.py`, stop the capture and save the file as a `.pcap`. This file will be the input for `pingParser.py`.
