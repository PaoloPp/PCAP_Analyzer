from scapy.all import *
import sys
import os
import constants as c
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def main():
    print("Hello World!")
    print("Pcap directory: " + c.PCAP_DIR)
    print("Scapy Version: " + str(scapy.__version__))
    print("Python Version: " + str(sys.version))
    extract_pcap("28_06_1000-1330.pcap")

#def send_email():
#    sender_email = 'paolopalmiero.p@gmail.com'
#    receiver_email = 'paolopalmiero.p@gmail.com'
#    subject = 'Extraction complete'
#    body = 'Congratulations! The extraction process has been completed successfully.'
#    
#    # Create the email message
#    msg = MIMEMultipart()
#    msg['From'] = sender_email
#    msg['To'] = receiver_email
#    msg['Subject'] = subject
#    msg.attach(MIMEText(body, 'plain'))
#    
#    # SMTP server configuration
#    smtp_server = 'smtp.gmail.com'
#    smtp_port = 587
#    smtp_user = 'your_email@example.com'
#    smtp_password = 'your_password'
#    
#    try:
#        # Create a secure connection with the server
#        server = smtplib.SMTP(smtp_server, smtp_port)
#        server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
#    
#        # Log in to the email account
#        server.login(smtp_user, smtp_password)
#    
#        # Send the email
#        server.send_message(msg)
#    
#        print('Email sent successfully.')
#    
#    except Exception as e:
#        print(f'Error: {e}')
#    
#    finally:
#        # Terminate the SMTP session and close the connection
#        server.quit()


def extract_pcap(file_name):    
    start = time.process_time()

    for i in range(1, 256): #21
            current_ip = c.IP_PREFIX + str(i)
            filtered_pkts = []

            try:
                current_cap = open_pcap(file_name)
            except NameError:
                print("Error: current_cap is not defined.")
                
            print("Time taken to open PCAP file: " + str(time.process_time() - start))
            print("Extracting IP: " + c.IP_PREFIX + str(i))

            if not os.path.isdir(c.PCAP_DIR + current_ip):
                os.mkdir(c.PCAP_DIR + current_ip)
            else:
                print("Directory already exists.")

            write_file = PcapWriter(c.PCAP_DIR + current_ip + "/" + file_name + "_" + current_ip + ".pcap", append=True)

            for packet in current_cap:
                if packet.haslayer(IP):
                    if packet[IP].src == current_ip or packet[IP].dst == current_ip:
                        print(packet.summary())
                        filtered_pkts.append(packet)
            write_file.write(packet)
    
#
#        wrpcap(c.PCAP_DIR + current_ip +
#               "/29_06_1330-1830" + "_" + current_ip + ".pcap",
#               filtered, append=True)


def open_pcap(name):
    print("Opening PCAP file: " + name)
    cap = PcapReader(c.PCAP_DIR + name)
    return cap


if __name__ == "__main__":
    main()
