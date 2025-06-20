import threading
from scapy.all import sniff
import logging
import os

class PacketSniffer(threading.Thread):
    def __init__(self, interface=None, packet_callback=None, logger=None):
        super().__init__()
        self.interface = interface
        self.packet_callback = packet_callback
        self.stop_sniffing = threading.Event()
        self.logger = logger or logging.getLogger(__name__)

    def run(self):
        try:
            self.logger.info(f"Attempting to start sniffer on interface {self.interface or 'default'}")
            sniff(iface=self.interface, prn=self.process_packet, stop_filter=self.should_stop)
        except PermissionError:
            self.logger.error("Permission denied to capture packets. Please ensure capabilities are set correctly: sudo setcap 'cap_net_raw,cap_net_admin=eip' venv/bin/python")
        except Exception as e:
            self.logger.error(f"Error starting packet sniffer: {e}")

    def stop(self):
        self.stop_sniffing.set()

    def should_stop(self, packet):
        return self.stop_sniffing.is_set()

    def process_packet(self, packet):
        if self.packet_callback:
            self.packet_callback(packet)
        else:
            self.logger.debug(packet.summary())

if __name__ == '__main__':
    # Example usage:
    def my_packet_processor(packet):
        print(f"Processed: {packet.summary()}")

    sniffer = PacketSniffer(packet_callback=my_packet_processor)
    sniffer.start()
    try:
        sniffer.join()
    except KeyboardInterrupt:
        print("Stopping sniffer...")
        sniffer.stop()
        sniffer.join()
        print("Sniffer stopped.") 