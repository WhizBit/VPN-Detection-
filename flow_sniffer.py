import scapy.all as scapy
import time
import numpy as np
import threading
import queue
from Interface_name import connected_interfaces

INTERFACE_NAME = connected_interfaces  # Change this to your interface
FLOW_TIMEOUT_SECONDS = 5     # How long to wait before expiring a flow

class FlowSniffer:
    """
    This class runs the Scapy sniffer and flow expiration logic
    in separate threads, feeding completed flow stats into a queue.
    """
    def __init__(self, output_queue, interface=INTERFACE_NAME, timeout=FLOW_TIMEOUT_SECONDS):
        self.output_queue = output_queue
        self.interface = interface
        self.timeout = timeout
        
        self.flows = {}
        self.lock = threading.Lock()
        self.running = False
        
        self.sniffer_thread = None
        self.expire_thread = None

    def process_packet(self, pkt):
        """
        Scapy's packet processing callback. Updates the shared 'flows' dict.
        """
        if not self.running:
            return
            
        try:
            if not pkt.haslayer("IP"):
                return

            proto_num = pkt["IP"].proto
            ip_src_orig = pkt["IP"].src
            ip_dst_orig = pkt["IP"].dst
            
            if pkt.haslayer("TCP"):
                proto = "TCP"
                src_port = pkt["TCP"].sport
                dst_port = pkt["TCP"].dport
            elif pkt.haslayer("UDP"):
                proto = "UDP"
                src_port = pkt["UDP"].sport
                dst_port = pkt["UDP"].dport
            elif pkt.haslayer("ICMP"):
                proto = "ICMP"
                src_port, dst_port = 0, 0
            else:
                proto = "Other"
                src_port, dst_port = 0, 0
                
            if ip_src_orig > ip_dst_orig:
                flow_src_ip, flow_dst_ip = ip_dst_orig, ip_src_orig
                flow_src_port, flow_dst_port = dst_port, src_port
            else:
                flow_src_ip, flow_dst_ip = ip_src_orig, ip_dst_orig
                flow_src_port, flow_dst_port = src_port, dst_port
                
            flow_key = f"{flow_src_ip}-{flow_dst_ip}-{flow_src_port}-{flow_dst_port}-{proto}"
            
            pkt_time = pkt.time
            pkt_len = len(pkt["IP"])
            
            # --- Thread-Safe Access ---
            with self.lock:
                if flow_key not in self.flows:
                    self.flows[flow_key] = {
                        "fwd_timestamps": [], "bwd_timestamps": [],
                        "fwd_pkt_lengths": [], "bwd_pkt_lengths": [],
                        "fwd_header_lengths": [], "bwd_header_lengths": [],
                        "fwd_win_bytes": [],
                        "flow_key": flow_key, "protocol": proto_num,
                        "flow_src_ip": flow_src_ip, "flow_dst_ip": flow_dst_ip,
                        "flow_src_port": flow_src_port, "flow_dst_port": flow_dst_port,
                        "last_seen": pkt_time, # Initialize with current packet time
                        "fwd_psh_flags": 0, "bwd_psh_flags": 0,
                        "fwd_urg_flags": 0, "bwd_urg_flags": 0,
                        "fin_flag_cnt": 0, "syn_flag_cnt": 0, "rst_flag_cnt": 0,
                        "psh_flag_cnt": 0, "ack_flag_cnt": 0, "urg_flag_cnt": 0,
                        "ece_flag_cnt": 0,
                    }
                    
                flow = self.flows[flow_key]
                
                is_forward_packet = (ip_src_orig == flow_src_ip)
                
                if is_forward_packet:
                    flow["fwd_timestamps"].append(pkt_time)
                    flow["fwd_pkt_lengths"].append(pkt_len)
                    flow["fwd_header_lengths"].append(pkt["IP"].ihl * 4) 
                else:
                    flow["bwd_timestamps"].append(pkt_time)
                    flow["bwd_pkt_lengths"].append(pkt_len)
                    flow["bwd_header_lengths"].append(pkt["IP"].ihl * 4)
                
                flow["last_seen"] = pkt_time

                if proto == "TCP":
                    flags = pkt["TCP"].flags
                    if flags.F: flow["fin_flag_cnt"] += 1
                    if flags.S: flow["syn_flag_cnt"] += 1
                    if flags.R: flow["rst_flag_cnt"] += 1
                    if flags.P:
                        flow["psh_flag_cnt"] += 1
                        if is_forward_packet: flow["fwd_psh_flags"] += 1
                        else: flow["bwd_psh_flags"] += 1
                    if flags.A: flow["ack_flag_cnt"] += 1
                    if flags.U:
                        flow["urg_flag_cnt"] += 1
                        if is_forward_packet: flow["fwd_urg_flags"] += 1
                        else: flow["bwd_urg_flags"] += 1
                    if flags.E: flow["ece_flag_cnt"] += 1
                    
                    if is_forward_packet and not flow["fwd_win_bytes"]:
                        flow["fwd_win_bytes"].append(pkt["TCP"].window)
            # --- End Thread-Safe Access ---

        except Exception as e:
            pass # Ignore errors

    def calculate_stats(self, flow):
        """
        Calculates stats for a flow and returns them as a flat dictionary.
        """
        stats = {}
        fwd_pkts_len = flow["fwd_pkt_lengths"]
        bwd_pkts_len = flow["bwd_pkt_lengths"]
        all_pkts_len = fwd_pkts_len + bwd_pkts_len
        
        fwd_iat_times = np.diff(flow["fwd_timestamps"]) * 1000 if len(flow["fwd_timestamps"]) > 1 else np.array([])
        bwd_iat_times = np.diff(flow["bwd_timestamps"]) * 1000 if len(flow["bwd_timestamps"]) > 1 else np.array([])
        
        all_timestamps = sorted(flow["fwd_timestamps"] + flow["bwd_timestamps"])
        flow_iat_times = np.diff(all_timestamps) * 1000 if len(all_timestamps) > 1 else np.array([])
        
        flow_duration = (max(all_timestamps) - min(all_timestamps)) if len(all_timestamps) > 0 else 0
        flow_duration_sec = max(flow_duration, 1e-6) # Avoid division by zero
        
        total_pkts = len(all_pkts_len)
        total_bytes = sum(all_pkts_len)
        
        def get_stats(data, is_iat=False):
            if not isinstance(data, np.ndarray): data = np.array(data)
            if len(data) == 0:
                return (np.nan, np.nan, np.nan, np.nan) if not is_iat else (np.nan, np.nan, np.nan, np.nan, np.nan)
            
            mean_val, std_val, min_val, max_val = np.mean(data), np.std(data), np.min(data), np.max(data)
            if is_iat:
                return (np.sum(data), mean_val, std_val, min_val, max_val)
            return (mean_val, std_val, min_val, max_val)

        fwd_len_mean, fwd_len_std, fwd_len_min, fwd_len_max = get_stats(fwd_pkts_len)
        bwd_len_mean, bwd_len_std, bwd_len_min, bwd_len_max = get_stats(bwd_pkts_len)
        all_len_mean, all_len_std, all_len_min, all_len_max = get_stats(all_pkts_len)
        
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_min, fwd_iat_max = get_stats(fwd_iat_times, is_iat=True)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_min, bwd_iat_max = get_stats(bwd_iat_times, is_iat=True)
        flow_iat_tot, flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max = get_stats(flow_iat_times, is_iat=True)

        # --- Populate stats dictionary ---
        stats['Flow ID'] = flow['flow_key']
        stats['Src IP'] = flow['flow_src_ip']
        stats['Src Port'] = flow['flow_src_port']
        stats['Dst IP'] = flow['flow_dst_ip']
        stats['Dst Port'] = flow['flow_dst_port']
        stats['Protocol'] = flow['protocol']
        stats['Timestamp'] = min(all_timestamps) if all_timestamps else 0
        stats['Flow Duration'] = flow_duration * 1000 # in ms
        stats['Tot Fwd Pkts'] = len(flow['fwd_pkt_lengths'])
        stats['Tot Bwd Pkts'] = len(flow['bwd_pkt_lengths'])
        stats['Tot Pkts'] = total_pkts # Added for convenience
        stats['Tot Bytes'] = total_bytes # Added for convenience
        stats['TotLen Fwd Pkts'] = sum(flow['fwd_pkt_lengths'])
        stats['TotLen Bwd Pkts'] = sum(flow['bwd_pkt_lengths'])
        stats['Fwd Pkt Len Max'] = fwd_len_max
        stats['Fwd Pkt Len Min'] = fwd_len_min
        stats['Fwd Pkt Len Mean'] = fwd_len_mean
        stats['Fwd Pkt Len Std'] = fwd_len_std
        stats['Bwd Pkt Len Max'] = bwd_len_max
        stats['Bwd Pkt Len Min'] = bwd_len_min
        stats['Bwd Pkt Len Mean'] = bwd_len_mean
        stats['Bwd Pkt Len Std'] = bwd_len_std
        stats['Flow Byts/s'] = total_bytes / flow_duration_sec
        stats['Flow Pkts/s'] = total_pkts / flow_duration_sec
        stats['Flow IAT Mean'] = flow_iat_mean
        stats['Flow IAT Std'] = flow_iat_std
        stats['Flow IAT Max'] = flow_iat_max
        stats['Flow IAT Min'] = flow_iat_min
        stats['Fwd IAT Tot'] = fwd_iat_tot
        stats['Fwd IAT Mean'] = fwd_iat_mean
        stats['Fwd IAT Std'] = fwd_iat_std
        stats['Fwd IAT Max'] = fwd_iat_max
        stats['Fwd IAT Min'] = fwd_iat_min
        stats['Bwd IAT Tot'] = bwd_iat_tot
        stats['Bwd IAT Mean'] = bwd_iat_mean
        stats['Bwd IAT Std'] = bwd_iat_std
        stats['Bwd IAT Max'] = bwd_iat_max
        stats['Bwd IAT Min'] = bwd_iat_min
        stats['Fwd PSH Flags'] = flow['fwd_psh_flags']
        stats['Bwd PSH Flags'] = flow['bwd_psh_flags']
        stats['Fwd URG Flags'] = flow['fwd_urg_flags']
        stats['Bwd URG Flags'] = flow['bwd_urg_flags']
        stats['Fwd Header Len'] = sum(flow['fwd_header_lengths'])
        stats['Bwd Header Len'] = sum(flow['bwd_header_lengths'])
        stats['Fwd Pkts/s'] = len(flow['fwd_pkt_lengths']) / flow_duration_sec
        stats['Bwd Pkts/s'] = len(flow['bwd_pkt_lengths']) / flow_duration_sec
        stats['Pkt Len Min'] = all_len_min
        stats['Pkt Len Max'] = all_len_max
        stats['Pkt Len Mean'] = all_len_mean
        stats['Pkt Len Std'] = all_len_std
        stats['Pkt Len Var'] = np.var(all_pkts_len) if len(all_pkts_len) > 1 else np.nan
        stats['FIN Flag Cnt'] = flow['fin_flag_cnt']
        stats['SYN Flag Cnt'] = flow['syn_flag_cnt']
        stats['RST Flag Cnt'] = flow['rst_flag_cnt']
        stats['PSH Flag Cnt'] = flow['psh_flag_cnt']
        stats['ACK Flag Cnt'] = flow['ack_flag_cnt']
        stats['URG Flag Cnt'] = flow['urg_flag_cnt']
        stats['ECE Flag Cnt'] = flow['ece_flag_cnt']
        stats['Down/Up Ratio'] = len(flow['bwd_pkt_lengths']) / len(flow['fwd_pkt_lengths']) if len(flow['fwd_pkt_lengths']) > 0 else 0
        stats['Pkt Size Avg'] = all_len_mean
        stats['Fwd Seg Size Avg'] = fwd_len_mean
        stats['Bwd Seg Size Avg'] = bwd_len_mean
        stats['Init Fwd Win Byts'] = flow['fwd_win_bytes'][0] if flow['fwd_win_bytes'] else np.nan

        return stats

    def expire_flows_loop(self):
        """
        Thread target that periodically checks for expired flows.
        """
        while self.running:
            time.sleep(1) # Check once per second
            current_time = time.time()
            
            flows_to_process = []
            
            # --- Thread-Safe Access ---
            with self.lock:
                # Find expired keys
                expired_keys = [
                    key for key, flow in self.flows.items()
                    if current_time - flow["last_seen"] > self.timeout
                ]
                
                # Safely remove them and get their data
                for key in expired_keys:
                    flows_to_process.append(self.flows.pop(key))
            # --- End Thread-Safe Access ---
            
            # Now, process them outside the lock
            for flow_data in flows_to_process:
                stats_dict = self.calculate_stats(flow_data)
                self.output_queue.put(stats_dict)

    def start(self):
        """
        Starts the sniffer and flow expiration threads.
        """
        if self.running:
            print("Sniffer is already running.")
            return
            
        self.running = True
        
        # Start the flow expiration thread
        self.expire_thread = threading.Thread(target=self.expire_flows_loop)
        self.expire_thread.daemon = True # So it exits when main app exits
        self.expire_thread.start()
        
        # Start the Scapy sniffer
        print(f"--- Starting Scapy Flow Analyzer on interface: '{self.interface}' ---")
        self.sniffer_thread = scapy.AsyncSniffer(
            iface=self.interface,
            prn=self.process_packet,
            store=0
        )
        self.sniffer_thread.start()

    def stop(self):
        """
        Stops the sniffer and expiration threads.
        """
        self.running = False
        
        if self.sniffer_thread:
            print("Stopping Scapy sniffer...")
            self.sniffer_thread.stop()
            
        if self.expire_thread:
            print("Waiting for expiration thread to finish...")
            self.expire_thread.join() # Wait for it to finish
            
        print("Sniffer stopped.")