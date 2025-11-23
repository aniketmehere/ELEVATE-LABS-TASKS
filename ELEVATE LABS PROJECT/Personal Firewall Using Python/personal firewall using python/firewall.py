#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import json
import logging
from datetime import datetime
import subprocess
import sys
import os

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
except ImportError:
    print("Scapy is not installed. Please install it with: pip install scapy")
    sys.exit(1)

is_filtering = False
packet_count = 0
blocked_count = 0
rules = []
log_entries = []

DEFAULT_RULES = [
    {"name": "Block All Incoming", "direction": "in", "action": "block", "protocol": "any", "src_ip": "any", "dst_ip": "any", "src_port": "any", "dst_port": "any", "enabled": True},
    {"name": "Allow HTTP Out", "direction": "out", "action": "allow", "protocol": "tcp", "src_ip": "any", "dst_ip": "any", "src_port": "any", "dst_port": "80", "enabled": True},
    {"name": "Allow HTTPS Out", "direction": "out", "action": "allow", "protocol": "tcp", "src_ip": "any", "dst_ip": "any", "src_port": "any", "dst_port": "443", "enabled": True},
    {"name": "Allow DNS", "direction": "both", "action": "allow", "protocol": "udp", "src_ip": "any", "dst_ip": "any", "src_port": "any", "dst_port": "53", "enabled": True},
]

class PacketFilter:
    def __init__(self):
        self.rules = []
        self.load_rules()
        
    def load_rules(self):
        global rules
        try:
            with open('firewall_rules.json', 'r') as f:
                rules = json.load(f)
                self.rules = rules
        except FileNotFoundError:
            rules = DEFAULT_RULES.copy()
            self.rules = rules
            self.save_rules()
    
    def save_rules(self):
        with open('firewall_rules.json', 'w') as f:
            json.dump(self.rules, f, indent=4)
    
    def add_rule(self, rule):
        self.rules.append(rule)
        self.save_rules()
    
    def remove_rule(self, index):
        if 0 <= index < len(self.rules):
            del self.rules[index]
            self.save_rules()
    
    def update_rule(self, index, rule):
        if 0 <= index < len(self.rules):
            self.rules[index] = rule
            self.save_rules()
    
    def match_rule(self, packet):
        """Check if packet matches any rule"""
        if not hasattr(packet, 'payload'):
            return None
            
        direction = "unknown"
        protocol = "unknown"
        src_ip = "unknown"
        dst_ip = "unknown"
        src_port = "any"
        dst_port = "any"
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            
            direction = "in"  
            
            if TCP in packet:
                protocol = "tcp"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "udp"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "icmp"
        
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
                
            rule_dir = rule.get('direction', 'both')
            if rule_dir not in [direction, 'both']:
                continue
                
            rule_protocol = rule.get('protocol', 'any')
            if rule_protocol not in [protocol, 'any']:
                continue
                
            rule_src_ip = rule.get('src_ip', 'any')
            if rule_src_ip != 'any' and rule_src_ip != src_ip:
                continue
                
            rule_dst_ip = rule.get('dst_ip', 'any')
            if rule_dst_ip != 'any' and rule_dst_ip != dst_ip:
                continue
                
            rule_src_port = rule.get('src_port', 'any')
            if rule_src_port != 'any' and str(rule_src_port) != str(src_port):
                continue
                
            rule_dst_port = rule.get('dst_port', 'any')
            if rule_dst_port != 'any' and str(rule_dst_port) != str(dst_port):
                continue
                
            return rule
            
        return {"action": "block", "name": "Default Deny"}
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        global packet_count, blocked_count
        
        packet_count += 1
        
        rule = self.match_rule(packet)
        action = rule.get('action', 'block')
        
        log_entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'action': action,
            'protocol': 'unknown',
            'src_ip': 'unknown',
            'dst_ip': 'unknown',
            'src_port': 'unknown',
            'dst_port': 'unknown',
            'rule': rule.get('name', 'Unknown')
        }
        
        if IP in packet:
            log_entry['src_ip'] = packet[IP].src
            log_entry['dst_ip'] = packet[IP].dst
            
            if TCP in packet:
                log_entry['protocol'] = 'TCP'
                log_entry['src_port'] = packet[TCP].sport
                log_entry['dst_port'] = packet[TCP].dport
            elif UDP in packet:
                log_entry['protocol'] = 'UDP'
                log_entry['src_port'] = packet[UDP].sport
                log_entry['dst_port'] = packet[UDP].dport
            elif ICMP in packet:
                log_entry['protocol'] = 'ICMP'
        
        log_entries.append(log_entry)
        
        if action == 'block':
            blocked_count += 1
            return f"Blocked by rule: {rule.get('name', 'Unknown')}"
        
        return None

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Personal Firewall")
        self.root.geometry("900x700")
        
        self.filter = PacketFilter()
        self.sniff_thread = None
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.rules_frame = ttk.Frame(self.notebook)
        self.logs_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.notebook.add(self.rules_frame, text="Rules")
        self.notebook.add(self.logs_frame, text="Logs")
        
        self.setup_dashboard()
        self.setup_rules()
        self.setup_logs()
        
        self.update_status()
    
    def setup_dashboard(self):
        status_frame = ttk.LabelFrame(self.dashboard_frame, text="Firewall Status", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: STOPPED", font=("Arial", 12, "bold"), foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.toggle_btn = ttk.Button(status_frame, text="Start Firewall", command=self.toggle_firewall)
        self.toggle_btn.pack(side=tk.RIGHT, padx=5)
        
        stats_frame = ttk.LabelFrame(self.dashboard_frame, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.packets_label = ttk.Label(stats_frame, text="Packets Processed: 0")
        self.packets_label.pack(side=tk.LEFT, padx=20)
        
        self.blocked_label = ttk.Label(stats_frame, text="Packets Blocked: 0")
        self.blocked_label.pack(side=tk.LEFT, padx=20)
        
        self.rules_label = ttk.Label(stats_frame, text=f"Active Rules: {len([r for r in self.filter.rules if r.get('enabled', True)])}")
        self.rules_label.pack(side=tk.LEFT, padx=20)
        
        actions_frame = ttk.LabelFrame(self.dashboard_frame, text="Quick Actions", padding=10)
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(actions_frame, text="View Logs", command=self.show_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Manage Rules", command=self.show_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Clear Statistics", command=self.clear_stats).pack(side=tk.LEFT, padx=5)
        
        activity_frame = ttk.LabelFrame(self.dashboard_frame, text="Recent Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame, height=15, width=80)
        self.activity_text.pack(fill=tk.BOTH, expand=True)
        
        self.update_stats()
    
    def setup_rules(self):
        list_frame = ttk.LabelFrame(self.rules_frame, text="Firewall Rules", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("#", "Name", "Direction", "Action", "Protocol", "Source IP", "Dest IP", "Source Port", "Dest Port", "Enabled")
        self.rules_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=80)
        
        self.rules_tree.column("#", width=40)
        self.rules_tree.column("Name", width=120)
        self.rules_tree.column("Source IP", width=100)
        self.rules_tree.column("Dest IP", width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        buttons_frame = ttk.Frame(self.rules_frame)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Add Rule", command=self.add_rule_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Edit Rule", command=self.edit_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Delete Rule", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Toggle Rule", command=self.toggle_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Reset to Default", command=self.reset_rules).pack(side=tk.LEFT, padx=5)
        
        self.load_rules_to_tree()
    
    def setup_logs(self):
        logs_frame = ttk.LabelFrame(self.logs_frame, text="Firewall Logs", padding=10)
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=20, width=80)
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        
        buttons_frame = ttk.Frame(self.logs_frame)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(buttons_frame, text="Refresh Logs", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)
        
        self.refresh_logs()
    
    def load_rules_to_tree(self):
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        for i, rule in enumerate(self.filter.rules):
            values = (
                i+1,
                rule.get('name', 'Unknown'),
                rule.get('direction', 'both'),
                rule.get('action', 'block'),
                rule.get('protocol', 'any'),
                rule.get('src_ip', 'any'),
                rule.get('dst_ip', 'any'),
                rule.get('src_port', 'any'),
                rule.get('dst_port', 'any'),
                "Yes" if rule.get('enabled', True) else "No"
            )
            self.rules_tree.insert("", tk.END, values=values)
    
    def add_rule_dialog(self):
        dialog = RuleDialog(self.root, self, title="Add New Rule")
        if dialog.result:
            self.filter.add_rule(dialog.result)
            self.load_rules_to_tree()
    
    def edit_rule(self):
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule to edit.")
            return
        
        item = selection[0]
        index = self.rules_tree.index(item)
        
        rule = self.filter.rules[index]
        
        dialog = RuleDialog(self.root, self, title="Edit Rule", rule=rule)
        if dialog.result:
            self.filter.update_rule(index, dialog.result)
            self.load_rules_to_tree()
    
    def delete_rule(self):
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule to delete.")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected rule?"):
            item = selection[0]
            index = self.rules_tree.index(item)
            
            self.filter.remove_rule(index)
            self.load_rules_to_tree()
    
    def toggle_rule(self):
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule to toggle.")
            return
        
        item = selection[0]
        index = self.rules_tree.index(item)
        
        rule = self.filter.rules[index]
        rule['enabled'] = not rule.get('enabled', True)
        self.filter.update_rule(index, rule)
        self.load_rules_to_tree()
    
    def reset_rules(self):
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset all rules to defaults?"):
            self.filter.rules = DEFAULT_RULES.copy()
            self.filter.save_rules()
            self.load_rules_to_tree()
    
    def toggle_firewall(self):
        global is_filtering
        
        if not is_filtering:
            self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
            self.sniff_thread.start()
            is_filtering = True
            self.toggle_btn.config(text="Stop Firewall")
            self.status_label.config(text="Status: RUNNING", foreground="green")
        else:
            is_filtering = False
            self.toggle_btn.config(text="Start Firewall")
            self.status_label.config(text="Status: STOPPED", foreground="red")
    
    def start_sniffing(self):
        try:
            sniff(prn=self.packet_callback, filter="ip", store=0, stop_filter=lambda x: not is_filtering)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start packet capture: {str(e)}")
    
    def packet_callback(self, packet):
        result = self.filter.packet_handler(packet)
        
        if result and "Blocked" in result:
            self.root.after(0, self.add_activity, f"BLOCKED: {packet.summary()}")
    
    def add_activity(self, text):
        self.activity_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {text}\n")
        self.activity_text.see(tk.END)
    
    def update_stats(self):
        global packet_count, blocked_count
        
        self.packets_label.config(text=f"Packets Processed: {packet_count}")
        self.blocked_label.config(text=f"Packets Blocked: {blocked_count}")
        self.rules_label.config(text=f"Active Rules: {len([r for r in self.filter.rules if r.get('enabled', True)])}")
        
        self.root.after(1000, self.update_stats)
    
    def update_status(self):
        global is_filtering
        
        if is_filtering:
            self.status_label.config(text="Status: RUNNING", foreground="green")
            self.toggle_btn.config(text="Stop Firewall")
        else:
            self.status_label.config(text="Status: STOPPED", foreground="red")
            self.toggle_btn.config(text="Start Firewall")
    
    def show_logs(self):
        self.notebook.select(self.logs_frame)
        self.refresh_logs()
    
    def show_rules(self):
        self.notebook.select(self.rules_frame)
    
    def clear_stats(self):
        global packet_count, blocked_count
        packet_count = 0
        blocked_count = 0
        self.activity_text.delete(1.0, tk.END)
    
    def refresh_logs(self):
        self.logs_text.delete(1.0, tk.END)
        
        for entry in log_entries[-100:]:  
            self.logs_text.insert(tk.END, 
                f"{entry['timestamp']} - {entry['action'].upper():6} - {entry['protocol']:4} "
                f"{entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']} "
                f"[Rule: {entry['rule']}]\n")
        
        self.logs_text.see(tk.END)
    
    def clear_logs(self):
        global log_entries
        log_entries = []
        self.refresh_logs()
    
    def export_logs(self):
        filename = f"firewall_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                for entry in log_entries:
                    f.write(f"{entry['timestamp']} - {entry['action'].upper():6} - {entry['protocol']:4} "
                            f"{entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']} "
                            f"[Rule: {entry['rule']}]\n")
            messagebox.showinfo("Export Successful", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export logs: {str(e)}")

class RuleDialog(tk.Toplevel):
    def __init__(self, parent, firewall, title="Rule Dialog", rule=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x350")
        self.resizable(False, False)
        
        self.firewall = firewall
        self.result = None
        
        self.rule = rule or {
            "name": "New Rule",
            "direction": "both",
            "action": "allow",
            "protocol": "any",
            "src_ip": "any",
            "dst_ip": "any",
            "src_port": "any",
            "dst_port": "any",
            "enabled": True
        }
        
        self.create_widgets()
        self.fill_form()
        
        self.transient(parent)
        self.grab_set()
        self.wait_window(self)
    
    def create_widgets(self):
        ttk.Label(self, text="Rule Name:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        self.name_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.name_var).grid(row=0, column=1, sticky=tk.EW, padx=10, pady=5)
        
        
        ttk.Label(self, text="Direction:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.direction_var = tk.StringVar()
        direction_frame = ttk.Frame(self)
        direction_frame.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)
        ttk.Radiobutton(direction_frame, text="Incoming", variable=self.direction_var, value="in").pack(side=tk.LEFT)
        ttk.Radiobutton(direction_frame, text="Outgoing", variable=self.direction_var, value="out").pack(side=tk.LEFT)
        ttk.Radiobutton(direction_frame, text="Both", variable=self.direction_var, value="both").pack(side=tk.LEFT)
        
        ttk.Label(self, text="Action:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.action_var = tk.StringVar()
        action_frame = ttk.Frame(self)
        action_frame.grid(row=2, column=1, sticky=tk.EW, padx=10, pady=5)
        ttk.Radiobutton(action_frame, text="Allow", variable=self.action_var, value="allow").pack(side=tk.LEFT)
        ttk.Radiobutton(action_frame, text="Block", variable=self.action_var, value="block").pack(side=tk.LEFT)
        
        ttk.Label(self, text="Protocol:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        self.protocol_var = tk.StringVar()
        protocol_combo = ttk.Combobox(self, textvariable=self.protocol_var, 
                                     values=["any", "tcp", "udp", "icmp"])
        protocol_combo.grid(row=3, column=1, sticky=tk.EW, padx=10, pady=5)
        
        ttk.Label(self, text="Source IP:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        self.src_ip_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.src_ip_var).grid(row=4, column=1, sticky=tk.EW, padx=10, pady=5)
        
        ttk.Label(self, text="Destination IP:").grid(row=5, column=0, sticky=tk.W, padx=10, pady=5)
        self.dst_ip_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.dst_ip_var).grid(row=5, column=1, sticky=tk.EW, padx=10, pady=5)
        
        ttk.Label(self, text="Source Port:").grid(row=6, column=0, sticky=tk.W, padx=10, pady=5)
        self.src_port_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.src_port_var).grid(row=6, column=1, sticky=tk.EW, padx=10, pady=5)
        
        ttk.Label(self, text="Destination Port:").grid(row=7, column=0, sticky=tk.W, padx=10, pady=5)
        self.dst_port_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.dst_port_var).grid(row=7, column=1, sticky=tk.EW, padx=10, pady=5)
        
        ttk.Label(self, text="Enabled:").grid(row=8, column=0, sticky=tk.W, padx=10, pady=5)
        self.enabled_var = tk.BooleanVar()
        ttk.Checkbutton(self, variable=self.enabled_var).grid(row=8, column=1, sticky=tk.W, padx=10, pady=5)
        
        button_frame = ttk.Frame(self)
        button_frame.grid(row=9, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="OK", command=self.on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT, padx=10)
        
        self.columnconfigure(1, weight=1)
    
    def fill_form(self):
        self.name_var.set(self.rule.get('name', 'New Rule'))
        self.direction_var.set(self.rule.get('direction', 'both'))
        self.action_var.set(self.rule.get('action', 'allow'))
        self.protocol_var.set(self.rule.get('protocol', 'any'))
        self.src_ip_var.set(self.rule.get('src_ip', 'any'))
        self.dst_ip_var.set(self.rule.get('dst_ip', 'any'))
        self.src_port_var.set(self.rule.get('src_port', 'any'))
        self.dst_port_var.set(self.rule.get('dst_port', 'any'))
        self.enabled_var.set(self.rule.get('enabled', True))
    
    def on_ok(self):
        if not self.name_var.get().strip():
            messagebox.showerror("Error", "Rule name is required.")
            return
        
        self.result = {
            "name": self.name_var.get().strip(),
            "direction": self.direction_var.get(),
            "action": self.action_var.get(),
            "protocol": self.protocol_var.get(),
            "src_ip": self.src_ip_var.get().strip() or "any",
            "dst_ip": self.dst_ip_var.get().strip() or "any",
            "src_port": self.src_port_var.get().strip() or "any",
            "dst_port": self.dst_port_var.get().strip() or "any",
            "enabled": self.enabled_var.get()
        }
        
        self.destroy()
    
    def on_cancel(self):
        self.destroy()

def main():
    if os.name == 'posix' and os.geteuid() != 0:
        print("This application requires root privileges to capture packets.")
        print("Please run with sudo.")
        sys.exit(1)
    
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()