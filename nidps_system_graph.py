#!/usr/bin/env python3
"""
NIDPS System Graph Generator
Creates visual graph representations of the NIDPS system workflows
"""

import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

def create_main_system_graph():
    """Create the main NIDPS system workflow graph"""
    G = nx.DiGraph()
    
    # Define nodes with their types and positions
    nodes = {
        'start': {'pos': (0, 8), 'type': 'start', 'label': 'System\nStart'},
        'init': {'pos': (0, 7), 'type': 'process', 'label': 'Initialize\nSystem'},
        'web_interface': {'pos': (0, 6), 'type': 'process', 'label': 'Start Web\nInterface'},
        'auth': {'pos': (0, 5), 'type': 'decision', 'label': 'User\nAuthentication'},
        'dashboard': {'pos': (0, 4), 'type': 'process', 'label': 'Load\nDashboard'},
        'engine_decision': {'pos': (0, 3), 'type': 'decision', 'label': 'Start Detection\nEngine?'},
        'packet_sniffer': {'pos': (0, 2), 'type': 'process', 'label': 'Initialize\nPacket Sniffer'},
        'load_rules': {'pos': (0, 1), 'type': 'process', 'label': 'Load Detection\nRules'},
        'monitoring': {'pos': (0, 0), 'type': 'process', 'label': 'Real-time\nMonitoring'},
        'user_management': {'pos': (3, 4), 'type': 'process', 'label': 'User\nManagement'},
        'admin_features': {'pos': (3, 3), 'type': 'process', 'label': 'Admin\nFeatures'},
        'user_features': {'pos': (-3, 3), 'type': 'process', 'label': 'User\nFeatures'},
        'logout': {'pos': (0, -1), 'type': 'decision', 'label': 'User\nLogout?'},
        'end': {'pos': (0, -2), 'type': 'end', 'label': 'System\nEnd'},
        'error': {'pos': (3, 5), 'type': 'error', 'label': 'Login\nError'},
    }
    
    # Add nodes
    for node, attrs in nodes.items():
        G.add_node(node, **attrs)
    
    # Add edges
    edges = [
        ('start', 'init'),
        ('init', 'web_interface'),
        ('web_interface', 'auth'),
        ('auth', 'dashboard', {'condition': 'valid'}),
        ('auth', 'error', {'condition': 'invalid'}),
        ('error', 'auth'),
        ('dashboard', 'engine_decision'),
        ('engine_decision', 'packet_sniffer', {'condition': 'yes'}),
        ('engine_decision', 'user_management', {'condition': 'no'}),
        ('packet_sniffer', 'load_rules'),
        ('load_rules', 'monitoring'),
        ('monitoring', 'logout'),
        ('user_management', 'admin_features', {'condition': 'admin'}),
        ('user_management', 'user_features', {'condition': 'user'}),
        ('admin_features', 'logout'),
        ('user_features', 'logout'),
        ('logout', 'end', {'condition': 'yes'}),
        ('logout', 'auth', {'condition': 'no'}),
    ]
    
    for edge in edges:
        if len(edge) == 3:
            G.add_edge(edge[0], edge[1], **edge[2])
        else:
            G.add_edge(edge[0], edge[1])
    
    return G

def create_packet_processing_graph():
    """Create the packet processing workflow graph"""
    G = nx.DiGraph()
    
    # Define nodes
    nodes = {
        'start': {'pos': (0, 8), 'type': 'start', 'label': 'Packet\nProcessing\nStart'},
        'sniffer_init': {'pos': (0, 7), 'type': 'process', 'label': 'Packet Sniffer\nInitialized'},
        'capture_loop': {'pos': (0, 6), 'type': 'process', 'label': 'Start Capture\nLoop'},
        'capture_packet': {'pos': (0, 5), 'type': 'process', 'label': 'Capture\nNetwork Packet'},
        'parse_headers': {'pos': (0, 4), 'type': 'process', 'label': 'Parse Packet\nHeaders'},
        'validate': {'pos': (0, 3), 'type': 'decision', 'label': 'Valid\nPacket?'},
        'dpi': {'pos': (0, 2), 'type': 'process', 'label': 'Deep Packet\nInspection'},
        'extract_features': {'pos': (0, 1), 'type': 'process', 'label': 'Extract\nFeatures'},
        'apply_rules': {'pos': (0, 0), 'type': 'process', 'label': 'Apply Detection\nRules'},
        'rule_match': {'pos': (0, -1), 'type': 'decision', 'label': 'Rule\nMatch?'},
        'threat_detected': {'pos': (3, -1), 'type': 'process', 'label': 'Threat\nDetected'},
        'calculate_score': {'pos': (3, -2), 'type': 'process', 'label': 'Calculate\nThreat Score'},
        'block_decision': {'pos': (3, -3), 'type': 'decision', 'label': 'Action = Block?'},
        'block_ip': {'pos': (5, -3), 'type': 'process', 'label': 'Block IP\nAddress'},
        'log_event': {'pos': (1, -3), 'type': 'process', 'label': 'Log\nEvent'},
        'send_notifications': {'pos': (3, -4), 'type': 'process', 'label': 'Send\nNotifications'},
        'update_analytics': {'pos': (3, -5), 'type': 'process', 'label': 'Update\nAnalytics'},
        'update_stats': {'pos': (-3, -1), 'type': 'process', 'label': 'Update Traffic\nStatistics'},
        'performance_check': {'pos': (0, -6), 'type': 'decision', 'label': 'Performance\nIssues?'},
        'performance_mode': {'pos': (3, -6), 'type': 'process', 'label': 'Enable\nPerformance Mode'},
        'monitor_resources': {'pos': (0, -7), 'type': 'process', 'label': 'Monitor\nResources'},
        'auto_recovery': {'pos': (0, -8), 'type': 'decision', 'label': 'System\nIssues?'},
        'trigger_recovery': {'pos': (3, -8), 'type': 'process', 'label': 'Trigger\nAuto-Recovery'},
        'continue_loop': {'pos': (0, -9), 'type': 'decision', 'label': 'System\nRunning?'},
        'cleanup': {'pos': (0, -10), 'type': 'process', 'label': 'Cleanup\nResources'},
        'end': {'pos': (0, -11), 'type': 'end', 'label': 'Processing\nEnd'},
    }
    
    # Add nodes
    for node, attrs in nodes.items():
        G.add_node(node, **attrs)
    
    # Add edges
    edges = [
        ('start', 'sniffer_init'),
        ('sniffer_init', 'capture_loop'),
        ('capture_loop', 'capture_packet'),
        ('capture_packet', 'parse_headers'),
        ('parse_headers', 'validate'),
        ('validate', 'dpi', {'condition': 'yes'}),
        ('validate', 'continue_loop', {'condition': 'no'}),
        ('dpi', 'extract_features'),
        ('extract_features', 'apply_rules'),
        ('apply_rules', 'rule_match'),
        ('rule_match', 'threat_detected', {'condition': 'yes'}),
        ('rule_match', 'update_stats', {'condition': 'no'}),
        ('threat_detected', 'calculate_score'),
        ('calculate_score', 'block_decision'),
        ('block_decision', 'block_ip', {'condition': 'yes'}),
        ('block_decision', 'log_event', {'condition': 'no'}),
        ('block_ip', 'send_notifications'),
        ('log_event', 'send_notifications'),
        ('send_notifications', 'update_analytics'),
        ('update_analytics', 'performance_check'),
        ('update_stats', 'performance_check'),
        ('performance_check', 'performance_mode', {'condition': 'yes'}),
        ('performance_check', 'monitor_resources', {'condition': 'no'}),
        ('performance_mode', 'monitor_resources'),
        ('monitor_resources', 'auto_recovery'),
        ('auto_recovery', 'trigger_recovery', {'condition': 'yes'}),
        ('auto_recovery', 'continue_loop', {'condition': 'no'}),
        ('trigger_recovery', 'continue_loop'),
        ('continue_loop', 'capture_packet', {'condition': 'yes'}),
        ('continue_loop', 'cleanup', {'condition': 'no'}),
        ('cleanup', 'end'),
    ]
    
    for edge in edges:
        if len(edge) == 3:
            G.add_edge(edge[0], edge[1], **edge[2])
        else:
            G.add_edge(edge[0], edge[1])
    
    return G

def create_user_management_graph():
    """Create the user management workflow graph"""
    G = nx.DiGraph()
    
    # Define nodes
    nodes = {
        'start': {'pos': (0, 8), 'type': 'start', 'label': 'User Access\nWeb Interface'},
        'login': {'pos': (0, 7), 'type': 'process', 'label': 'Login\nAttempt'},
        'auth_check': {'pos': (0, 6), 'type': 'decision', 'label': 'Valid\nCredentials?'},
        'load_dashboard': {'pos': (0, 5), 'type': 'process', 'label': 'Load User\nDashboard'},
        'check_role': {'pos': (0, 4), 'type': 'decision', 'label': 'Admin\nRole?'},
        'admin_dashboard': {'pos': (3, 4), 'type': 'process', 'label': 'Access Admin\nDashboard'},
        'user_dashboard': {'pos': (-3, 4), 'type': 'process', 'label': 'Access User\nDashboard'},
        'admin_menu': {'pos': (3, 3), 'type': 'process', 'label': 'Show Admin\nMenu'},
        'user_menu': {'pos': (-3, 3), 'type': 'process', 'label': 'Show User\nMenu'},
        'user_management': {'pos': (3, 2), 'type': 'process', 'label': 'User\nManagement'},
        'system_config': {'pos': (3, 1), 'type': 'process', 'label': 'System\nConfiguration'},
        'analytics': {'pos': (3, 0), 'type': 'process', 'label': 'Analytics\nDashboard'},
        'system_monitor': {'pos': (3, -1), 'type': 'process', 'label': 'System\nMonitor'},
        'detection_rules': {'pos': (3, -2), 'type': 'process', 'label': 'Detection\nRules'},
        'view_alerts': {'pos': (-3, 2), 'type': 'process', 'label': 'View\nAlerts'},
        'change_password': {'pos': (-3, 1), 'type': 'process', 'label': 'Change\nPassword'},
        'view_profile': {'pos': (-3, 0), 'type': 'process', 'label': 'View\nProfile'},
        'logout_check': {'pos': (0, -3), 'type': 'decision', 'label': 'Logout\nRequested?'},
        'end_session': {'pos': (0, -4), 'type': 'process', 'label': 'End\nSession'},
        'end': {'pos': (0, -5), 'type': 'end', 'label': 'Session\nEnded'},
        'login_error': {'pos': (3, 6), 'type': 'error', 'label': 'Show Login\nError'},
    }
    
    # Add nodes
    for node, attrs in nodes.items():
        G.add_node(node, **attrs)
    
    # Add edges
    edges = [
        ('start', 'login'),
        ('login', 'auth_check'),
        ('auth_check', 'load_dashboard', {'condition': 'yes'}),
        ('auth_check', 'login_error', {'condition': 'no'}),
        ('login_error', 'login'),
        ('load_dashboard', 'check_role'),
        ('check_role', 'admin_dashboard', {'condition': 'yes'}),
        ('check_role', 'user_dashboard', {'condition': 'no'}),
        ('admin_dashboard', 'admin_menu'),
        ('user_dashboard', 'user_menu'),
        ('admin_menu', 'user_management'),
        ('admin_menu', 'system_config'),
        ('admin_menu', 'analytics'),
        ('admin_menu', 'system_monitor'),
        ('admin_menu', 'detection_rules'),
        ('user_menu', 'view_alerts'),
        ('user_menu', 'change_password'),
        ('user_menu', 'view_profile'),
        ('user_management', 'logout_check'),
        ('system_config', 'logout_check'),
        ('analytics', 'logout_check'),
        ('system_monitor', 'logout_check'),
        ('detection_rules', 'logout_check'),
        ('view_alerts', 'logout_check'),
        ('change_password', 'logout_check'),
        ('view_profile', 'logout_check'),
        ('logout_check', 'end_session', {'condition': 'yes'}),
        ('logout_check', 'admin_menu', {'condition': 'no'}),
        ('end_session', 'end'),
    ]
    
    for edge in edges:
        if len(edge) == 3:
            G.add_edge(edge[0], edge[1], **edge[2])
        else:
            G.add_edge(edge[0], edge[1])
    
    return G

def draw_graph(G, title, filename):
    """Draw the graph with custom styling"""
    plt.figure(figsize=(16, 12))
    
    # Get positions
    pos = nx.get_node_attributes(G, 'pos')
    
    # Define colors for different node types using a mapping
    node_colors = {}
    node_types = nx.get_node_attributes(G, 'type')
    
    for node in G.nodes():
        node_type = node_types[node]
        if node_type == 'start':
            node_colors[node] = 'lightgreen'
        elif node_type == 'end':
            node_colors[node] = 'lightcoral'
        elif node_type == 'decision':
            node_colors[node] = 'lightblue'
        elif node_type == 'process':
            node_colors[node] = 'lightyellow'
        elif node_type == 'error':
            node_colors[node] = 'lightpink'
        else:
            node_colors[node] = 'lightgray'
    
    # Convert to list in the order of nodes
    colors = [node_colors[node] for node in G.nodes()]
    
    # Draw nodes with proper color handling
    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=3000, alpha=0.8)
    
    # Draw edges
    nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, arrowsize=20, alpha=0.7)
    
    # Draw labels
    labels = nx.get_node_attributes(G, 'label')
    nx.draw_networkx_labels(G, pos, labels, font_size=8, font_weight='bold')
    
    # Add edge labels for conditions
    edge_labels = {}
    for edge in G.edges(data=True):
        if 'condition' in edge[2]:
            edge_labels[(edge[0], edge[1])] = edge[2]['condition']
    
    nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=6)
    
    plt.title(title, fontsize=16, fontweight='bold', pad=20)
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.show()

def main():
    """Generate all three graphs"""
    print("Generating NIDPS System Graphs...")
    
    # Create and draw main system graph
    print("1. Creating main system workflow graph...")
    main_graph = create_main_system_graph()
    draw_graph(main_graph, "NIDPS Main System Workflow", "nidps_main_system_graph.png")
    
    # Create and draw packet processing graph
    print("2. Creating packet processing workflow graph...")
    packet_graph = create_packet_processing_graph()
    draw_graph(packet_graph, "NIDPS Packet Processing Workflow", "nidps_packet_processing_graph.png")
    
    # Create and draw user management graph
    print("3. Creating user management workflow graph...")
    user_graph = create_user_management_graph()
    draw_graph(user_graph, "NIDPS User Management Workflow", "nidps_user_management_graph.png")
    
    print("All graphs generated successfully!")
    print("Files created:")
    print("- nidps_main_system_graph.png")
    print("- nidps_packet_processing_graph.png")
    print("- nidps_user_management_graph.png")

if __name__ == "__main__":
    main() 