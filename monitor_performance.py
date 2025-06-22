#!/usr/bin/env python3
"""
NIDPS Performance Monitor
Simple script to monitor CPU usage and provide recommendations
"""

import psutil
import time
import os
import sys

def get_nidps_process():
    """Find NIDPS process"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'python' in proc.info['name'].lower():
                cmdline = ' '.join(proc.info['cmdline'])
                if 'run.py' in cmdline or 'nidps' in cmdline.lower():
                    return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def monitor_performance():
    """Monitor system performance"""
    print("=== NIDPS Performance Monitor ===")
    print("Press Ctrl+C to stop monitoring")
    print("=" * 40)
    
    nidps_proc = get_nidps_process()
    
    if not nidps_proc:
        print("❌ NIDPS process not found. Make sure the engine is running.")
        return
    
    print(f"✅ Found NIDPS process (PID: {nidps_proc.pid})")
    print()
    
    try:
        while True:
            # System CPU usage
            system_cpu = psutil.cpu_percent(interval=1)
            
            # NIDPS process CPU usage
            try:
                nidps_cpu = nidps_proc.cpu_percent()
                nidps_memory = nidps_proc.memory_info().rss / 1024 / 1024  # MB
            except psutil.NoSuchProcess:
                print("❌ NIDPS process stopped")
                break
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Status indicators
            cpu_status = "🟢" if system_cpu < 30 else "🟡" if system_cpu < 70 else "🔴"
            memory_status = "🟢" if memory.percent < 70 else "🟡" if memory.percent < 90 else "🔴"
            
            # Clear screen (works on most terminals)
            os.system('clear' if os.name == 'posix' else 'cls')
            
            print("=== NIDPS Performance Monitor ===")
            print(f"Time: {time.strftime('%H:%M:%S')}")
            print("=" * 40)
            
            print(f"System CPU: {cpu_status} {system_cpu:.1f}%")
            print(f"NIDPS CPU:  {nidps_cpu:.1f}%")
            print(f"Memory:     {memory_status} {memory.percent:.1f}% ({memory.used/1024/1024/1024:.1f}GB / {memory.total/1024/1024/1024:.1f}GB)")
            print(f"NIDPS RAM:  {nidps_memory:.1f} MB")
            print()
            
            # Recommendations
            print("💡 Recommendations:")
            if system_cpu > 50:
                print("  • High CPU usage detected!")
                print("  • Consider enabling Performance Mode")
                print("  • Reduce packet sampling rates")
                print("  • Disable packet logging")
            elif system_cpu > 30:
                print("  • Moderate CPU usage")
                print("  • Consider reducing DPI sampling rate")
            else:
                print("  • CPU usage is normal")
                print("  • You can increase sampling rates if needed")
            
            if memory.percent > 80:
                print("  • High memory usage!")
                print("  • Consider restarting the system")
            
            print()
            print("Press Ctrl+C to stop monitoring")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped.")
        print("\n📊 Performance Summary:")
        print("• Use the web interface to adjust performance settings")
        print("• Performance Mode: Reduces CPU usage by 60-80%")
        print("• Sampling Rates: Lower = Less CPU usage")
        print("• Packet Logging: Disable for maximum performance")

if __name__ == "__main__":
    monitor_performance() 