"""
AegisOSINT - One-Click Launcher
Starts the FastAPI threat intelligence backend and opens the CTI Workbench UI in your browser.
"""

import os
import sys
import time
import webbrowser
import uvicorn


def print_banner():
    banner = """
 =========================================================================
   ___                   _        ____   ____  ___  _   _  _____ 
  / _ \\                 (_)      / __ \\ / ___||_ _|| \\ | ||_   _|
 / /_\\ \\ ___   __ _  _  _  ___  | |  | |\\___ \\  | | |  \\| |  | |  
 |  _  |/ _ \\ / _` || || |/ __| | |  | | ___) | | | | |\\  |  | |  
 | | | |  __/| (_| || || |\\__ \\ | |__| | |____/ |_| |_| \\_|  |_|  
 \\_| |_/\\___| \\__, ||_||_||___/  \\____/                          
               __/ |   Automated Brand Impersonation & Fraud OSINT
              |___/    Forensic CTI Intelligence & Takedown Suite
 =========================================================================
    """
    print(banner)
    print(" [*] Initializing AegisOSINT Threat Engines...")
    print(" [*] API & Workbench URL: http://127.0.0.1:8000")
    print(" [*] Press Ctrl+C to terminate.")
    print(" =========================================================================\n")


def main():
    print_banner()

    # Open browser after slight delay
    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://127.0.0.1:8000")

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    # Run Uvicorn server
    uvicorn.run(
        "backend.app:app",
        host="127.0.0.1",
        port=8000,
        log_level="info",
        reload=False
    )


if __name__ == "__main__":
    main()
