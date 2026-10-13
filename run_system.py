"""
AegisOSINT - One-Click Launcher
Starts the FastAPI threat intelligence backend and opens the CTI Workbench UI in your browser.
Auto-detects port availability to prevent conflict with other running processes.
"""

import os
import sys
import time
import socket
import webbrowser
import uvicorn


def find_available_port(preferred_port: int = 8000, fallback_ports=(8080, 8001, 8088)) -> int:
    """Finds an available TCP port starting with preferred_port, falling back if occupied."""
    for port in [preferred_port, *fallback_ports]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return preferred_port


def print_banner(port: int = 8000):
    banner = f"""
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
    print(f" [*] API & Workbench URL: http://127.0.0.1:{port}")
    print(" [*] Swagger OpenAPI Docs: http://127.0.0.1:{}/docs".format(port))
    print(" [*] Press Ctrl+C to terminate.")
    print(" =========================================================================\n")


def main():
    # Detect port from CLI arguments or search for first available port
    port = 8000
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg.isdigit():
                port = int(arg)
                break
            elif arg.startswith("--port="):
                port = int(arg.split("=")[1])
                break
    else:
        port = find_available_port(8000)

    print_banner(port)

    # Open browser after slight delay
    def open_browser():
        time.sleep(1.5)
        webbrowser.open(f"http://127.0.0.1:{port}")

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    # Run Uvicorn server
    uvicorn.run(
        "backend.app:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
        reload=False
    )


if __name__ == "__main__":
    main()
