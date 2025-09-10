
import os
import sys
import subprocess
from colorama import init, Fore, Style

init(autoreset=True)

def install_requirements():
    try:
        print(f"{Fore.YELLOW}Installing required packages...{Style.RESET_ALL}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print(f"{Fore.GREEN}All requirements installed successfully!{Style.RESET_ALL}")
        return True
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}Failed to install requirements. Please install manually.{Style.RESET_ALL}")
        return False

def main():
    print(f"""
 $$$$$$\                      $$\                      $$$$$$\                                                             
$$  __$$\                     \__|                    $$  __$$\                                                            
$$ /  $$ |$$$$$$$\   $$$$$$\  $$\ $$$$$$$\   $$$$$$$\ $$ /  \__| $$$$$$$\ $$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\  
$$ |  $$ |$$  __$$\ $$  __$$\ $$ |$$  __$$\ $$  _____|\$$$$$$\  $$  _____|\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$ |  $$ |$$ |  $$ |$$ /  $$ |$$ |$$ |  $$ |\$$$$$$\   \____$$\ $$ /      $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |$$ |  $$ | \____$$\ $$\   $$ |$$ |     $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      
 $$$$$$  |$$ |  $$ |\$$$$$$  |$$ |$$ |  $$ |$$$$$$$  |\$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |      
 \______/ \__|  \__| \______/ \__|\__|  \__|\_______/  \______/  \_______|\_______|\__|  \__|\__|  \__| \_______|\__| 
{Fore.WHITE}Web Vulnerability Scanner
{Fore.GREEN}Created by: o0c | GitHub: o0cdev | Discord: 0xo0c | Instagram: o0ctf
{Style.RESET_ALL}
    """)
    
    if not os.path.exists("requirements.txt"):
        print(f"{Fore.RED}requirements.txt not found!{Style.RESET_ALL}")
        return
    
    try:
        import requests
        import colorama
        import bs4
    except ImportError:
        print(f"{Fore.YELLOW}Some packages are missing. Installing...{Style.RESET_ALL}")
        if not install_requirements():
            return
    
    print(f"{Fore.GREEN}Starting OnionScanner...{Style.RESET_ALL}")
    
    try:
        from main import OnionScanner
        scanner = OnionScanner()
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scanner interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
