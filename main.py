import os
import logging
from memory_acquisition import load_vt_api_keys, acquire_memory_and_volatility_paths
from analyzer import MemoryAnalyzer

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='memory_analysis.log',
        filemode='a'
    )
    logging.info("Starting Volatility 3 Automation.")

    # Load API keys
    vt_api_keys = load_vt_api_keys()
    
    # Acquire Memory Dump & Volatility paths
    memory_image, volatility_path, is_process_dump = acquire_memory_and_volatility_paths()
    if is_process_dump:
        print("Warning: The provided memory image is a process dump. Some features may not be available.")
        logging.warning("The provided memory image is a process dump. Some features may not be available.")

    if not memory_image or not volatility_path:
        logging.error("Memory image or Volatility path not found. Exiting.")
        return

    # Instantiate main analyzer
    analyzer = MemoryAnalyzer(memory_image, volatility_path, vt_api_keys)

    while True:
        print("\nChoose the command you want to run:")
        print("1 - Find malicious processes")
        print("2 - Network scan (netscan IP check)")
        print("3 - UserAssist")
        print("4 - Full automation")
        print("5 - Pick a specific Volatility command")
        print("6 - Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            analyzer.find_malicious_processes()

        elif choice == "2":
            analyzer.check_malicious_ips()

        elif choice == "3":
            # Just userassist
            ua_out, _ = analyzer.vol_wrapper.run_volatility_command("userassist")
            if ua_out:
                from data_processing import filter_user_assist
                filtered_path = os.path.join(analyzer.output_dir, "filtered_userassist.json")
                filter_user_assist(ua_out, filtered_path)

        elif choice == "4":
            analyzer.full_automation()

        elif choice == "5":
            while True:
                print("\nChoose the command you want to run:")
                print("1 - pslist")
                print("2 - netscan")
                print("3 - wininfo")
                print("4 - userassist")
                print("5 - malfind")
                print("6 - cmdline")
                print("7 - pstree")
                print("8 - Enter command manually")
                print("9 - Back to main menu")
                cmd_choice = input("Enter your choice: ")

                if cmd_choice == "1":
                    analyzer.vol_wrapper.run_volatility_command("pslist")
                elif cmd_choice == "2":
                    analyzer.check_malicious_ips()
                elif cmd_choice == "3":
                    analyzer.vol_wrapper.run_volatility_command("wininfo")
                elif cmd_choice == "4":
                    ua_out, _ = analyzer.vol_wrapper.run_volatility_command("userassist")
                    if ua_out:
                        from data_processing import filter_user_assist
                        filtered_path = os.path.join(analyzer.output_dir, "filtered_userassist.json")
                        filter_user_assist(ua_out, filtered_path)
                elif cmd_choice == "5":
                    analyzer.vol_wrapper.run_volatility_command("malfind")
                elif cmd_choice == "6":
                    analyzer.vol_wrapper.run_volatility_command("cmdline")
                elif cmd_choice == "7":
                    analyzer.vol_wrapper.run_volatility_command("pstree")
                elif cmd_choice == "8":
                    custom_cmd = input("Enter the Volatility command (e.g., windows.info.Info): ")
                    command_list = ["python", volatility_path, "-f", memory_image, custom_cmd]
                    analyzer.vol_wrapper.run_volatility_command(f"custom_{custom_cmd.replace('.', '_')}", command_list)
                elif cmd_choice == "9":
                    break
                else:
                    print("Invalid choice. Please try again.")

        elif choice == "6":
            logging.info("Exiting Volatility 3 Automation.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()