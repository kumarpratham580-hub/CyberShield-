
from scripts.realtime_monitor import start_monitor
from scripts.baseline_guard import verify_baseline

def main():

    while True:
        print("\n===================================")
        print("       CYBERSHIELD SECURITY TOOL")
        print("===================================")

        print("1. Start Real-Time Monitoring")
        print("2. Verify Trusted Baseline")
        print("3. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            start_monitor()

        elif choice == "2":
            verify_baseline()

        elif choice == "3":
            print("Exiting CyberShield. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

