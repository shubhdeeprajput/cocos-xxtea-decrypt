import frida
import sys
import time

# Global variable to store the captured key
captured_key = None
is_key_captured = False
session = None

def on_message(message, data):
    """Callback function to handle messages from the Frida JavaScript script."""
    global captured_key
    global session
    global is_key_captured
    
    if message['type'] == 'send':
        payload = message['payload']
        # Check if the message is our key signal
        if isinstance(payload, dict) and payload.get('type') == 'DECRYPT_KEY' and not is_key_captured:
            key = payload.get('key')
            if key:
                is_key_captured = True
                captured_key = key
                print(key) 

                if session:
                    try:
                        session.detach()  # Detach the frida session
                    except:
                        pass
                try:
                    sys.exit(0) # Exit the Python script
                except:
                    pass
        elif isinstance(payload, dict) and payload.get('type') == 'INFO':
            # Handle standard messages
            print(payload.get('info'), file=sys.stderr) # This goes to stderr, so bash ignores it
    elif message['type'] == 'error':
        print(f"[!] Frida JS Error: {message.get('description')}", file=sys.stderr)
        if session:
            session.detach()
        sys.exit(1)

def hook_frida(package_name, func_address, js_script_path):

    try:
        # 1. Attach to the USB device
        device = frida.get_usb_device(timeout=10)
        
        # 2. Spawn the target application
        # print(f"Info: Spawning {package_name}...")
        pid = device.spawn([package_name])
        session = device.attach(pid)
        
        # 3. Load the JavaScript code
        with open(js_script_path, 'r') as f:
            script_code = f.read()

        # Create the script and replace the placeholder with the actual address
        # This assumes your JS script has a placeholder for the address
        script = session.create_script(script_code.replace("DECRYPT_FUNC_ADD", func_address))
        script.on('message', on_message)
        script.load()
        
        # 4. Resume the application execution
        device.resume(pid)

        # 5. Wait for the key to be captured or for a timeout
        # time.sleep(30) # Wait up to 30 seconds

    # except frida.core.DeviceNotFoundError:
    #     print("Error: USB device not found or frida-server not running.", file=sys.stderr)
    #     sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        if session:
            session.detach()
        sys.exit(1)

    # If we get here, the script timed out without finding the key
    if not captured_key:
        print("Error: Timeout reached. Key was not captured.", file=sys.stderr)
        if session:
            session.detach()
        sys.exit(1)

if __name__ == "__main__":

    # --- Get arguments from the shell script ---
    # The script expects arguments in this order: package_name, decrypt_func_address, js_script_path
    if len(sys.argv) < 4:
        print("Error: Missing arguments.", file=sys.stderr)
        sys.exit(1)

    package_name = sys.argv[1]
    func_address = sys.argv[2]
    js_script_path = sys.argv[3]

    hook_frida(package_name, func_address, js_script_path)

#test decrypt key: com.rettulfgsdg452same.luckyspid451ngold