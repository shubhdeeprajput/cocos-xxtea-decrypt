#!/bin/bash

FILE_TYPE=""
APK_PATH=""  
DECRYPT_FUNC_ADD=""  
PACKAGE_NAME=""
MAIN_ACTIVITY=""
TEMP_APK_DIR="" 
TEMP_SPLIT_APK_DIR=""
OUTPUT_PATH=""
JSC_ARRAY=()


# --- Function: Display Usage and Exit ---
usage() {
    echo "Error: Usage: $0 <path_to_split_apks_zip_or_apk> <base_address> <output_path>"
    echo "  <path_to_split_apks_zip_or_apk> : Path to the ZIP or APK file containing split APKs."
    echo "  <base_address>: Base address of xxtea_decrypt function."
    echo "  <output_path>: Path to write decrypted jsc files."
    exit 1
}

# --- Function: Parse Command Line Arguments ---
parse_args() {
    if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
        usage
    fi
    APK_PATH="$1"
    DECRYPT_FUNC_ADD="$2"
    OUTPUT_PATH="$3"

    echo "Info: APK Bundle Path: '$APK_PATH'"
    echo "Info: Base address: '$DECRYPT_FUNC_ADD'"
    echo "Info: Output Path: '$OUTPUT_PATH'"

    if [ ! -d "$OUTPUT_PATH" ]; then
        echo "Error: Output Directory path does not exist."
        usage
    fi

    if [ -f "$APK_PATH" ] && [[ "$APK_PATH" =~ \.zip$ ]]; then
        FILE_TYPE="BUNDLE"
        return 0
    elif [ -f "$APK_PATH" ] && [[ "$APK_PATH" =~ \.apk$ ]]; then
        FILE_TYPE="APK"
        return 0
    else
        echo "Error: The provided APK path '$APK_PATH' is not a valid ZIP or APK file."
        usage
    fi
}

# --- Function: Check for Required CLI Tools ---
check_cli_tools() {
    echo "Info: Verifying required CLI tools..."
    local tools=(frida adb unzip) # List of tools to check
    local missing_tools=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "Error: The following required CLI tools were not found:" >&2
        for missing_tool in "${missing_tools[@]}"; do
            echo " - $missing_tool" >&2
        done
        echo "Please install them or add their location to your PATH and re-run the script." >&2
        exit 1
    fi
    echo "Info: All required CLI tools are installed and accessible!"
}


# --- Function: Check Frida Device and Server Status ---
check_frida_device() {
    echo "Info: Checking Frida device connection and server status..."
    local FRIDA_PS_OUTPUT
    local FRIDA_PS_EXIT_CODE

    FRIDA_PS_OUTPUT=$(frida-ps -U 2>&1)
    FRIDA_PS_EXIT_CODE=$?

    if [ "$FRIDA_PS_EXIT_CODE" -ne 0 ] || [ -z "$FRIDA_PS_OUTPUT" ]; then
        echo "Error: Frida device not connected or frida-server not running/responsive."
        echo "Hint: Ensure your device is connected."
        exit 1
    fi
    echo "Info: Frida device appears connected and frida-server is responsive."
}

check_jsc_file(){
    # --- Find all jsc files and store in array ---
    while IFS= read -r file; do
        JSC_ARRAY+=("$file")
    done < <(find "$TEMP_APK_DIR" -type f -name "*.jsc")

    # --- Check if no jsc file is present ---
    if [[ ${#JSC_ARRAY[@]} -eq 0 ]]; then
        echo "No .jsc files found in the specified directory. Nothing to decrypt, aborting the process..."
        exit 1
    fi

    echo "Found ${#JSC_ARRAY[@]} .jsc files."
}

# --- Function: Handle APK file ---
handle_apk_file() {
    echo "Info: Handling APK file and extracting .jsc files..."

    # Create temporary directory for extraction of APK content
    TEMP_APK_DIR=$(mktemp -d -t apk-content)
    if [ $? -ne 0 ]; then echo "Error: Failed to create temporary directory." ; exit 1 ; fi
    echo "Info: Temporary extraction directory: '$TEMP_APK_DIR'"

    # --- Extract APK content from APK ---
    if ! unzip -o -qq "$APK_PATH" -d "$TEMP_APK_DIR"; then
        echo "Error: Failed to unzip '$APK_PATH'."
        echo "Hint: Ensure apk file is valid."
        cleanup_temp_dir $TEMP_APK_DIR
        exit 1
    fi
    echo "Info: All APK content extracted to '$TEMP_APK_DIR'."

    check_jsc_file
    handle_apk_installation

}

# --- Function: Handle Split APKs ---
handle_and_install_apk_bundle() {
    echo "Info: Handling split APK bundle and extracting jsc..."

    # Create temporary directory for extraction of split APKs
    TEMP_SPLIT_APK_DIR=$(mktemp -d -t split-apks)
    if [ $? -ne 0 ]; then echo "Error: Failed to create temporary directory." ; exit 1 ; fi
    echo "Info: Temporary apk extraction directory: '$TEMP_SPLIT_APK_DIR'"

    # --- Extract All APKs from ZIP ---
    echo "Info: Extracting all APKs from ZIP to temporary directory..."
    if ! unzip -o -qq "$APK_PATH" -d "$TEMP_SPLIT_APK_DIR"; then
        echo "Error: Failed to unzip '$APK_PATH'."
        echo "Hint: Ensure the ZIP file is valid."
        cleanup_temp_dir $TEMP_SPLIT_APK_DIR
        exit 1
    fi
    echo "Info: All APKs extracted to '$TEMP_SPLIT_APK_DIR'."

    # Create temporary directory for extraction of APK contents from split apks
    TEMP_APK_DIR=$(mktemp -d -t apk-content)
    if [ $? -ne 0 ]; then echo "Error: Failed to create temporary directory." ; exit 1 ; fi
    echo "Info: Temporary apk extraction directory: '$TEMP_APK_DIR'"

    # --- Extract All APK content from Split APKs ---
    echo "Info: Extracting all APKs from ZIP to temporary directory..."
    if ! for apks in "$TEMP_SPLIT_APK_DIR"/*.apk; do unzip -o -qq "$apks" -d "$TEMP_APK_DIR"; done then
        echo "Error: Failed to unzip '$TEMP_SPLIT_APK_DIR/*.apk'."
        echo "Hint: Ensure the '$TEMP_SPLIT_APK_DIR' directory contains valid split apks."
        cleanup_temp_dir $TEMP_APK_DIR
        cleanup_temp_dir $TEMP_SPLIT_APK_DIR
        exit 1
    fi
    echo "Info: All APK content extracted to '$TEMP_APK_DIR'."

    check_jsc_file
    handle_apk_installation

}

handle_apk_installation(){
    # --- Install the APK on Device ---
    echo "Info: Installing the APK on device..."
    local DISP_PATH
    local INSTALL_OUTPUT
    local INSTALL_EXIT_CODE
    if [ "$FILE_TYPE" == "BUNDLE" ]; then
        INSTALL_OUTPUT=$(adb install-multiple -r -t "$TEMP_SPLIT_APK_DIR"/*.apk 2>&1)
        INSTALL_EXIT_CODE=$?
        DISP_PATH=$TEMP_SPLIT_APK_DIR
    elif [ "$FILE_TYPE" == "APK" ]; then
        INSTALL_OUTPUT=$(adb install -r -t "$APK_PATH" 2>&1)
        INSTALL_EXIT_CODE=$?
        DISP_PATH=$APK_PATH
    fi

    if [ "$INSTALL_EXIT_CODE" -ne 0 ]; then
      echo "Error: Failed to install APK from '$DISP_PATH'."
      echo "Hint: Check ADB install/install-multiple output for details. Common issues: signature, ABI, min SDK."
      echo "ADB Install Output:"
      echo "$INSTALL_OUTPUT"
      cleanup_temp_dir $TEMP_APK_DIR
      cleanup_temp_dir $TEMP_SPLIT_APK_DIR
      exit 1
    fi
    echo "Info: APK installed successfully."
}

# ---Function: Run Frida and Extract Key ---
run_frida_and_extract_key() {
    echo "Info: Starting Frida to hook and capture encryption key..."
    
    local frida_python_script="xxtea_extractor.py"
    local frida_js_hook="cocosdecrypt.js"
    
    # Call the python script and capture its output
    ENCRYPTION_KEY=$(python3 "$frida_python_script" \
        "com.rettulfgame.luckyspinfun" \
        "$DECRYPT_FUNC_ADD" \
        "'$frida_js_hook'")

    if [ $? -ne 0 ] || [ -z "$ENCRYPTION_KEY" ]; then
      echo "Error: Frida key extraction failed or returned an empty key." >&2
      exit 1 
    fi

    echo "Success: Captured Encryption Key: '$ENCRYPTION_KEY'"

    # Now you can use the ENCRYPTION_KEY variable for your next steps
}

# --- Function: Cleanup Temporary Directory (called on exit or failure) ---
cleanup_temp_dir() {
    TEMP_DIR=$1
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        echo "Info: Cleaning up temporary directory: '$TEMP_DIR'"
        if ! rm -rf "$TEMP_DIR"; then
            echo "Error: Couldn't Delete temporary directory: '$TEMP_DIR'"
            echo "Hint: Manually clean the directory to for removing reduntant files."
            exit 1
        fi
        TEMP_DIR="" # Clear the variable
        echo "Info: Temporary directory removed."
    fi
}

# --- Main Script Logic ---
main() {
    # Ensure temporary directory is cleaned up on script exit (even if errors occur)
    trap cleanup_temp_dir EXIT

    parse_args "$@"   
    check_cli_tools          
    check_frida_device       

    if [ "$FILE_TYPE" == "BUNDLE" ]; then
        handle_and_install_apk_bundle 
    elif [ "$FILE_TYPE" == "APK" ]; then
        handle_apk_file
    fi   
    cleanup_temp_dir $TEMP_APK_DIR
    run_frida_and_extract_key                

    echo "Success: All steps completed successfully."
}

# --- Call the main function ---
main "$@"