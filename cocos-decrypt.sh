#!/bin/bash

FILE_TYPE=""                 # Variable to store type of file given by user
APK_PATH=""                  # Variable to store user supplied path to zip or apk
DECRYPT_FUNC_ADD=""          # Variable to store user supplied function address
PACKAGE_NAME=""              # Variable to store package name of the app
TEMP_APK_DIR=""              # Temporary Directory to store apk contents
TEMP_SPLIT_APK_DIR=""        # Temporary Directory to store split apks
OUTPUT_PATH=""               # Directory to store decrypted jsc files
JSC_ARRAY=()                 # Array to store jsc file paths


# --- Function: Display Usage and Exit ---
usage() {
    echo "Error: Usage: $0 <path_to_split_apks_zip_or_apk> <base_address> <output_path>"
    echo "  <path_to_split_apks_zip_or_apk> : Path to the ZIP or APK file containing split APKs."
    echo "  <base_address>: Base address of xxtea_decrypt function."
    echo "  <output_path>: Path to write decrypted jsc files."
    exit 1
}

# Function to ask for user confirmation
confirm() {
    read -r -p "$1 [Y/n] " response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            true
            ;;
        *)
            false
            ;;
    esac
}

# --- Function: Parse Command Line Arguments ---
parse_args() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        usage
    fi
    APK_PATH="$1"
    DECRYPT_FUNC_ADD="$2"
    OUTPUT_PATH=${3:-"."}       # Set output path to current directory by default if none is passed

    echo "Info: APK Bundle Path: '$APK_PATH'"
    echo "Info: Base address: '$DECRYPT_FUNC_ADD'"
    echo "Info: Output Path: '$OUTPUT_PATH'"

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
    local tools=(frida adb unzip aapt) # List of tools to check
    local missing_tools=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "Error: The $tool command is required."
            if [ ! $tool = "aapt" ]; then
                if confirm "Do you want to install it now?"; then
                    local os_type=$(uname -s)
                    case "$os_type" in 
                        Linux*)
                        apt install -y "$tool" || { echo "Error: Failed to install '$tool'. Please install manually." >&2; exit 1; }
                        ;;
                        Darwin*)
                        brew install "$tool" || { echo "Error: Failed to install '$tool'. Please install manually." >&2; exit 1; }
                        ;;
                        *)
                        echo "Error: Unsupported OS: $os_type." 
                        exit 1
                    esac
                else
                    echo "Info: Please Install the '$tool' and rerun the script."
                    exit 1
                fi
            else
                if confirm "Do you want to setup aapt to PATH now?"; then
                    local android_sdk_path=""
                    if [ -d "$HOME/Library/Android/sdk" ]; then
                        android_sdk_path="$HOME/Library/Android/sdk"
                    elif [ -d "$HOME/Android/sdk" ]; then
                        android_sdk_path="$HOME/Android/sdk"
                    else
                        echo "Error: Android SDK not found in standard locations. Please install it." >&2
                        exit 1
                    fi
                    local latest_version=$(ls -v "$android_sdk_path/build-tools" | tail -n 1)
                    export PATH="$PATH:$android_sdk_path/build-tools/$latest_version"
                    echo "Info: Path to aapt has been added to the current script's environment."
                else
                    echo "Info: Please manually add the Android SDK Build-Tools path to your PATH and re-run the script." >&2
                    exit 1
                fi
            fi
        fi
    done
    echo "Info: All required CLI tools are installed and accessible!"
}

# --- Function: Setup python environment ---
setup_python_environment(){
    if ! command -v python3 &> /dev/null; then
        echo "Error: Python 3 is required. Please install it." >&2
        exit 1
    fi

    if [ ! -d ".venv" ]; then
        echo "Info: Creating Python Virtual Environment..."
        python3 -m venv .venv || { echo "Error: Faild to create venv." >&2; exit 1; }
    fi

    source .venv/bin/activate || { echo "Error: Failed to activate virtual environment. Exiting..." >&2; exit 1; }

    echo "Info: Installing Python Dependencies..."
    pip3 install -r requirements.txt || { echo "Error: Failed to install Python dependencies" >&2; exit 1;}

    deactivate

    echo "Info: Python Environment is ready!"

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

    for jsc_file in "${JSC_ARRAY[@]}"; do
        echo "- $jsc_file"
    done
}

# --- Function: Handle APK file ---
handle_apk_file() {
    echo "Info: Handling APK file and extracting .jsc files..."

    # Create temporary directory for extraction of APK content
    TEMP_APK_DIR=$(mktemp -d -t apk-content)
    if [ $? -ne 0 ]; then echo "Error: Failed to create temporary directory." ; exit 1 ; fi
    echo "Info: Temporary extraction directory: '$TEMP_APK_DIR'"

    # --- Extract APK content from APK ---
    echo "Info: Extracting APK content from APK to temporary directory..."
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
    echo "Info: Handling APK bundle and extracting jsc..."

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

    # --- Extract APK content from Split APKs ---
    echo "Info: Extracting APK content from APKs to temporary directory..."
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
      echo "Error: Failed to install APK from '$DISP_PATH'." >&2
      echo "Hint: Check ADB install/install-multiple output for details. Common issues: signature, ABI, min SDK."
      echo "ADB Install Output:"
      echo "$INSTALL_OUTPUT"
      cleanup_temp_dir $TEMP_APK_DIR
      cleanup_temp_dir $TEMP_SPLIT_APK_DIR
      exit 1
    fi
    echo "Info: APK installed successfully."

    if [ "$FILE_TYPE" == "BUNDLE" ]; then
        cleanup_temp_dir $TEMP_SPLIT_APK_DIR
    fi
}

# --- Function: Extract package name of the app ---
get_package_name(){
    echo "Info: Retrieving package name from APK using bundletool..."

    AAPT_OUTPUT=$(aapt dump badging "$TEMP_APK_DIR")
    PACKAGE_NAME=$(echo "$AAPT_OUTPUT" | awk '/package:/ {print $2}' | sed "s/name='//g" | sed "s/'//g")

    echo "Info: Package name retrieved: $PACKAGE_NAME"
}

# --- Function: Run Frida and Extract Key ---
run_frida_and_extract_key() {
    echo "Info: Starting Frida to hook and capture encryption key..."
    
    local frida_python_script="xxtea_extractor.py"
    local frida_js_hook="cocosdecrypt.js"
    
    source .venv/bin/activate || { echo "Error: Failed to activate virtual environment. Exiting..." >&2; exit 1; }

    # Call the python script and capture its output
    DECRYPTION_KEY=$(python3 "$frida_python_script" \
        "$PACKAGE_NAME" \
        "$DECRYPT_FUNC_ADD" \
        "$frida_js_hook")

    deactivate

    if [ $? -ne 0 ] || [ -z "$DECRYPTION_KEY" ]; then
      echo "Error: Frida key extraction failed or returned an empty key." >&2
      cleanup_temp_dir $TEMP_APK_DIR
      exit 1 
    fi

    echo "Success: Captured Encryption Key: '$DECRYPTION_KEY'"
}

# --- Function: Decrypt all available .jsc files ---
decrypt_jsc_file(){
    echo "Info: Decrypting .jsc files with extracted key..."

    local python_decrypt_script="decrypt.py"
    # local output_path

    source .venv/bin/activate || { echo "Error: Failed to activate virtual environment. Exiting..." >&2; exit 1; }

    for jsc_file in "${JSC_ARRAY[@]}"; do
        python3 "$python_decrypt_script" "$jsc_file" "$DECRYPTION_KEY" "$OUTPUT_PATH"
    done

    cleanup_temp_dir $TEMP_APK_DIR

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

# --- Function: Environment Setup check ---
check_environment_setup(){
    echo "Info: Checking and setting up the environment before running the script..."
    check_cli_tools   
    setup_python_environment       
    check_frida_device 
}

# --- Main Script Logic ---
main() {
    # Ensure temporary directory is cleaned up on script exit (even if errors occur)
    trap cleanup_temp_dir EXIT

    parse_args "$@"    
    check_environment_setup     

    if [ "$FILE_TYPE" == "BUNDLE" ]; then
        handle_and_install_apk_bundle 
    elif [ "$FILE_TYPE" == "APK" ]; then
        handle_apk_file
    fi   
    get_package_name
    run_frida_and_extract_key
    decrypt_jsc_file               

    echo "Success: All steps completed successfully."
}

# --- Call the main function ---
main "$@"