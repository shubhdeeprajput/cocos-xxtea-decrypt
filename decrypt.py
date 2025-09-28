import xxtea
import zipfile
import os
import sys

# install xxtea-py, cffi, setuptools module using pip3 install <package>
def decrypt_xxtea_to_zip(input_file, key, output_zip, extract_to):
    # Read excrypted file
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt using xxtea
    decrypted_data = xxtea.decrypt(encrypted_data, key.encode('utf-8'))  # convert key to bytes
    if decrypted_data is None:
        print("Decryption failed. Check the key or file format.")
        return
    
    # Write decrypted data to a zip file
    with open(output_zip, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decrypted ZIP written to: {output_zip}")

    # Extract ZIP contents
    try:
        with zipfile.ZipFile(output_zip, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print(f"ZIP extracted to: {extract_to}")
    except zipfile.BadZipFile:
        print("Decrypted file is not a valid ZIP archive.")

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Error: Missing arguments.", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    key = sys.argv[2] # Decrypt Key
    output_zip_path = sys.argv[3]+"/"+input_path[input_path.find("apk-content"):].replace("/","_").replace(".","_")+".zip"
    extract_folder = sys.argv[3]

    os.makedirs(extract_folder, exist_ok=True)
    decrypt_xxtea_to_zip(input_path, key, output_zip_path, extract_folder)
