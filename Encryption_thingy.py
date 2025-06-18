from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
from cryptography import x509
import os



base_path = "/Users/quinnesser/Documents/"

filename = input("Please enter file name here:").strip()


def Asymetric_Encryption(input_path, output_path, cert_path="cert.txt"):
    # Load the certificate
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        public_key = cert.public_key()

    symmetric_key = Fernet.generate_key()
    fernet = Fernet(symmetric_key)

    # Encrypt the data using the symmetric key
    with open(input_path, "rb") as file:
        data = file.read()
        encrypted_data = fernet.encrypt(data)

    # Encrypt the symmetric key using the public key
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save encrypted data + encrypted key as a JSON object
    wrapper = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8")
    }

    with open(output_path, "w") as f:
        json.dump(wrapper, f)


def Asymetric_Decryption(input_path, output_path, key_path = "key.txt"):
    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Load encrypted key + data
    with open(input_path, "r") as f:
        wrapper = json.load(f)

    encrypted_key = base64.b64decode(wrapper["encrypted_key"])
    encrypted_data = base64.b64decode(wrapper["encrypted_data"])


    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    fernet = Fernet(symmetric_key)
    decrypted = fernet.decrypt(encrypted_data)

    with open(output_path, "wb") as f:
        f.write(decrypted)









if __name__ == "__main__":
    try:



        input_path = os.path.join(base_path, filename)
        if not os.path.isfile(input_path):
            print("The specified file does not exist.")
            exit()


        output_path = input("Enter output file path (leave blank to overwrite the original): ").strip()
        if output_path == "":
            output_path = input_path


            cert_or_key = input("Press E for encyption or D for decyption: ").strip().upper()
            if cert_or_key == "E":
              Asymetric_Encryption(input_path, output_path)
              print("File encrypted using public certificate!")
            elif cert_or_key == "D":
                Asymetric_Decryption(input_path, output_path)
                print("File decrypted using private key!")

        else:
            Decrypt(key, input_path, output_path)
            print(f"File decrypted successfully and saved to {output_path}")

    except Exception as e:
        print(f"An error occurred: {e}")
