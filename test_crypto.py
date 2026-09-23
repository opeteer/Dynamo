import os
import shutil
import crypto_utils
from datetime import datetime

test_dir = "/tmp/dynamo_test"
if os.path.exists(test_dir):
    shutil.rmtree(test_dir)

print("1. Init Vault")
success = crypto_utils.init_vault("super_secret", test_dir)
print(f"Init success: {success}")

print("2. Unlock Vault")
vk = crypto_utils.unlock_vault("super_secret", test_dir)
print(f"Unlock success: {vk is not None}")

print("3. Write Manifest")
manifest = crypto_utils.read_manifest(vk, test_dir)
manifest["files"]["test_id"] = {"name": "test.txt", "uuid": "uuid_test"}
crypto_utils.write_manifest(manifest, vk, test_dir)

print("4. Read Manifest")
manifest2 = crypto_utils.read_manifest(vk, test_dir)
print(f"Manifest read success: {'test_id' in manifest2['files']}")

print("5. Test stream encryption")
os.makedirs(os.path.join(test_dir, "files"), exist_ok=True)
dest_path = os.path.join(test_dir, "files", "uuid_test")

def stream_gen():
    yield b"Hello World!"
    yield b" This is a test."

crypto_utils.encrypt_stream(vk, stream_gen(), dest_path)
print(f"File created: {os.path.exists(dest_path)}")

print("6. Test stream decryption")
decrypted = b"".join(crypto_utils.decrypt_stream(vk, dest_path))
print(f"Decrypted: {decrypted.decode()}")

print("7. Test Shuffling")
crypto_utils.execute_shuffle(test_dir, vk)
manifest3 = crypto_utils.read_manifest(vk, test_dir)
new_uuid = manifest3["files"]["test_id"]["uuid"]
print(f"Shuffled old UUID to: {new_uuid}")
print(f"Old file exists: {os.path.exists(dest_path)}")
print(f"New file exists: {os.path.exists(os.path.join(test_dir, 'files', new_uuid))}")

print("8. Test Crypto Shred")
crypto_utils.crypto_shred_dir(test_dir)
print(f"Test dir empty/gone: {not os.path.exists(test_dir) or len(os.listdir(test_dir)) == 0}")

