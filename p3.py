from Crypto.Hash import MD5, SHA256, SHA512

# Función para generar el hash de un mensaje utilizando diferentes algoritmos
def generate_hash(message, algorithm='sha256'):
 if algorithm == 'md5':
    hash_obj = MD5.new()
 elif algorithm == 'sha256':
    hash_obj = SHA256.new()
 elif algorithm == 'sha512':
    hash_obj = SHA512.new()
 else:
    raise ValueError("Unsupported algorithm. Use 'md5', 'sha256', or 'sha512'")

 # Codificar el mensaje y generar el hash
 hash_obj.update(message.encode('utf-8'))
 return hash_obj.hexdigest()

# Función para verificar la integridad comparando hashes
def verify_integrity(message, expected_hash, algorithm='sha256'):
 calculated_hash = generate_hash(message, algorithm)
 return calculated_hash == expected_hash

# Probar las funciones de hashing
if __name__ == "__main__":
 message = "This is a test message for hashing"

 # Generar hashes con diferentes algoritmos
 md5_hash = generate_hash(message, 'md5')
 sha256_hash = generate_hash(message, 'sha256')
 sha512_hash = generate_hash(message, 'sha512')

 print(f"MD5 Hash: {md5_hash}")
 print(f"SHA-256 Hash: {sha256_hash}")
 print(f"SHA-512 Hash: {sha512_hash}")

 # Verificar la integridad de los datos
 original_message = "This is a test message for hashing modified 2"
 altered_message = "This is a modified message"

 is_valid = verify_integrity(original_message, sha256_hash, 'sha256')
 print(f"Integrity check passed: {is_valid}")

 # Intentar verificar con un mensaje alterado
 is_valid_altered = verify_integrity(altered_message, sha256_hash, 'sha256')
 print(f"Integrity check passed (altered message): {is_valid_altered}")