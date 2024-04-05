from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64, os, json

class cypher():
	def GetmasterKey(home_path, senha_usuario):
		with open(f"{home_path}.dchat-server/keys/keys.json", 'r') as file:
			jsonkeys = json.load(file)
			master_key = base64.b64decode(jsonkeys["mkey"])
			iv = base64.b64decode(jsonkeys["ikey"])
			sal = base64.b64decode(jsonkeys["skey"])

		kdf = PBKDF2HMAC(
		    algorithm=hashes.SHA256(),
		    length=32,
		    salt=sal,
		    iterations=100000,
		    backend=default_backend()
		)

		chave_derivada = kdf.derive(senha_usuario.encode())

		cipher = Cipher(algorithms.AES(chave_derivada), modes.CBC(iv), backend=default_backend())
		decryptor = cipher.decryptor()

		chave_mestra_aes_descriptografada = decryptor.update(master_key) + decryptor.finalize()
		return chave_mestra_aes_descriptografada, iv

	def GenAESkey(senha_usuario, home_path):
		sal = os.urandom(16)  # Sal aleatório para PBKDF2

		kdf = PBKDF2HMAC(
		    algorithm=hashes.SHA256(),
		    length=32,  # Tamanho da chave para AES-256
		    salt=sal,
		    iterations=100000,
		    backend=default_backend()
		)

		chave_derivada = kdf.derive(senha_usuario.encode())

		chave_mestra_aes = os.urandom(32)  # Chave mestra AES-256 aleatória
		iv = os.urandom(16)  # Vetor de inicialização para AES

		cipher = Cipher(algorithms.AES(chave_derivada), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		chave_mestra_aes_criptografada = encryptor.update(chave_mestra_aes) + encryptor.finalize()


		chave_b64 = base64.b64encode(chave_mestra_aes_criptografada).decode('utf-8')
		salt_b64 = base64.b64encode(sal).decode('utf-8')
		iv_b64 = base64.b64encode(iv).decode('utf-8')

		keyjson = {
			"mkey":chave_b64,
			"skey":salt_b64,
			"ikey":iv_b64
		}

		with open(f"{home_path}.dchat-server/keys/keys.json", 'w') as file:
			json.dump(keyjson, file, indent=4)


	def encryptAES(self, plaintext, key, iv):
		if len(key) != 32 or len(iv) != 16:
			raise ValueError("A chave deve ter 32 bytes e o iv 16 bytes.")

		padder = padding.PKCS7(algorithms.AES.block_size).padder()
		padded_plaintext = padder.update(plaintext) + padder.finalize()
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()

		# Criptografa o texto plano
		ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
		return ciphertext

	def decryptAES(self, ciphertext, key, iv):
		if len(key) != 32 or len(iv) != 16:
			raise ValueError("A chave deve ter 32 bytes e o iv 16 bytes.")

		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
		decryptor = cipher.decryptor()
		padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
		unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

		# Descriptografa conteudo
		plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
		return plaintext

	def GenKey(self, home_path, aes_key, iv):
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=4096,
			backend=default_backend()
		)

		public_key = private_key.public_key()

		private_key_pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)

		public_key_pem = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		with open(f'{home_path}.dchat-server/keys/private_key.pem', 'wb') as f:
			f.write(self.encryptAES(private_key_pem, aes_key, iv))
			print ("[!] Chave publica criada")

		with open(f'{home_path}.dchat-server/keys/public_key.pem', 'wb') as f:
			f.write(public_key_pem)
			print ("[!] Chave privada criptograda criada")


		return private_key_pem, public_key_pem

	def GetKeys(self, home_path, aes_key, iv):
		with open(f'{home_path}.dchat-server/keys/private_key.pem', 'rb') as f:
			try:
				private_key_pem = self.decryptAES(f.read(), aes_key, iv).decode("UTF-8")
			except:
				private_key_pem = False

		with open(f'{home_path}.dchat-server/keys/public_key.pem', 'r') as f:
			public_key_pem = f.read()

		return private_key_pem, public_key_pem



	def DecodeRSA(encrypted_data, private_key):
		from cryptography.hazmat.primitives.asymmetric import padding

		private_key = serialization.load_pem_private_key(
		    private_key.encode(),
		    password=None,
		    backend=default_backend()
		)

		original_message = private_key.decrypt(
		    encrypted_data,
		    padding.OAEP(
		        mgf=padding.MGF1(algorithm=hashes.SHA256()),
		        algorithm=hashes.SHA256(),
		        label=None
		    )
		)

		return original_message


	def EncodeRSA(data, public_key):
		from cryptography.hazmat.primitives.asymmetric import padding


		public_key = serialization.load_pem_public_key(
		    public_key.encode(),
		    backend=default_backend()
		)

		message = data.encode()

		encrypted = public_key.encrypt(
		    message,
		    padding.OAEP(
		        mgf=padding.MGF1(algorithm=hashes.SHA256()),
		        algorithm=hashes.SHA256(),
		        label=None
		    )
		)

		return encrypted
