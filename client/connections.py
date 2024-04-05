import socket, threading
import json, base64
from pyCypher import cypher
from os import urandom, environ, path
import hashlib, time

class connection():
	def actions(self, sock, key, iv, public_key):
		environ['server'] = "1"
		def recvData(s, key, iv, public_key):
			while True:
				if environ.get('stoprcv') = "1":
					continue

				data = sock.recv(2048)
				try:
					data = data.decode()
					if data:
						print (data)
				except Exception as e:
#					print (f"[RcvData] {e}\n")
					json_data = json.loads(cypher().decryptAES(data, key, iv).decode())
					action = json_data['action']
					if action == "list-users":
						hash_obj = hashlib.sha256(public_key.encode())
						myID = hash_obj.hexdigest()

						for id in json_data["users"]:
							if myID == id:
								print (f"> {id} - {json_data['users'][id]}")
							else:
								print (f"{id} - {json_data['users'][id]}")

					elif action == "savePublicKey":
						otherUserPKey = json_data["public_key"]
						userID = json_data["user_id"]
						home_path = environ.get("home_path")

						if path.isfile(f"{home_path}.dchat/users/{userID}") == False:
							with open(f"{home_path}.dchat/users/{userID}", "w") as f:
								f.write(otherUserPKey)
							print (f"[PublicKeyAdd] {userID}")


					elif action == "alert":
						text = json_data["text"]
						print (f"[!] {text}")

		def sendData(s, key, iv):
			while True:
				try:
					chat = environ.get('chat').replace("\n", "")
					if chat == "0":
						s.send("ping".encode())
					else:
						data = False
						if chat[:6] == "/users":
							data = json.dumps({"action":"list-users"})

						elif chat[:7] == "/getKey":
							userID = chat.split(" ")[1]
							data = json.dumps({"action":"getPublicKey", "user_id":userID})

						elif chat[:5] == "/chat":
							userID = chat.split(" ")[1]
							environ['stoprcv']="1"

							data = json.dumps({"action":"handshake-1", "user_id":userID})

						if data != False:
							data = cypher().encryptAES(data.encode('utf-8'), key, iv)
							s.send(data)

						environ['chat'] = "0"

					time.sleep(3)
				except Exception as e:
					print (f"[SndData] {e}\n")
					break

		thread_receber = threading.Thread(target=recvData, args=(sock, key, iv, public_key, ))
		thread_receber.start()

		thread_enviar = threading.Thread(target=sendData, args=(sock, key, iv,))
		thread_enviar.start()

		thread_enviar.join()
		sock.close()
		environ['server'] = "0"

	def server(self, host, port, public_key, username):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, port))

		try:
			data = json.loads(s.recv(1024).decode("UTF-8"))
		except json.decoder.JSONDecodeError:
			print ("SERVIDOR RETORNOU ALGO INESPERADO")

			s.close()
			return 0

		if data["server"]:
			serverPKey = data["public_key"]

			# Cria chave AES para se comunicar com servidor
			key = urandom(32)
			iv = urandom(16)

			data = json.dumps({"username":username, "public_key": public_key})
			enc_client_info = base64.b64encode(cypher().encryptAES(data.encode('utf-8'), key, iv))

			bkey = base64.b64encode(key).decode('utf-8')
			biv = base64.b64encode(iv).decode('utf-8')

			data = json.dumps({"aes":bkey, "iv":biv})
			enc_aes_info = base64.b64encode(cypher.EncodeRSA(data, serverPKey))

			data = {"client":enc_client_info.decode('utf-8'), "cypher":enc_aes_info.decode('utf-8')}
			handshake = json.dumps(data).encode('utf-8')
			s.send(handshake)
			if s.recv(5).decode() == "ok":
				print (f"[!] Conectado com {host}")
				self.actions(s, key, iv, public_key)


