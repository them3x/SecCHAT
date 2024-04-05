from checking import run
from pyCypher import cypher

import socket, json
import threading, time
import hashlib, base64

private_key, public_key = run.checkInstall()


username = "MAINSERVER"

MAX_CLIENTS = 30
current_clients = 0
clientsIDs = {}

def handle_client(client_socket, public_key, private_key):
	def actions(sock, aes_key, aes_iv):
		def recvData(s, aes_key, aes_iv):
			global clientsIDs
			while True:
				data = sock.recv(2048)
				try:
					data = data.decode()
					if data:
						print (data)

				except Exception as e:
#					print (f"[RcvData] {e}\n")
					raw_data = json.loads(cypher().decryptAES(data, aes_key, aes_iv).decode())
					action = raw_data["action"]

					if action == "list-users":
						clients = {}
						for id in clientsIDs:
							nick = clientsIDs[id]['username']
							clients[id] = nick

						json_users = {"action":"list-users", "users":clients}
						json_data = json.dumps(json_users)

					elif action == "getPublicKey":
						userID = raw_data["user_id"]
						if userID in clientsIDs:
							publicKey = clientsIDs[userID]['public_key']
							json_data = json.dumps({"action":"savePublicKey", "public_key":publicKey, "user_id": userID})
						else:
							json_data = json.dumps({"action":"alert", "text":"User is Offline or dont exist"})

					data = cypher().encryptAES(json_data.encode(), aes_key, aes_iv)
					s.send(data)

		def sendData(s, aes_key, aes_iv):
			while True:
				try:
					time.sleep(3)
				except Exception as e:
					print (f"[SndData] {e}\n")
					break

		thread_receber = threading.Thread(target=recvData, args=(sock, aes_key, aes_iv,))
		thread_receber.start()

		thread_enviar = threading.Thread(target=sendData, args=(sock, aes_key, aes_iv,))
		thread_enviar.start()

		thread_enviar.join()
		sock.close()


	global current_clients, clientsIDs
	try:
		handshake = json.dumps({"server":True, "public_key":public_key})
		client_socket.send(handshake.encode('utf-8'))
		try:
			response_hshake = json.loads(client_socket.recv(2048).decode('utf-8'))
		except json.decoder.JSONDecodeError:
			print ("[HandShake] Cliente retornou algo inesperado")
			client_socket.close()
			with clients_count_lock:
				current_clients -= 1

			return 0

		user_data_enc = base64.b64decode(response_hshake['client']) # Cifrado com AES
		aesk_data_enc = base64.b64decode(response_hshake['cypher']) # Cifrado com Chave publica RSA

		aes_data = json.loads(cypher.DecodeRSA(aesk_data_enc, private_key))
		aes_key = base64.b64decode(aes_data["aes"])
		aes_iv = base64.b64decode(aes_data["iv"])

		user_data = json.loads(cypher().decryptAES(user_data_enc, aes_key, aes_iv).decode("utf-8"))

		hash_obj = hashlib.sha256(user_data['public_key'].encode())
		clientID = hash_obj.hexdigest()

		# Salva ID do usuario e chave publica
		clientsIDs[clientID] = user_data
		client_socket.send("ok".encode())

		actions(client_socket, aes_key, aes_iv)

	finally:
		client_socket.close()
		with clients_count_lock:
			current_clients -= 1

def start_server(host, port):
	global current_clients, clientsIDs
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((host, port))
	server.listen(5)  # O servidor escuta por conexões
	print(f"Servidor escutando em {host}:{port}")

	while True:
		if current_clients < MAX_CLIENTS:
			client_socket, addr = server.accept()  # Aceita uma conexão de cliente
			print(f"Conexão aceita de {addr}")

			client_thread = threading.Thread(target=handle_client, args=(client_socket,public_key,private_key, ))
			client_thread.start()

			with clients_count_lock:
				current_clients += 1
		else:
			print("Máximo de clientes atingido. Aguardando a liberação de conexões...")


clients_count_lock = threading.Lock()
if __name__ == "__main__":
	start_server('localhost', 9999)
