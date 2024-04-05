import os, getpass
from pyCypher import cypher

class run:
	def checkInstall():
		home_path = os.path.expanduser('~')
		if home_path[-1:] != "/":
			home_path = f"{home_path}/"

		if os.path.isdir(f"{home_path}.dchat-server") == False:
			print ("[!] Iniciando processo de instalação")
			os.mkdir(f"{home_path}.dchat-server")

		if os.path.isdir(f"{home_path}.dchat-server/keys") == False:
			print ("[!] Iniciando processo de geração de chaves")
			os.mkdir(f"{home_path}.dchat-server/keys")

		if os.path.isfile(f"{home_path}.dchat-server/keys/keys.json") == False:
			print ("[!] Criando chave mestra")
			while True:
				passwd = getpass.getpass("Cria uma senha: ")
				confpw = getpass.getpass("Confirme a senha: ")
				if passwd != confpw:
					print ("As senhas não combinam")
					continue

				cypher.GenAESkey(passwd, home_path)
				print ("Chave mestra criada")
				break

			mkey, iv = cypher.GetmasterKey(home_path, passwd)
		else:
			passwd = getpass.getpass("Digite sua senha: ")
			mkey, iv = cypher.GetmasterKey(home_path, passwd)

		if os.path.isfile(f"{home_path}.dchat-server/keys/private_key.pem") == False or os.path.isfile(f'{home_path}.dchat-server/keys/public_key.pem') == False:
			private_key, public_key = cypher().GenKey(home_path, mkey, iv)
		else:
			while True:
				private_key, public_key = cypher().GetKeys(home_path, mkey, iv)
				if private_key == False:
					print ("Senha incorreta")
					passwd = getpass.getpass("Digite sua senha: ")
					mkey, iv = cypher.GetmasterKey(home_path, passwd)
				else:
					break

		return private_key, public_key
