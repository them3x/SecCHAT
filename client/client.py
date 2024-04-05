from connections import connection
from checking import run
import threading, os

private_key, public_key = run.checkInstall()
username = "M3X"

#print ("UserName: {username}")


os.environ['chat'] = "0"
os.environ['server'] = "0"
os.environ['inchat'] = "0"
os.environ['stoprcv'] = "0"

print ("> DCHAT MAIN MENU")
while True:
	data = input("")

	if data == "/connect":
		client_thread = threading.Thread(target=connection().server, args=("localhost", 9999, public_key, username, ))
		client_thread.start()

	elif data == " /help":
		print ("""
	USE
/connect > conectar ao servidor
/users   > visualizar usuarios online
/ketKey  > obtem chave de usuario
		""")

	elif data[:5] == "/chat":
		userID = chat.split(" ")[1]
		if os.path.isfile(f"{home_path}.dchat/users/{userID}") == False:
			print ("[!] Você não possui a chave publica este usuario")
		else:
			os.environ['chat'] = data

	else:
		if os.environ.get('server') == "0":
			print ("[!] Não esta conectado com nenhum servidor")
		else:
			os.environ['chat'] = data
