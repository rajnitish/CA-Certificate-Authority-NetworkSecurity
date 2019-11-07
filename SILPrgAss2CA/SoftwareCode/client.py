#!/usr/bin/python

import socket
import sys
import time
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random


print("Set Connection Parameters")
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = socket.gethostname()
port = int(sys.argv[1])
client_id = sys.argv[2]

while True:
	print("Client ID: " + client_id)
	print("--------------------------------------------")
	print("Choose Operation :\n (1) Get CA Certificate \n (2) Send Hello Msg to Client \n (3) Receive Hello Msg from client")
	print(" (4) Send ACK Msg to Client \n (5) Receive ACK Msg from client")
	
	inp = input()
	if (int(inp) == 1):
		print("Generate Certificate")
		server_port = port - int(client_id)
		mysoc = socket.socket()
		mysoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		mysoc.connect((host, server_port))
		print("Read Public Key for server and client")
		f = open('./server_key.pub', 'rb')
		server_bin_pub_key = f.read()
		f = open('.//client' + client_id + '/key' + client_id + '.pub', 'rb')
		client_bin_pub_key = f.read()
		msg = client_id + '_' + str(client_bin_pub_key)
		print("RSA Encryption using Public Key for server and client ")
		server_pub_key_obj = RSA.importKey(server_bin_pub_key)
		msg_hash = hashlib.sha512(msg).hexdigest()
		emsg = server_pub_key_obj.encrypt(msg_hash, 'x')[0]
		mysoc.sendall(client_id)
		mysoc.close 
		time.sleep(3)
		mysoc = socket.socket()
		mysoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		mysoc.connect((host, server_port))
		mysoc.sendall(emsg)
		data = mysoc.recv(1024)
		data = data.decode('utf-8').split('_')

		with open("./client" + client_id + "/certificate" + client_id + ".txt", "wb") as cert_file:
			cert_file.write("Time of issuance: " + data[0] + "\n")
			cert_file.write("ID: " + client_id + "\n")
			cert_file.write("Key:\n")
			cert_file.write(str(client_bin_pub_key))
			cert_file.write("CA Signature: " + data[1] + "\n")
		mysoc.close
		print("Certificate saved!\n")
	elif (int(inp) == 2):
		#Send hello
		recv_id = input("Enter Client ID: ")
		mysoc = socket.socket()
		mysoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		mysoc.connect((host, port - int(client_id) + int(recv_id)))
		mysoc.sendall(client_id)
		recv_certificate = mysoc.recv(2048)
		recv_certificate = recv_certificate.decode('utf-8').split('\n')
		l = len(recv_certificate)
		recv_time = recv_certificate[0]
		recv_time = recv_time.split(": ")
		recv_time = recv_time[1].replace("\n", "")
		recv_id = recv_certificate[1]
		recv_id = recv_id.split(": ")
		recv_id = recv_id[1]
		recv_pub_key = recv_certificate[3] + "\n"
		for i in range(4, l-2):
			recv_pub_key = recv_pub_key + recv_certificate[i] + "\n"
		recv_sig = recv_certificate[l-2]
		recv_sig = recv_sig.split(": ")
		recv_sig = recv_sig[1]
		pub_f = open('./server_key.pub', 'rb')
 		ca_pub_key = pub_f.read()
 		ca_pub_key_obj = RSA.importKey(ca_pub_key)
 		recv_hash = hashlib.sha512(recv_id + "_" + str(recv_pub_key) + "_" + recv_time).digest()
 		recv_sig = eval(recv_sig)
 		if(ca_pub_key_obj.verify(recv_hash, recv_sig)):
 			print("Certificate verified!")
 			mysoc.close
			time.sleep(3)
			mysoc = socket.socket()
			mysoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			mysoc.connect((host, port - int(client_id) + int(recv_id)))
			msg = "hello" + client_id
			recv_pub_key_obj = RSA.importKey(recv_pub_key)
			emsg = recv_pub_key_obj.encrypt(msg, 'x')[0]
			mysoc.sendall(emsg)
			mysoc.close
			print("Sent message to client " + recv_id + "\n")
			time.sleep(1)
 		else:
 			print("Invalid certificate!\n")
 			mysoc.close
 			time.sleep(1)


	elif (int(inp) == 3):
		#receive hello
		
		mysoc = socket.socket()
		mysoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		mysoc.bind((host, port))
		mysoc.listen(5)
		c, addr = mysoc.accept()
		recv_client_id = c.recv(1024)
		f = open("./client" + client_id + "/certificate" + client_id + ".txt" ,"rb")
		msg = f.read()
		c.send(msg)
		c.close()
		c, addr = mysoc.accept()
		recv_emsg = c.recv(1024)
		f = open("./client" + client_id + "/key" + client_id + '.pem', 'rb')
		priv_key = f.read()
		priv_key_obj = RSA.importKey(priv_key)
		recv_msg = priv_key_obj.decrypt(recv_emsg)
		print("Message received from client " + recv_client_id + ": " + recv_msg + "\n")
		mysoc.close
	elif (int(inp) == 4):
		#Send ACK
		recv_id = input("Enter Client ID: ")
		mysoc = socket.socket()
		mysoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		mysoc.connect((host, port - int(client_id) + int(recv_id)))
		mysoc.sendall(client_id)
		recv_certificate = mysoc.recv(2048)
		recv_certificate = recv_certificate.decode('utf-8').split('\n')
		l = len(recv_certificate)
		recv_time = recv_certificate[0]
		recv_time = recv_time.split(": ")
		recv_time = recv_time[1].replace("\n", "")
		recv_id = recv_certificate[1]
		recv_id = recv_id.split(": ")
		recv_id = recv_id[1]
		recv_pub_key = recv_certificate[3] + "\n"
		for i in range(4, l-2):
			recv_pub_key = recv_pub_key + recv_certificate[i] + "\n"
		recv_sig = recv_certificate[l-2]
		recv_sig = recv_sig.split(": ")
		recv_sig = recv_sig[1]
		pub_f = open('./server_key.pub', 'rb')
 		ca_pub_key = pub_f.read()
 		ca_pub_key_obj = RSA.importKey(ca_pub_key)
 		recv_hash = hashlib.sha512(recv_id + "_" + str(recv_pub_key) + "_" + recv_time).digest()
 		recv_sig = eval(recv_sig)
 		if(ca_pub_key_obj.verify(recv_hash, recv_sig)):
 			print("Certificate verified!")
 			mysoc.close
			time.sleep(3)
			mysoc = socket.socket()
			mysoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			mysoc.connect((host, port - int(client_id) + int(recv_id)))
			msg = "ACK" + client_id
			recv_pub_key_obj = RSA.importKey(recv_pub_key)
			emsg = recv_pub_key_obj.encrypt(msg, 'x')[0]
			mysoc.sendall(emsg)
			mysoc.close
			print("Sent message to client " + recv_id + "\n")
			time.sleep(1)
 		else:
 			print("Invalid certificate!\n")
 			mysoc.close
 			time.sleep(1)


	elif (int(inp) == 5):
		#receive ACK
		mysoc.close
		mysoc = socket.socket()
		mysoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		mysoc.bind((host, port))
		mysoc.listen(5)
		c, addr = mysoc.accept()
		recv_client_id = c.recv(1024)
		f = open("./client" + client_id + "/certificate" + client_id + ".txt" ,"rb")
		msg = f.read()
		c.send(msg)
		c.close()
		c, addr = mysoc.accept()
		recv_emsg = c.recv(1024)
		f = open("./client" + client_id + "/key" + client_id + '.pem', 'rb')
		priv_key = f.read()
		priv_key_obj = RSA.importKey(priv_key)
		recv_msg = priv_key_obj.decrypt(recv_emsg)
		print("ACK Message received from client " + recv_client_id + ": " + recv_msg + "\n")
		mysoc.close



