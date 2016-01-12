# Implementation Rules
---

+ Messages are coded in the channel (a.k.a. the file) as 

		 
		Content Type - Message Type \n
		Message \n
		

+ Both server and client must have a personal file to save the log of all the messages exchanged.   
This will be used for the final check of the protocol (hmac of all the messages).  
So
	+ Client has a *client.txt* locally
	+ Server has a *server.txt* locally
	+ Cli-Ser have a *channel.txt* for communication
	+ Cli-Ser have two semaphores *ok_client.txt* and *ok_server.txt* for concurrency

+ Both server and client has access to a CA certificate *ca.crt*.  
Only server has a *certificate.crt* of his public key, signed by the CA.


---

+ Use folder to separate the machines:
	+ **Server** : will contain the servers file
	+ **Client** : will contain the client file 
	+ **Common** : will contain the common file to use


---

+ REMEMBER (ALE) fix the max length of the string

+ REMEMBER concordare se scrivere anche un numero per ogni comunicazione oppure no


-> il problema principale di lettura è scrittura è capire come aprire il file, cioè se lo apro in modalità lettura "r", anche se uso "r+", da problemi se poi ci voglio scrivere sopra e viceversa. E' probabile che in un solo stato il channel vada aperto due volte prima per leggerlo e poi per scriverci su








