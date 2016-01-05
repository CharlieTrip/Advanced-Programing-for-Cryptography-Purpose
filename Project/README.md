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
	+ Cli-Ser have a *semaphore.txt* for concurrency

+ Both server and client has access to a CA certificate *ca.crt*.  
Only server has a *certificate.crt* of his public key, signed by the CA.


---

+ Use folder to separate the machines:
	+ **Server** : will contain the servers file
	+ **Client** : will contain the client file 
	+ **Common** : will contain the common file to use