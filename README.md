# Monke Encryption for Mirror
 
Monke is a plug and play encrypted transport layer for mirror.

Prevent hackers from spying on your monkey business! 


# How to use

1. Add Monke.cs to your NetworkManager object.
2. Drag Monke into the NetworkManager Transport field.
3. Drag the transport you want to use (ie. KCP, Telepathy) into the 'Communication Transport' field in Monke.

# What it does

Monke currently ONLY encrypts outgoing messages and decrypts incoming messages.
It is NOT a full fledged security solution for Mirror.

# Future

Currently I plan to rework the initial key exchange, using RSA and DH.
