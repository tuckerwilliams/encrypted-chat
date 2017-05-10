# encrypted-chat

## Overview
An example of encrypted chat application for a class project in Applied Cryptography. A few functions from a larger project. Not supplied is the skeleton code for the server and client.

These included functions (which handle the crypto system, and as such were enough to share without including the skeleton) provide for:
    
    - message authentication (Bob knows it is Alice sending the message), 
    - message encryption (secure transit of the message using AES-256 in CTR mode), and 
    - replay protection (using client-side counters to prevent replay attacks.) 
    
Unfortunately, this implementation does not provide for key freshness.

## Specifics of the protocol

There are two main goals in this message protocol:

    1. Key Exchange
    2. Message send and receive (with sign/verify, encrypt/decrypt, 
    
### Key Exchange

    1. The chatroom creator gets the public RSA encryption keys of the users he specified upon creation. (We access this via JSON, but in a different client/server implementation this could be implemented via calls to the server (as it is safe to store public keys on the server.))

    2. The creator creates a symmetric key (16 random bytes) that will encrypt all messages.

    3. The creator then shares the symmetric key with the chatroom participants, shared by encrypting this key with the respective user's public encryption key (above). This message is signed with the creator's RSA signing key.
    
    4. The participants in the chat check the digital signature attached to the key exchange message. If it matches the supposed sender_id (included in the message), then use that person's public RSA encryption key to decrypt and key the symmetric key.
    
### Message send / receive

Based on our JSON-formatted message, we check three things before accepting a message and decrypting:

    1. User ID. If the user ID of the message being received isn't in the chatroom conversation, don't accept. (Do this check first because it is computationally cheaper than verifying signature.)
    2. Signature. If the signature does not verify to the userID reported as the message sender, drop the message.
    3. Message counter. If the counter is less than the message counter the receiving user currently has on file for the sender, drop the message.
    4. Otherwise, accept and decrypt.
