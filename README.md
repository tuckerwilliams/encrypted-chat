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

The chatroom creator gets the public encryption keys (RSA) of the users he specified to add to the chat. We access this via JSON, but in a different client/server implementation this could be implemented via calls to the server (as it is safe to store public keys on the server.)

The creator creates a symmetric key (16 random bytes) that will encrypt all messages.

The creator then shares the symmetric key with the chatroom participants, shared by encrypting this key with the respective user's public encryption key (above). This message is signed with the creator's RSA signing key.
