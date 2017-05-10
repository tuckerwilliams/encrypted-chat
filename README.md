# encrypted-chat
An example of encrypted chat application for a class project in Applied Cryptography. A few functions from a larger project. Not supplied is the skeleton code for the server and client.

These included functions (which handle the crypto system, and as such were enough to share without including the skeleton) provide for:
    message authentication (Bob knows it is Mallory sending the message), 
    message encryption (secure transit of the message using AES-256 in CTR mode), and 
    replay protection (using client-side counters to prevent replay attacks.) 
    
Unfortunately, this implementation does not provide for key freshness.
