from message import Message
from time import sleep
from threading import Thread
from Crypto.PublicKey import RSA as RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
import sys
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64
import hashlib
import json
import os
import sys
import random
import struct

class Conversation:
    '''
    Represents a conversation between participants
    '''
    def __init__(self, c_id, manager):
        '''
        Constructor
        :param c_id: ID of the conversation (integer)
        :param manager: instance of the ChatManager class
        :return: None
        '''
        self.id = c_id  # ID of the conversation
        self.all_messages = []  # all retrieved messages of the conversation
        self.printed_messages = []
        self.last_processed_msg_id = 0  # ID of the last processed message
        from chat_manager import ChatManager
        assert isinstance(manager, ChatManager)
        self.manager = manager # chat manager for sending messages
        self.run_infinite_loop = True
        self.msg_process_loop = Thread(
            target=self.process_all_messages
        ) # message processing loop
        self.msg_process_loop.start()
        self.msg_process_loop_started = True

    def append_msg_to_process(self, msg_json):
        '''
        Append a message to the list of all retrieved messages

        :param msg_json: the message in JSON encoding
        :return:
        '''
        self.all_messages.append(msg_json)

    def append_msg_to_printed_msgs(self, msg):
        '''
        Append a message to the list of printed messages

        :param msg: an instance of the Message class
        :return:
        '''
        assert isinstance(msg, Message)
        self.printed_messages.append(msg)

    def exit(self):
        '''
        Called when the application exists, breaks the infinite loop of message processing

        :return:
        '''
        self.run_infinite_loop = False
        if self.msg_process_loop_started == True:
            self.msg_process_loop.join()

    def process_all_messages(self):
        '''
        An (almost) infinite loop, that iterates over all the messages received from the server
        and passes them for processing

        The loop is broken when the application is exiting
        :return:
        '''
        while self.run_infinite_loop:
            for i in range(0, len(self.all_messages)):
                current_msg = self.all_messages[i]
                msg_raw = ""
                msg_id = 0
                owner_str = ""
                try:
                    # Get raw data of the message from JSON document representing the message
                    msg_raw = base64.decodestring(current_msg["content"])
                    # Base64 decode message
                    msg_id = int(current_msg["message_id"])
                    # Get the name of the user who sent the message
                    owner_str = current_msg["owner"]
                except KeyError as e:
                    print "Received JSON does not hold a message"
                    continue
                except ValueError as e:
                    print "Message ID is not a valid number:", current_msg["message_id"]
                    continue
                if msg_id > self.last_processed_msg_id:
                    # If the message has not been processed before, process it
                    self.process_incoming_message(msg_raw=msg_raw,
                                                  msg_id=msg_id,
                                                  owner_str=owner_str)
                    # Update the ID of the last processed message to the current
                    self.last_processed_msg_id = msg_id
                sleep(0.01)

    def setup_conversation(self):
        '''
        Prepares the conversation for usage
        :return:
        '''
        # You can use this function to initiate your key exchange
        # Useful stuff that you may need:
        # - name of the current user: self.manager.user_name
        # - list of other users in the converstaion: list_of_users = self.manager.get_other_users()
        # - cretor of conversation: creator = self.manager.get_conversation_creator()
        # You may need to send some init message from this point of your code
        # you can do that with self.process_outgoing_message("...") or whatever you may want to send here...

        # if user is not the creator, no need to generate key
        if (self.manager.user_name != self.manager.get_conversation_creator()):
            return

        user_file = self.get_json_of_user(self.manager.user_name)
        if user_file == None:
            return

        # if user is creator but key has already been created, no need to create it again
        with open(user_file) as user_data:
            user_info = json.loads(user_data.read())
            if str(self.id) in user_info['conversation_counter']:
                return

        symmetric_key = Random.new().read(16)
        encrypted_symmetric_keys = {}

        # set symmetric key in creator's file
        with open(user_file) as user_data:
            user_info["symmetric_key"].update({ str(self.id) : symmetric_key })
        with open(user_file, 'w') as user_data:
            json.dump(user_info, user_data, encoding='latin1')

        # iterate over files in current directory to get the public keys for encryption
        for user in self.manager.get_other_users():
            user_file = self.get_json_of_user(user)
            if user_file == None:
                return

            with open(user_file) as user_data:
                user_info = json.loads(user_data.read())
                
                public_key_enc = RSA.importKey(user_info["public_key_enc"])
                private_key_sign = RSA.importKey(user_info["private_key_sign"])
                encrypted_symmetric_key = public_key_enc.encrypt(symmetric_key, None)[0]
                encrypted_symmetric_keys[user] = encrypted_symmetric_key

        init_message = json.dumps(encrypted_symmetric_keys, encoding='latin1')
        self.process_outgoing_message(init_message, False)

    def process_incoming_message(self, msg_raw, msg_id, owner_str):
        '''
        Process incoming messages
        :param msg_raw: the raw message
        :param msg_id: ID of the message
        :param owner_str: user name of the user who posted the message
        :param user_name: name of the current user
        :param print_all: is the message part of the conversation history?
        :return: None
        '''

        if (owner_str == self.manager.user_name):
           return

        decoded_msg = base64.decodestring(msg_raw)
        msg_info = json.loads(decoded_msg)

        # check if sender is valid user from the chatroom
        reported_sender_id = msg_info['sender_id'].encode('latin1')
        if (reported_sender_id not in self.manager.get_other_users()):
            print 'Error for incoming message: sender ' + reported_sender_id + ' is not a member of chatroom ' + str(self.id)
            return
        
        sender_file = self.get_json_of_user(str(reported_sender_id))
        sender_public_key_sign = None
        if sender_file == None:
            return
        with open(sender_file) as sender_data:
            sender_info = json.loads(sender_data.read())
            sender_public_key_sign = RSA.importKey(sender_info['public_key_sign'])

        init_message = True if msg_info['initialization'] == 1 else False
        reported_msg_counter = msg_info['msg_counter']
        payload = msg_info['payload'].encode('latin1')
        signature = msg_info['signature'].encode('latin1')

        dir_path = os.path.dirname(os.path.realpath(__file__))
        user_file = self.get_json_of_user(self.manager.user_name)
        if user_file == None:
            return

        message = None
        with open(user_file) as user_data:
            user_info = json.loads(user_data.read())

            # if INITIALIZATION message
            if init_message:
                # write symmetric key
                private_key_enc = RSA.importKey(user_info["private_key_enc"])
                init_msg = json.loads(payload)
                decrypted_symmetric_key = private_key_enc.decrypt(init_msg[self.manager.user_name].encode('latin1'))
                user_info['symmetric_key'].update({ str(self.id) : decrypted_symmetric_key })

                # create message here and check signature of it
                message = str(1) + str(reported_msg_counter) + str(reported_sender_id) + payload
                signer = PKCS1_v1_5.new(sender_public_key_sign )
                digest = SHA256.new()
                digest.update(message)
                if (not signer.verify(digest, signature)):
                    print 'Error for incoming message: signatures do not match'
                    return


                # write counters
                user_info['conversation_counter'].update({ str(self.id) : {self.manager.user_name: 0}})
                for other_user in self.manager.get_other_users():
                    user_info['conversation_counter'][str(self.id)][other_user] = 0
                user_info['conversation_counter'][str(self.id)][self.manager.get_conversation_creator()] = 1

            # else NORMAL CHAT MESSAGE
            else:
                symmetric_key = user_info['symmetric_key'][str(self.id)].encode('latin1')
                iv = msg_info['iv'].encode('latin1')
                ivhex = iv.encode('hex')
                ctr = Counter.new(128, initial_value = long(ivhex, 16))
                cipher = AES.new(symmetric_key, AES.MODE_CTR, counter = ctr)
                decrypted_msg = cipher.decrypt(payload)
                
                # check if data length matches
                reported_data_length = msg_info['data_length']
                if (reported_data_length != len(decrypted_msg)):
                    print 'Error for incoming message: reported data length is ' + str(reported_data_length) + \
                            ' but actual data length is ' + str(len(decrypted_msg))
                    return

                curr = user_info['conversation_counter'][str(self.id)][owner_str]
                # check msg_counter
                if (reported_msg_counter <= curr):
                    print 'Error in incoming message: reported_msg_counter (' + str(reported_msg_counter) + \
                            ') is smaller than or equal to counter stored locally (' + str(curr) + ')'
                    return

                # create message here and check signature of it
                message = str(0) + str(len(decrypted_msg)) + str(reported_msg_counter) + str(reported_sender_id) \
                        + unicode(str(iv), errors='ignore') + unicode(payload, errors='ignore')
                signer = PKCS1_v1_5.new(sender_public_key_sign )
                digest = SHA256.new()
                digest.update(message)
                if (not signer.verify(digest, signature)):
                    print 'Error for incoming message: signatures do not match'
                    return

                # update counter
                user_info['conversation_counter'][str(self.id)][owner_str] = curr + 1

        # write and close
        with open(user_file, 'w') as user_data:
            json.dump(user_info, user_data, encoding='latin1')

        if (not init_message):
            # print message and add it to the list of printed messages
            self.print_message(
                msg_raw=decrypted_msg,
                owner_str=owner_str
            )

    def process_outgoing_message(self, msg_raw, originates_from_console=False):
        '''
        Process an outgoing message before Base64 encoding

        :param msg_raw: raw message
        :return: message to be sent to the server
        '''

        msg_type = 0
        my_counter = 0
        symmetric_key = None
        msg = None
        message = None
        msg_structure = {}
        private_sign_key = None

        # update message counters
        user_file = self.get_json_of_user(self.manager.user_name)
        if user_file == None:
            return
        with open(user_file) as user_data:

            user_info = json.loads(user_data.read())
            private_sig_key = RSA.importKey(user_info["private_key_sign"])

            # if INITIALIZATION message
            if (not originates_from_console):
                user_info['conversation_counter'].update( {str(self.id) : {self.manager.user_name : 1}} )
                for other_user in self.manager.get_other_users():
                    user_info['conversation_counter'][str(self.id)][other_user] = 0
                my_counter = 1

                msg_structure['initialization'] = 1
                msg_structure['msg_counter'] = my_counter
                msg_structure['sender_id'] = self.manager.user_name
                msg_structure['payload'] = msg_raw

                # create message to sign
                message = str(1) + str(my_counter) + self.manager.user_name + msg_raw

            # else NORMAL MESSAGE
            else:
                msg_type = 1
                symmetric_key = user_info["symmetric_key"][str(self.id)].encode('latin1')
                curr = user_info['conversation_counter'][str(self.id)][self.manager.user_name]
                my_counter = curr + 1
                user_info['conversation_counter'][str(self.id)][self.manager.user_name] = my_counter
                

                # AES.CTR encryption for payload
                iv = Random.new().read(16)
                ivhex = iv.encode('hex')
                ctr = Counter.new(128, initial_value = long(ivhex, 16))
                cipher = AES.new(symmetric_key, AES.MODE_CTR, counter = ctr)
                payload = cipher.encrypt(msg_raw)
                
                msg_structure['initialization'] = 0
                msg_structure['data_length'] = len(msg_raw)
                msg_structure['msg_counter'] = my_counter
                msg_structure['sender_id'] = self.manager.user_name
                msg_structure['iv'] = iv
                msg_structure['payload'] = payload

                # create message to sign
                message = str(0) + str(len(msg_raw)) + str(my_counter) + self.manager.user_name \
                        + unicode(str(iv), errors='ignore') + unicode(payload, errors='ignore')

            # write and close
            with open(user_file, 'w') as user_data:
                    json.dump(user_info, user_data, encoding='latin1')

            # PKCS1 PSS Signature of the SHA-256 hash of concatenated message
            signer = PKCS1_v1_5.new(private_sig_key)
            digest = SHA256.new()
            digest.update(message)
            signature = signer.sign(digest)

            msg_structure['signature'] = signature
            msg = json.dumps(msg_structure, encoding='latin1')

        # if the message has been typed into the console, record it, so it is never printed again during chatting
        if (originates_from_console):
            # message is already seen on the console
            m = Message(
                owner_name=self.manager.user_name,
                content=msg_raw
            )
            self.printed_messages.append(m)

        encoded_msg = base64.encodestring(msg) #WITHOUT PROTOCOL

        # post the message to the conversation
        self.manager.post_message_to_conversation(encoded_msg)


    def get_json_of_user(self, owner_str):

        dir_path = os.path.dirname(os.path.realpath(__file__))
        for filename in os.listdir(dir_path):
            if filename.endswith(".json") and filename.startswith("user_"):
                 with open(filename) as user_data:
                    user_info = json.loads(user_data.read())
                    user_name = user_info["user_name"]

                    if user_name != owner_str:
                        continue
                    else:
                        return filename

        return None

    def print_message(self, msg_raw, owner_str):
        '''
        Prints the message if necessary

        :param msg_raw: the raw message
        :param owner_str: name of the user who posted the message
        :return: None
        '''
        # Create an object out of the message parts
        msg = Message(content=msg_raw,
                      owner_name=owner_str)
        # If it does not originate from the current user or it is part of conversation history, print it
        if msg not in self.printed_messages:
            print msg
            # Append it to the list of printed messages
            self.printed_messages.append(msg)

    def __str__(self):
        '''
        Called when the conversation is printed with the print or str() instructions
        :return: string
        '''
        for msg in self.printed_messages:
            print msg

    def get_id(self):
        '''
        Returns the ID of the conversation
        :return: string
        '''
        return self.id

    def get_last_message_id(self):
        '''
        Returns the ID of the most recent message
        :return: number
        '''
        return len(self.all_messages)
