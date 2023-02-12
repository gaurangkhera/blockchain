from hack import db,login_manager
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin
from datetime import datetime
import hashlib as hl
import requests
from urllib.parse import urlparse
import json
from sqlalchemy import func

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String(64),index=True)
    password = db.Column(db.String)
    money = db.Column(db.Integer, default=0)

class Blockchain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chain = db.relationship('Block')
    def __init__(self):
            self.chain = []
            self.transactions = []
            self.create_block(proof = 1, prev_hash = '0')
            self.nodes = set()

    def create_block(self, proof, prev_hash):
            # block = {'index': len(self.chain) + 1,
            #         'timestamp': str(datetime.now()),
            #         'proof': proof,
            #         'prev_hash': prev_hash,
            #         'transactions' : self.transactions}
            block = Block(proof=proof, chain=1,prev_hash=prev_hash, transactions=[])
            db.session.add(block)
            db.session.commit()
            return block

    def get_prev_block(self):
            return self.chain[-1]

    def pow(self, prev_proof):
            new_proof = 1
            check_proof = False
            while check_proof is False:
                hash_operation = hl.sha256(str(new_proof**2 - prev_proof**2).encode()).hexdigest()
                if hash_operation[:4] == '0000':
                    check_proof = True
                else:
                    new_proof += 1
            return new_proof

    def hash(self, block):
            block_content = {'index': block.id,
                             'proof': block.proof,
                             'timestamp': block.timestamp,
                             'prev_hash': block.prev_hash,
                             }
            enc = json.dumps(block_content, sort_keys=True).encode()
            return hl.sha256(enc).hexdigest()

    def validate(self, blk,bc):
            prev_block = bc[0]
            block_index = 1
            for i in range(len(bc)):
                block_index += 1
            while block_index < len(bc):
                block = bc[block_index]
                if block.prev_hash != blk.prev_hash:
                    return False
                prev_proof = prev_block.proof
                proof = block.proof
                hash_operation = hl.sha256(str(proof**2 - prev_proof**2).encode()).hexdigest()
                if hash_operation[:4] != '0000':
                    return False
                prev_block = block
                block_index += 1
            return True
        
    # def transact(self, sender, receiver , amount):
    #         self.transactions.append({'sender' : sender,
    #                                 'receiver' : receiver,
    #                                 'amount' : amount})
    #         prev_block = self.get_prev_block()
    #         return prev_block['index'] + 1

    def add_node(self, address):
            parsed_url = urlparse(address)
            self.nodes.add(parsed_url.netloc)

    def replace_chain(self):
            network = self.nodes
            longest_chain = None
            max_length = len(self.chain)
            for node in network:
                response = requests.get(f'http://{node}/get_chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    if length > max_length and self.is_chain_valid(chain):
                        max_length = length
                        longest_chain = chain
            if longest_chain:
                self.chain =longest_chain
                return True
            return False
        
class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proof = db.Column(db.Integer)
    prev_hash = db.Column(db.String)
    timestamp = db.Column(db.String, server_default=func.now())
    chain = db.Column(db.Integer, db.ForeignKey('blockchain.id'))
    transactions = db.relationship('Transaction')
    
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String)
    receiver = db.Column(db.String)
    amount = db.Column(db.Integer)
    block = db.Column(db.Integer, db.ForeignKey('block.id'))