import json
from flask import Flask, jsonify, request
import requests
from datetime import datetime
import hashlib as hl
from urllib.parse import urlparse
import uuid 

app = Flask(__name__)

class XCBlockChain():
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof = 1, prev_hash = '0')
        self.nodes = set()

    def create_block(self, proof, prev_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.now()),
                 'proof': proof,
                 'prev_hash': prev_hash,
                 'transactions' : self.transactions}
        self.transactions = []
        self.chain.append(block)
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
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hl.sha256(encoded_block).hexdigest()

    def validate(self, chain):
        prev_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['prev_hash'] != self.hash(prev_block):
                return False
            prev_proof = prev_block['proof']
            proof = block['proof']
            hash_operation = hl.sha256(str(proof**2 - prev_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            prev_block = block
            block_index += 1
        return True
    
    def transact(self, sender, receiver , amount):
        self.transactions.append({'sender' : sender,
                                'receiver' : receiver,
                                'amount' : amount})
        prev_block = self.get_prev_block()
        return prev_block['index'] + 1

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
    
node_addr = str(uuid.uuid1()).replace('-', '')
blockchain = XCBlockChain()

@app.route('/mine')
def mine():
    prev_block = blockchain.get_prev_block()
    prev_proof = prev_block['proof']
    proof = blockchain.pow(prev_proof)
    prev_hash = blockchain.hash(prev_block)
    new_block = blockchain.create_block(proof, prev_hash)
    blockchain.transact(sender=node_addr, receiver='{{current_user.username}}', amount=5)
    res = {
        'message': 'block mined successfully.',
        'index': new_block['index'],
        'proof': new_block['proof'],
        'transactions': new_block['transactions']
    }
    return jsonify(res), 200

@app.route('/get', methods=['GET'])
def get_chain():
    res = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(res), 200

@app.route('/validate', methods=['GET'])
def valid():
    valid_ = blockchain.validate(blockchain.chain)
    if valid_:
        res = {
            'message': 'chain valid',
        }
    else:
        res = {
            'message': 'invalid chain'
        }
    return jsonify(res), 200

@app.route('/transact', methods=['GET','POST'])
def transaction():
    file = open('txn.json', 'r')
    json_obj = json.load(file)
    file.close()
    txn_keys = ['sender', 'receiver', 'amount']
    if all(key in json_obj for key in txn_keys):
        index = blockchain.transact(json_obj['sender'], json_obj['receiver'], json_obj['amount'])
        res = {
            "message": 'successful transaction'
        }
        return jsonify(res), 201
    else:
        return 'err'
    
@app.route('/connect', methods=['POST'])
def connect():
    file = open('nodes.json', 'r')
    json_obj = json.load(file)
    file.close()
    nodes = json_obj.get('nodes')
    if nodes is not None:
        for node in nodes:
            blockchain.add_node(node)
        res = {
            'message': 'node connected successfully',
            'all_nodes': list(blockchain.nodes)
        }
        return jsonify(res), 201
    else:
        return 'err'
    
@app.route('/get_largest_chain', methods=['GET'])
def get_largest_chain():
    replaced_ = blockchain.replace_chain()
    if replaced_:
        res = {
            'message': 'blockchain synced successfully',
            'new': blockchain.chain
        }
    else:
        res = {
            'message': 'alr synced',
            'chain': blockchain.chain
        }
    return jsonify(res), 200

if __name__ == "__main__":
    app.run(debug=True)

