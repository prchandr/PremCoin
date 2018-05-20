import datetime
import hashlib
import time
import json
from flask import Flask, request, render_template, redirect
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

""" Taken/inspired by:
http://www.pyscoop.com/building-a-simple-blockchain-in-python/
https://www.ibm.com/developerworks/cloud/library/cl-develop-blockchain-app-in-python/index.html
"""


class Block:

    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash

    def hash_block(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha3_256(block_string.encode()).hexdigest()


class BlockChain(object):
    difficulty = 1
    blocks_per_increase = 100000

    def __init__(self):
        self.chain = []
        self.current_node_transactions = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0,[], time.time(), '0')
        genesis_block.hash = genesis_block.hash_block()
        self.chain.append(genesis_block)

    def add_block(self, block, proof):
        previous_hash = self.get_last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not self.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        return True

    @staticmethod
    def is_valid_proof(block, block_hash):
        return block_hash.startswith('0'*BlockChain.difficulty) and block_hash == block.hash_block()

    def add_new_transaction(self, transaction):
        self.current_node_transactions.append(transaction)

    def mine(self):
        if not self.current_node_transactions:
            return False

        last_block = self.get_last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.current_node_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)
        self.current_node_transactions = []
        announce_new_block(new_block)
        return new_block.index

    @staticmethod
    def proof_of_work(block):
        block.nonce = 0
        computed_hash = block.hash_block()
        while not computed_hash.startswith('0'*(BlockChain.difficulty + int(len(bc.chain)/BlockChain.blocks_per_increase))):
            block.nonce += 1
            computed_hash = block.hash_block()
        return computed_hash

    @staticmethod
    def check_chain_validity(cls, chain):
        previous_hash = "0"
        for block in chain:
            block_hash = block.hash
            delattr(block, 'hash')
            if not cls.is_valid_proof(block, block_hash) or previous_hash != block.previous_hash:
                break
            block.hash, previous_hash = block_hash, block_hash
        return True

    @property
    def get_last_block(self):
        return self.chain[-1]


class Wallet:
    def __init__(self, public_key=None, private_key=None):
        if private_key is not None and public_key is not None:
            self.__private_key__ = private_key
            self.__public_key__ = public_key
        self.ecc = self.generate_ecc_instance()

    def generate_ecc_instance(self):
        if self.__private_key__ is None or self.__public_key__ is None:
            self.__private_key__ = ec.generate_private_key(ec.SECP384R1(), default_backend)
            self.__public_key__ = self.__private_key__.public_key()
        else:
            pass

        return None


app = Flask(__name__)
bc = BlockChain()
peers = set()
CONNECTED_NODE_ADDRESS = "http://127.0.0.1:8000"
posts = []


def consensus():
    global bc

    longest_chain = None
    current_len = len(bc.chain)

    for node in peers:
        response = requests.get('http://{}/chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and bc.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        bc = longest_chain
        return True
    return False


def announce_new_block(block):
    for peer in peers:
        url = "http://{}/add_block".format(peer)
        requests.post(url, data=json.dumps(block.__dict__, sort_keys=True))


@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["from", "to", "amount"]

    for field in required_fields:
        if not tx_data[field]:
            return "Invalid transaction data", 404

    tx_data['timestamp'] = time.time()
    bc.add_new_transaction(tx_data)
    return 'Success', 201


@app.route('/mine', methods=['GET'])
def mine():
    result = bc.mine()
    if not result:
        return "No transactions to mine\n"
    return "Block {} has been mined".format(result)


@app.route('/chain', methods=['GET'])
def get_chain():
    consensus()
    chain_data = []
    for block in bc.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data})


@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(bc.current_node_transactions)


@app.route('/add_nodes', methods=['POST'])
def register_new_peers():
    nodes = request.get_json()
    if not nodes:
        return "Invalid data\n", 400
    for node in nodes:
        peers.add(node)
    return "Success\n", 201


@app.route('/add_block', methods=['POST'])
def validate_and_add_block():
    block_data = request.get_json()
    block = Block(block_data['index'], block_data['transactions'], block_data['timestamp'], block_data['previous_hash'])
    proof = block_data['hash']
    added = bc.add_block(block, proof)

    if not added:
        return 'The block was discarded by the node', 400

    return 'Block added to the chain', 201


def fetch_transactions():
    get_chain_address = "{}/chain".format(CONNECTED_NODE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        content = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["hash"] = block["previous_hash"]
                content.append(tx)

        global posts
        posts = sorted(content, key=lambda k: k['timestamp'], reverse=True)


@app.route('/')
def index():
    fetch_transactions()
    return render_template('index.html',
                           title='PremCoin: '
                                 'Premier Cryptocurrency',
                           transactions=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)


@app.route('/submit', methods=['POST'])
def submit_textarea():
    post_from = request.form["from"]
    post_to = request.form["to"]
    post_amount = request.form["amount"]

    post_object = {
        'from': post_from,
        'to': post_to,
        'amount': post_amount,
    }

    new_tx_address = "{}/new_transaction".format(CONNECTED_NODE_ADDRESS)

    requests.post(new_tx_address,
                  json=post_object,
                  headers={'Content-type': 'application/json'})

    return redirect('/')


def timestamp_to_string(epoch_time):
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%H:%M')


if __name__ == '__main__':
    app.run(debug='True', port=8000)
