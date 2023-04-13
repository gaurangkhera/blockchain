from hack import app, create_db, db
from flask import render_template, redirect, url_for, flash, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from hack.forms import LoginForm, RegForm, PayForm
from hack.models import User, Blockchain, Transaction
from werkzeug.security import generate_password_hash, check_password_hash
# from api.blockchain import XCBlockChain
# create_db(app)
from uuid import uuid1

node_addr = str(uuid1()).replace('-', '')

# blockchain = XCBlockChain()

@app.route('/')
def home():
    # blockchain = Blockchain()
    # db.session.add(blockchain)
    # db.session.commit()
    # bc = Blockchain.query.filter_by(id=1).first()
    # bc.create_block(proof=1, prev_hash='0')
    # db.session.commit()
    # bc = Blockchain.query.filter_by(id=1).first()
    # blk = bc.create_block(proof=1, prev_hash='0')
    # db.session.add(blk)
    # db.session.commit()
    # print(bc.chain)
    return render_template('index.html')

@app.route('/chain')
def see_chain():
    bc = Blockchain.query.filter_by(id=1).first()
    return render_template('see_bc.html', bc=bc)

@app.route('/mine')
@login_required
def mine():
    blockchain = Blockchain.query.filter_by(id=1).first()
    prev_block = blockchain.get_prev_block()
    prev_proof = prev_block.proof
    proof = blockchain.pow(prev_proof)
    prev_hash = blockchain.hash(prev_block)
    new_block = blockchain.create_block(proof, prev_hash)
    new_txn = Transaction(sender=node_addr, receiver=current_user.username, amount=5)
    current_user.money += new_txn.amount
    db.session.add(current_user)
    db.session.add(new_txn)
    new_block.transactions.append(new_txn)
    db.session.add(new_block, blockchain)
    db.session.commit()
    return 'block mined successfully'

@app.route('/validate')
def valid():
    bc = Blockchain.query.filter_by(id=1).first()
    res = ''
    chain = []
    for i in range(len(bc.chain)):
        res = bc.validate(bc.chain[i], bc.chain)
        chain.append(res)
    if all(chain):
        return 'chain is valid.'
    else:
        return 'chain is invalid.'
    
@app.route('/pay')
def pay_user():
    users = User.query.all()
    return render_template('pay_sel.html', users=users)
@app.route('/pay/<user>/', methods=['POST', 'GET'])
@login_required
def pay(user):
    form = PayForm()
    user = User.query.filter_by(username=user).first()
    amount = form.amount.data
    blockchain = Blockchain.query.filter_by(id=1).first()
    if user:
        if form.validate_on_submit():
            if current_user.money >= amount and amount > 0:
                new_txn = Transaction(sender=current_user.username, receiver=user.username, amount=amount)
                db.session.add(new_txn)
                blk = blockchain.chain[-1]
                blk.transactions.append(new_txn)
                db.session.add(blk, blockchain)
                current_user.money -= amount
                user.money += amount
                db.session.commit()
                flash('Money sent successfully')
            else:
                flash('Not enough money', 'error')
    else:
        print('not found')
    return render_template('pay.html', user=user, form=form)

@app.route('/reg', methods=['GET', 'POST'])
def reg():
    form = RegForm()
    mess=''
    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            mess = 'Account already exists'
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect('/')
    return render_template('reg.html', form=form, mess=mess)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    mess=''
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            mess = 'Email not found'
        else:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect(url_for('home'))
            else:
                mess = 'Incorrect password.'
    return render_template('login.html', mess=mess, form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
