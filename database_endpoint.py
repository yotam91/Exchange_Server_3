from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, MetaData, Table
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from pprint import pprint
import verification_endpoint
from models import Base, Order, Log

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)


# These decorators allow you to use g.session to access the database inside the request code
@app.before_request
def create_session():
    g.session = scoped_session(
        DBSession)  # g is an "application global" https://flask.palletsprojects.com/en/1.1.x/api/#application-globals


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    g.session.commit()
    g.session.remove()


"""
-------- Helper methods (feel free to add your own!) -------
"""


def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    payload = d['payload']
    messagePayload = json.dumps(payload)
    log_obj = Log(message=messagePayload)
    session.add(log_obj)
    session.commit()
    pass


"""
---------------- Endpoints ----------------
"""


@app.route('/trade', methods=['POST'])
# delete content
def trade():
    if request.method == "POST":
        content = request.get_json(silent=True)
        print(f"content = {json.dumps(content)}")
        columns = ["sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                print(json.dumps(content))
                log_message(content)
                return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            log_message(content)
            return jsonify(False)

        # Your code here
        platform = content['payload']['sell_currency']
        if platform == 'Ethereum':
            if verifyEth(content):
                insert_order_to_db(content)
                return jsonify(True)
        elif platform == 'Algorand':
            if verifyAlg(content):
                insert_order_to_db(content)
                return jsonify(True)
        else:
            log_message(content)
        return jsonify(False)



@app.route('/order_book')
def order_book():
    # Your code here
    # Note that you can access the database session using g.session
    #
    orders = session.query(Order).filter(Order.filled == None).all()
    data = []
    for existing_order in orders:
        if is_valid_order(existing_order):
            #print("valid")
            sender_pk = existing_order.sender_pk
            receiver_pk = existing_order.receiver_pk
            buy_currency = existing_order.buy_currency
            sell_currency = existing_order.sell_currency
            buy_amount = existing_order.buy_amount
            sell_amount = existing_order.sell_amount
            signature = existing_order.signature

            orderJson = {
                "sender_pk": sender_pk,
                "receiver_pk": receiver_pk,
                "buy_currency": buy_currency,
                "sell_currency": sell_currency,
                "buy_amount": buy_amount,
                "sell_amount": sell_amount,
                "signature": signature,
            }
            data.append(orderJson)
    result = {"data": data}
    # return json.dumps(result)
    # return app.response_class(json.dumps(result), content_type='application/json')
    return jsonify(result)


def insert_order_to_db(order):
    order_obj = Order(sender_pk=order['payload']['sender_pk'], receiver_pk=order['payload']['receiver_pk'],
                      buy_currency=order['payload']['buy_currency'], sell_currency=order['payload']['sell_currency'],
                      buy_amount=order['payload']['buy_amount'], sell_amount=order['payload']['sell_amount'])
    session.add(order_obj)
    session.commit()
    # print("order inserted ", order)


def is_valid_order(existing_order):
    sig = existing_order.signature
    sender_pk = existing_order.sender_pk
    receiver_pk = existing_order.receiver_pk
    buy_currency = existing_order.buy_currency
    sell_currency = existing_order.sell_currency
    buy_amount = existing_order.buy_amount
    sell_amount = existing_order.sell_amount
    platform = sell_currency

    if sell_currency != "Ethereum" and sell_currency != "Algorand":
        return False

    return True


def verifyEth(content):
    valid_eth = False
    eth_pk = content['payload']['sender_pk']
    payload = content['payload']
    payload = json.dumps(payload)
    eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
    if eth_account.Account.recover_message(eth_encoded_msg, signature=content['sig']) == eth_pk:
        print("Eth sig verifies!")
        valid_eth = True
    return valid_eth


def verifyAlg(content):
    payload = content['payload']
    algo_sig_str = content['sig']
    algo_pk = payload['sender_pk']
    payload = json.dumps(payload)
    if algosdk.util.verify_bytes(payload.encode('utf-8'), algo_sig_str, algo_pk):
        print("Algo sig verifies!")
        return True
    return False


if __name__ == '__main__':
    #content = {'sig':'0xd51babaaefe9cacbfae8bed46434399ad05700403ee7aa51c83ddb5d04ab7d4d4cb5307263812ea0c002cf6aebed2c0677adf0d74529d68ca59bbdb81ccdd4da1c', 'payload': {'platform': 'Ethereum', 'sender_pk': '0x906DB3244Eea11815EABEf36f8bcbbF47C92765C', 'receiver_pk': 'a651c757d3488953430969a31d480d4bf8cb4e16952ed41fee1feef764ee3df6', 'buy_currency': 'Algorand', 'sell_currency': 'Ethereum', 'sell_amount': 5172, 'buy_amount': 15516}}
    #verifyAlg(content)
    app.run(port='5002')
    #order_book()
#        'sig': '0xd51babaaefe9cacbfae8bed46434399ad05700403ee7aa51c83ddb5d04ab7d4d4cb5307263812ea0c002cf6aebed2c0677adf0d74529d68ca59bbdb81ccdd4da1c',
#        'payload': {'platform': 'Ethereum', 'sender_pk': '0x906DB3244Eea11815EABEf36f8bcbbF47C92765C',
#                    'receiver_pk': 'a651c757d3488953430969a31d480d4bf8cb4e16952ed41fee1feef764ee3df6',
#                    'buy_currency': 'Algorand',
#                    'sell_currency': 'Ethereum',
#                    'sell_amount': 5172,
#                    'buy_amount': 15516}}
