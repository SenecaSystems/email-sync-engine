import os
import json
import base64

from datetime import datetime

from flask import (request, g, Blueprint, make_response, Response,stream_with_context)
from flask import jsonify as flask_jsonify
from flask.ext.restful import reqparse
from sqlalchemy import asc, func
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm.exc import NoResultFound

from inbox.models.account import Account
from inbox.models.message import Message
from inbox.models.block import Block
from inbox.models.thread import Thread
from inbox.models.namespace import Namespace
from inbox.models.contact import Contact
from inbox.models.calendar import Calendar
from inbox.models.event import Event
from inbox.models.transaction import Transaction

from inbox.api.kellogs import APIEncoder
from inbox.api import filtering
from inbox.api.validation import (valid_account, get_attachments, get_calendar,
                                  get_recipients, get_draft, valid_public_id,
                                  valid_event, valid_event_update, timestamp,
                                  bounded_str, view, strict_parse_args,
                                  limit, offset, ValidatableArgument,
                                  strict_bool, validate_draft_recipients,
                                  valid_delta_object_types, valid_display_name,
                                  noop_event_update, valid_category_type,
                                  comma_separated_email_list,
                                  get_sending_draft)
from inbox import events, contacts, sendmail
from nylas.logging import get_logger
from inbox.models.constants import MAX_INDEXABLE_LENGTH
from inbox.models.action_log import schedule_action
from inbox.models.session import session_scope_by_shard_id
# from inbox.search.adaptor import NamespaceSearchEngine, SearchEngineError
from inbox.transactions import delta_sync

from inbox.util.url import provider_from_address
from inbox.auth.base import handler_from_provider

from inbox.basicauth import NotSupportedError
from inbox.api.err import InputError
from inbox.api.err import ConflictError
from inbox.api.err import err

SHARD_ID = 0

# from inbox.ignition import main_engine

# engine = main_engine()

app = Blueprint(
    'auth_api',
    __name__,
    url_prefix='/auth')


@app.before_request
def start():
    g.log = get_logger()
    g.parser = reqparse.RequestParser(argument_class=ValidatableArgument)
    g.encoder = APIEncoder()


@app.after_request
def finish(response):
    return response


@app.errorhandler(NotImplementedError)
def handle_not_implemented_error(error):
    response = flask_jsonify(message="API endpoint not yet implemented.",
                             type='api_error')
    response.status_code = 501
    return response


@app.errorhandler(InputError)
def handle_input_error(error):
    response = flask_jsonify(message=str(error), type='api_error')
    response.status_code = 400
    return response


@app.route('/')
def index():
    return """
    <html><body>
       Check out the <strong><pre style="display:inline;">docs</pre></strong>
       folder for how to use this API.
    </body></html>
    """


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)

    if data.get('email'):
        email_address = data.get('email')

        reauth = True if data.get('reauth') else False

        with session_scope_by_shard_id(SHARD_ID) as db_session:
            account = db_session.query(Account).filter_by(
                email_address=email_address).first()

        if account is not None and reauth is False:
            raise ConflictError('Account already logged in!');

        provider = provider_from_address(email_address)

        if provider == 'unknown':
            provider = 'custom'

        auth_handler = handler_from_provider(provider)

        response = auth_handler.init_auth(email_address)

        return g.encoder.jsonify({'provider': provider, 'response': response,
                                  'email': email_address})
    else:
        # return err(406, 'Email address is required!')
        raise InputError('Email address is required!')


def verify(email_address, provider, auth_data):
    auth_info = {'provider': provider}

    auth_handler = handler_from_provider(provider)
    auth_response = auth_handler.auth(auth_data)

    if auth_response is False:
        return g.encoder.jsonify({"valid": False})

    auth_info.update(auth_response)
    account = auth_handler.create_account(email_address, auth_info)

    try:
        if auth_handler.verify_account(account):
            return g.encoder.jsonify({"valid": True})
        else:
            return g.encoder.jsonify({"valid": False})
    except:
        return g.encoder.jsonify({"valid": False})


def authorize(email_address, provider, auth_data):
    auth_info = {'provider': provider}

    auth_handler = handler_from_provider(provider)
    auth_response = auth_handler.auth(auth_data)

    if auth_response is False:
        return err(403, 'Authorization error!')

    auth_info.update(auth_response)
    account = auth_handler.create_account(email_address, auth_info)

    try:
        if auth_handler.verify_account(account):
            account.name = auth_data['name']

            with session_scope_by_shard_id(SHARD_ID) as db_session:
                db_session.add(account)
                db_session.commit()

            return g.encoder.jsonify({
                "id": account.namespace.public_id,
                "msg": "Authorization successful!"
            })
        else:
            return err(406, 'Could not verify account!')
    except NotSupportedError as e:
        return err(406, 'Provider not supported!')


@app.route('/gmail', methods=['POST'])
def gmail_auth():
    data = request.get_json(force=True)

    if not data.get('email'):
        return err(406, 'Email address is required!')

    if not data.get('code'):
        return err(406, 'Authorization code is required!')

    if data.get('verify_only'):
        return verify(data.get('email'), 'gmail', data.get('code'))
    return authorize(data.get('email'), 'gmail', data.get('code'))


@app.route('/outlook', methods=['POST'])
def outlook_auth():
    data = request.get_json(force=True)

    if not data.get('email'):
        return err(406, 'Email address is required!')

    if not data.get('code'):
        return err(406, 'Authorization code is required!')

    if data.get('verify_only'):
        return verify(data.get('email'), 'outlook', data.get('code'))
    return authorize(data.get('email'), 'outlook', data.get('code'))


@app.route('/custom', methods=['POST'])
def custom_auth():
    data = request.get_json(force=True)

    for key in ['email', 'password', 'imap_server_host', 'smtp_server_host']:
        if not data.get(key):
            return err(406, '{0} is required!'.format(key))

    return (verify if data.get('verify_only') else authorize)(
        data.get('email'),
        'custom',
        {
            "provider_type":    "custom",
            "email_address":    data.get('email'),
            "password":         data.get('password'),
            "name":             data.get('name') or '',
            "imap_server_host": data.get('imap_server_host'),
            "imap_server_port": data.get('imap_server_port') or 993,
            "smtp_server_host": data.get('smtp_server_host'),
            "smtp_server_port": data.get('smtp_server_port') or 587,
            "ssl_required":     data.get('ssl_required') or True
        }
    )


@app.route('/generic', methods=['POST'])
def generic_auth():
    data = request.get_json(force=True)

    if not data.get('email'):
        return err(406, 'Email address is required!')

    if not data.get('password'):
        return err(406, 'Password is required!')

    return authorize(data.get('email'), provider_from_address(data.get('email')), {
        "provider_type": "generic", "email_address": data.get('email'),
        "password": data.get('password')})
