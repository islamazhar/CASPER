import sys; sys.path.append("..")

from typing import Dict
import json

from flask import Flask, render_template, request
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from server.model import Credential, UserAccount


# Create our Flask app
app = Flask(__name__)
port_number = 8000


################
#
# RP Configuration
#
################

rp_id = "localhost"
origin = f"http://localhost:{port_number}"
rp_name = "Sample RP"
user_id = "some_random_user_identifier_like_a_uuid"
username = f"your.name@{rp_id}"
print(f"User ID: {user_id}")
print(f"Username: {username}")

# A simple way to persist credentials by user ID
in_memory_db: Dict[str, UserAccount] = {}

# Register our sample user
in_memory_db[user_id] = UserAccount(
    id=user_id,
    username=username,
    credentials=[],
)

# Passwordless assumes you're able to identify the user before performing registration or
# authentication
logged_in_user_id = user_id

# A simple way to persist challenges until response verification
current_registration_challenge = None
current_authentication_challenge = None


import random 
import string 
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

################
#
# Views
#
################





@app.route("/")
def index():
    context = {
        "username": username,
    }
    return render_template("index.html", **context)


################
#
# Registration
#
################


@app.route("/generate-registration-options", methods=["GET"])
def handler_generate_registration_options():
    global current_registration_challenge
    global logged_in_user_id
    
    uname = request.args.get('uname')
    user_id, username = -1, -1
    for k, v in  in_memory_db.items():
        if v.username ==uname:
            # username already exists
            user_id = k 
            username = v.username 
            break 
    
    if user_id == -1:       
        username = uname 
        user_id = id_generator()
        in_memory_db[user_id] = UserAccount(
            id=user_id,
            username=username,
            credentials=[],
        )
        
        
    
    # check if username exists; if yes use that username; otherwise create a new entry. 
    
    
    
    print(f"============user_id => {user_id}\t in_memory_db[user_id] = {in_memory_db[user_id]}==========")
    

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id,
        # user_name=user.username,
        user_name=username,
        exclude_credentials=[
            {"id": cred.id, "transports": cred.transports, "type": "public-key"}
            for cred in in_memory_db[user_id].credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    current_registration_challenge = options.challenge

    return options_to_json(options)


@app.route("/verify-registration-response", methods=["POST"])
def handler_verify_registration_response():
    global current_registration_challenge
    global logged_in_user_id

    body = request.get_data()

    try:
        credential = RegistrationCredential.parse_raw(body)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=current_registration_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except Exception as err:
        return {"verified": False, "msg": str(err), "status": 400}

    user = in_memory_db[logged_in_user_id]

    new_credential = Credential(
        id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=json.loads(body).get("transports", []),
    )

    user.credentials.append(new_credential) # it should not append it should replace. 

    return {"verified": True}


################
#
# Authentication
#
################

# challenge phase. Gives the user id and sends a challenge. 
@app.route("/generate-authentication-options", methods=["GET"])
def handler_generate_authentication_options():
    global current_authentication_challenge
    global logged_in_user_id

    user = in_memory_db[logged_in_user_id]

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            {"type": "public-key", "id": cred.id, "transports": cred.transports}
            for cred in user.credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    current_authentication_challenge = options.challenge

    return options_to_json(options)


# verification phase 
@app.route("/verify-authentication-response", methods=["POST"])
def hander_verify_authentication_response():
    global current_authentication_challenge
    global logged_in_user_id

    body = request.get_data()

    try:
        credential = AuthenticationCredential.parse_raw(body)

        # Find the user's corresponding public key
        user = in_memory_db[logged_in_user_id]
        user_credential = None
        for _cred in user.credentials:
            if _cred.id == credential.raw_id:
                user_credential = _cred

        if user_credential is None:
            raise Exception("Could not find corresponding public key in DB")

        # Verify the assertion
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=current_authentication_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=user_credential.public_key,
            credential_current_sign_count=user_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as err:
        return {"verified": False, "msg": str(err), "status": 400}

    # Update our credential's sign count to what the authenticator says it is now
    user_credential.sign_count = verification.new_sign_count

    return {"verified": True}


if __name__ == '__main__':
    app.run(host=rp_id, port=port_number, debug=True)