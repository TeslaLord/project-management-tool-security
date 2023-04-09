from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from datetime import datetime, timedelta
import psycopg2
import requests
import os
from docopt import docopt
from ntru.ntrucipher import NtruCipher
from ntru.mathutils import random_poly
from sympy.abc import x
from sympy import ZZ, Poly
from padding.padding import *
import numpy as np
import sys
import logging
import math

log = logging.getLogger("ntru")

debug = False
verbose = False


def generate(N, p, q, priv_key_file, pub_key_file):
    ntru = NtruCipher(N, p, q)
    ntru.generate_random_keys()
    h = np.array(ntru.h_poly.all_coeffs()[::-1])
    f, f_p = ntru.f_poly.all_coeffs()[::-1], ntru.f_p_poly.all_coeffs()[::-1]
    np.savez_compressed(priv_key_file, N=N, p=p, q=q, f=f, f_p=f_p)
    log.info("Private key saved to {} file".format(priv_key_file))
    np.savez_compressed(pub_key_file, N=N, p=p, q=q, h=h)
    log.info("Public key saved to {} file".format(pub_key_file))


def encrypt(pub_key_file, input_arr, bin_output=False, block=False):
    pub_key = np.load(pub_key_file, allow_pickle=True)
    ntru = NtruCipher(int(pub_key['N']), int(pub_key['p']), int(pub_key['q']))
    ntru.h_poly = Poly(pub_key['h'].astype(int)[::-1], x).set_domain(ZZ)
    if not block:
        if ntru.N < len(input_arr):
            raise Exception("Input is too large for current N")
        output = (ntru.encrypt(Poly(input_arr[::-1], x).set_domain(ZZ),
                               random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])
    else:
        input_arr = padding_encode(input_arr, ntru.N)
        input_arr = input_arr.reshape((-1, ntru.N))
        output = np.array([])
        block_count = input_arr.shape[0]
        for i, b in enumerate(input_arr, start=1):
            log.info("Processing block {} out of {}".format(i, block_count))
            next_output = (ntru.encrypt(Poly(b[::-1], x).set_domain(ZZ),
                                        random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1])
            if len(next_output) < ntru.N:
                next_output = np.pad(next_output, (0, ntru.N - len(next_output)), 'constant')
            output = np.concatenate((output, next_output))

    if bin_output:
        k = int(math.log2(ntru.q))
        output = [[0 if c == '0' else 1 for c in np.binary_repr(n, width=k)] for n in output]
    return np.array(output).flatten()


def decrypt(priv_key_file, input_arr, bin_input=False, block=False):
    priv_key = np.load(priv_key_file, allow_pickle=True)
    ntru = NtruCipher(int(priv_key['N']), int(priv_key['p']), int(priv_key['q']))
    ntru.f_poly = Poly(priv_key['f'].astype(int)[::-1], x).set_domain(ZZ)
    ntru.f_p_poly = Poly(priv_key['f_p'].astype(int)[::-1], x).set_domain(ZZ)

    if bin_input:
        k = int(math.log2(ntru.q))
        pad = k - len(input_arr) % k
        if pad == k:
            pad = 0
        input_arr = np.array([int("".join(n.astype(str)), 2) for n in
                              np.pad(np.array(input_arr), (0, pad), 'constant').reshape((-1, k))])
    if not block:
        if ntru.N < len(input_arr):
            raise Exception("Input is too large for current N")
        log.info("POLYNOMIAL DEGREE: {}".format(max(0, len(input_arr) - 1)))
        return ntru.decrypt(Poly(input_arr[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]

    input_arr = input_arr.reshape((-1, ntru.N))
    output = np.array([])
    block_count = input_arr.shape[0]
    for i, b in enumerate(input_arr, start=1):
        log.info("Processing block {} out of {}".format(i, block_count))
        next_output = ntru.decrypt(Poly(b[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]
        if len(next_output) < ntru.N:
            next_output = np.pad(next_output, (0, ntru.N - len(next_output)), 'constant')
        output = np.concatenate((output, next_output))
    return padding_decode(output, ntru.N)


# print(enc_text)
# output = decrypt("myKey.priv.npz", enc_text)
# print(np.packbits(np.array(output).astype(int)).tobytes().decode('utf-8'))


app = FastAPI()
security = HTTPBasic()
pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")


DB_HOST = os.getenv("DB_HOST", "0.0.0.0")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8001"))

SECRET_KEY = "4FD1F5769D50F9E928AE45AB078A092E"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# HOST = "0.0.0.0"
# PORT = "8001"
BACKEND_URL = f"http://{HOST}:{PORT}"



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def db_connection_middleware(request: Request, call_next):
    conn = psycopg2.connect(
        host=DB_HOST,
        port="5432",
        database="postgres",
        user="postgres",
        password="invmtharun"
    )
    request.state.db = conn
    response = await call_next(request)
    conn.close()
    return response

def verify_password(plain_password, hashed_password):
    # print(hashed_password)
    hashed_password = np.fromstring(hashed_password.strip('[]'), sep=' ')
    output = decrypt("myKey.priv.npz", hashed_password)
    output = np.packbits(np.array(output).astype(int)).tobytes().decode('utf-8')
    if output == plain_password:
        return True
    return False
    return True

    # if get_password_hash(plain_password) == hashed_password:
    #     return True
    # # return False
    # return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    input_arr = np.unpackbits(np.frombuffer(password.encode('utf-8'), dtype=np.uint8))
    input_arr = np.trim_zeros(input_arr, 'b')
    output = encrypt("myKey.pub.npz", input_arr)
    # output = np.array2string(output)
    # output = pwd_context.hash(output)
    return np.array2string(output)

def get_user(request, username):
    cur = request.state.db.cursor()
    cur.execute(f"SELECT * FROM users where name='{username}'")
    user_id, name, enc_psd, role = cur.fetchone()
    result = dict(user_id=user_id, name=name, enc_psd=enc_psd, role=role)
    cur.close()
    return result

def authenticate_user(request, username, password):
    user = get_user(request, username)
    if not user:
        return False
    if not verify_password(password, user["enc_psd"]):
        return False
    return user

def create_access_token(data, expires_delta):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes = 15)

    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request, token:str = Depends(oauth_2_scheme)):
    credential_exception = HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers = {"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credential_exception
        ##
        token_data = username
    except JWTError:
        raise credential_exception
    user = get_user(request, username=username)
    if user is None:
        raise credential_exception
    return user

async def get_current_active_user(current_user=Depends(get_current_user)):
    # if current_user["disabled"]:
    #     raise HTTPException(status_code = 400, detail="inactive user")
    return current_user

##
@app.post('/token')
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm= Depends(   )):
    user = authenticate_user(request, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail="Incorrect Credentials", headers = {"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["name"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type":"bearer", "role":user["role"]}




def make_get_request(url, params=None):
    response = requests.get(url, params)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return f'Request failed with status code {response.status_code}'

@app.get("/get_users")
async def get_users(current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_users'
    return make_get_request(url)

@app.get("/get_managers")
async def get_managers(current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_managers'
    return make_get_request(url)


@app.get("/get_employees")
async def get_employees(  manager_id, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_employees'
    params = {
        'manager_id': manager_id
    }
    return make_get_request(url, params)

@app.get("/get_manager_tickets")
async def get_manager_tickets( manager_id, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_manager_tickets'
    params = {
        'manager_id': manager_id
    }
    return make_get_request(url, params)

@app.get("/get_ticket_detail")
async def get_ticket_detail( ticket_id, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_ticket_detail'
    params = {
        'ticket_id': ticket_id
    }
    return make_get_request(url, params)

@app.get("/get_employee_tickets")
async def get_employee_tickets(employee_id, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_employee_tickets'
    params = {
        'employee_id': employee_id
    }
    return make_get_request(url, params)

@app.get("/update_ticket_status")
async def update_ticket_status(ticket_id, status, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/update_ticket_status'
    params = {
        'ticket_id': ticket_id,
        'status' : status
    }
    return make_get_request(url, params)

@app.get("/get_ticket_comments")
async def get_ticket_comments(ticket_id, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_ticket_comments'
    params = {
        'ticket_id': ticket_id
    }
    return make_get_request(url, params)


@app.get("/update_comment")
async def update_comment(ticket_id, comment, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/update_comment'
    params = {
        'ticket_id': ticket_id,
        'comment':comment
    }
    return make_get_request(url, params)

@app.get("/create_ticket")
async def create_ticket(employee_id, manager_id, title, description, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/create_ticket'
    params = {
        'employee_id': employee_id,
        'manager_id':manager_id,
        'description':description,
        'title': title
    }
    return make_get_request(url, params)


@app.get("/get_manager_id")
async def get_manager_id(manager_name, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_manager_id'
    params = {
        'manager_name': manager_name,
    }
    return make_get_request(url, params)

@app.get("/get_employee_id")
async def get_employee_id( employee_name, current_user = Depends(get_current_active_user)):
    url = f'{BACKEND_URL}/get_employee_id'
    params = {
        'employee_name': employee_name
    }
    return make_get_request(url, params)



print(get_password_hash("manager"))