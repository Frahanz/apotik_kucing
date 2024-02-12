from flask import Flask, render_template, request, redirect, url_for, jsonify, session, abort,make_response, flash
import os
import jwt
import base64
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
import secrets
from twilio.rest import Client
from werkzeug.exceptions import NotFound

#* Token
TOKEN_KEY="mytoken"
SECRET_KEY="sparta"

app = Flask(__name__)
app.secret_key = os.urandom(24)

client = MongoClient('mongodb+srv://farhanrahmat321:sparta@cluster0.dx5e0tw.mongodb.net/?retryWrites=true&w=majority')
eCommerceDB = client['eCommerceDB']


products_collection = eCommerceDB['products']
collection = eCommerceDB['hmm']
question_collection = eCommerceDB['question']
app.secret_key = secrets.token_hex(16)

# * Function Helper JWT TOKEN
def decode_token(payload):
    token = jwt.decode(payload, SECRET_KEY, algorithms=["HS256"])
    return token


def encode_token(payload):
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


#halaman utama pada saat running
@app.route('/')
def redirect_to_home():
    return redirect(url_for('user_home'))

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = os.urandom(24).hex()  
    return session['_csrf_token']

# Di dalam fungsi admin
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        product_data = {
            'name': request.form['name'],
            'image': request.form['image'],
            'description': request.form['description'],
            'price': float(request.form['price']),
            'stock': int(request.form['stock']),  # Tambahkan stok
        }
        products_collection.insert_one(product_data)
        return redirect(url_for('admin'))

    elif request.method == 'GET':
        products = products_collection.find()
        return render_template('admin/admin.html', products=products)

@app.route('/user/signin')
def user_signin():
    csrf_token = generate_csrf_token()  
    msg = request.args.get('msg')
    return render_template('user/signin.html', csrf_token=csrf_token,msg=msg)

@app.route('/signin', methods=['POST'])
def sign_in():
    if request.method == 'POST':
        
        if request.form['_csrf_token'] != session.pop('_csrf_token', None):
            abort(403)  
   
        email = request.form['email']
        password = request.form['password']
        
        
        
        user = collection.find_one({'email': email, 'password': password})
        if user:
            payload = {
                "email": email,
                "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24),
            }
            token = encode_token(payload)
            msg= {"msg":"Sign in successful","status": 200}
            response = make_response(redirect(url_for("user_home",msg=msg)))
            response.set_cookie(TOKEN_KEY, token)
            return response
        else:
            
            msg ={"msg":"Sign in failed","status": 401}
            return redirect(url_for("user_signin", msg=msg))
    return "Invalid request"

@app.route('/admin/delete/<product_id>')
def delete_product(product_id):
    products_collection.delete_one({'_id': ObjectId(product_id)})
    return redirect(url_for('admin'))


@app.route('/admin/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    try:
        product_id_obj = ObjectId(product_id)
    except Exception as e:
        print(f"Invalid ObjectId: {e}")
        return redirect(url_for('admin'))

    product = products_collection.find_one({'_id': product_id_obj})

    if product is None:
        raise NotFound(f"Product with ID {product_id} not found")

    if request.method == 'POST':
        
        updated_data = {
            'name': request.form['name'],
            'image': request.form['image'],
            'description': request.form.get('description', ''),
            'price': float(request.form['price']),
            'stock': int(request.form['stock']),  # Perbarui stok
        }
        products_collection.update_one({'_id': product_id_obj}, {'$set': updated_data})
        return redirect(url_for('admin'))

    return render_template('admin/edit_product.html', product=product)



@app.route('/user/home')
def user_home():
    token_receive = request.cookies.get(TOKEN_KEY)
    print(token_receive)
    try:
        payload = decode_token(token_receive)
        print(payload)
        msg = request.args.get("msg")
        user_info = collection.find_one({"email": payload.get("email")})
        print(user_info)
        return render_template('user/home.html', msg=msg,user_info=user_info)

    except jwt.ExpiredSignatureError:
        msg = "Your token has expired"
        return redirect(url_for("user_signin", msg=msg))
    except jwt.exceptions.DecodeError:
        msg= {"status":401,"msg":"Anda Belum Login"}
        return redirect(url_for("user_signin", msg=msg))
    
@app.route('/products')
def user_products():
    products = products_collection.find()  
    return render_template('user/products.html', products=products)


@app.route('/product/<product_id>')
def product_detail(product_id):
    product = products_collection.find_one({'_id': ObjectId(product_id)})  
    return render_template('user/detail_product.html', product=product)

from flask import abort
@app.route('/user/detail_product/<product_id>', methods=['GET', 'POST'])
def detail_product(product_id):
    try:
        product_id_obj = ObjectId(product_id)
    except Exception as e:
        print(f"Invalid ObjectId: {e}")
        return redirect(url_for('user_products'))

    product = products_collection.find_one({'_id': product_id_obj})

    if not product:
        abort(404)

    if request.method == 'POST':
        new_quantity = int(request.form['quantity'])

        if 'cart' not in session:
            session['cart'] = []

        existing_item = next((item for item in session['cart'] if item['product_id'] == str(product['_id'])), None)

        if existing_item:
            existing_item['quantity'] = new_quantity
            existing_item['total_price'] = new_quantity * product['price']
        else:
            session['cart'].append({
                'product_id': str(product['_id']),
                'product_name': product['name'],
                'quantity': new_quantity,
                'total_price': new_quantity * product['price']
            })

        session.modified = True  # Perbaruan session
        return redirect(url_for('user_products'))

    return render_template('user/detail_product.html', product=product)


@app.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    try:
        product_id_obj = ObjectId(product_id)
    except Exception as e:
        print(f"Invalid ObjectId: {e}")
        flash('Terjadi kesalahan. Silakan coba lagi.', 'danger')
        return redirect(url_for('user_products'))

    product = products_collection.find_one({'_id': product_id_obj})

    if not product:
        flash('Produk tidak ditemukan.', 'danger')
        return render_template('404.html'), 404

    if 'cart' not in session:
        session['cart'] = []

    if request.method == 'POST':
        new_quantity = int(request.form['quantity'])

        # Pastikan jumlah yang dipesan tidak melebihi stok
        if new_quantity > product['stock']:
            flash('Jumlah yang diminta melebihi stok yang tersedia.', 'danger')
            return redirect(url_for('user_products'))

        existing_item = next((item for item in session['cart'] if item['product_id'] == str(product['_id'])), None)

        if existing_item:
            existing_item['quantity'] = new_quantity
            existing_item['total_price'] += new_quantity * product['price']
        else:
            session['cart'].append({
                'product_id': str(product['_id']),
                'product_name': product['name'],
                'quantity': new_quantity,
                'total_price': new_quantity * product['price']
            })

        # Kurangi stok produk
        products_collection.update_one({'_id': product_id_obj}, {'$inc': {'stock': -new_quantity}})

        flash('Produk berhasil ditambahkan ke keranjang.', 'success')

        session.modified = True  # Perbaruan session
        return redirect(url_for('checkout'))

    flash('Terjadi kesalahan. Silakan coba lagi.', 'danger')
    return render_template('user/products.html', products=products_collection.find())

def send_whatsapp_message(nama_pengguna, nama_barang, quantity, harga):
    account_sid = 'Your_Account_SID'
    auth_token = 'Your_Auth_Token'
    client = Client(account_sid, auth_token)

    message_body = f"Hi {nama_pengguna}, terima kasih telah memesan {nama_barang} sebanyak {quantity}. Total harga: {harga}"
    message = client.messages.create(
        body=message_body,
        from_='whatsapp:+14155238886',
        to='whatsapp:+6281234567890'  # Ganti dengan nomor WhatsApp penerima
    )

    print(f"Message sent with SID: {message.sid}")

@app.route('/user/checkout', methods=['GET', 'POST'])
def checkout():
    cart = session.get('cart', [])
    if request.method == 'POST':
        nama_pengguna = request.form['nama_pengguna']
        nama_barang = request.form['nama_barang']
        quantity = request.form['quantity']
        harga = request.form['harga']

        # Kirim pesan WhatsApp
        send_whatsapp_message(nama_pengguna, nama_barang, quantity, harga)

        for item in cart:
            product_id = ObjectId(item['product_id'])
            product = products_collection.find_one({'_id': product_id})

            if not product or product['stock'] < item['quantity']:
                return "Error: Product not found or insufficient stock."

            # Kurangi stok produk setelah pembelian berhasil
            updated_stock = product['stock'] - item['quantity']
            products_collection.update_one({'_id': product_id}, {'$set': {'stock': updated_stock}})

        session.pop('cart', None)
        return redirect(url_for('checkout_success'))

    total_price = sum(item['total_price'] for item in cart)
    return render_template('user/checkout.html', cart=cart, total_price=total_price)


@app.route('/user/checkout_success')
def checkout_success():
    return render_template('user/checkout_success.html')


@app.route('/user/about')
def user_about():
    return render_template('user/about.html')


@app.route('/user/pertanyaan', methods=['GET'])
def user_pertanyaan():
    
    questions = list(question_collection.find())
    questions_with_username = []

    for question in questions:
        
        user_id = question.get('user_id')
        user_details = collection.find_one({'_id': ObjectId(user_id)})

        
        if user_details:
            question_with_username = {
                'date': question.get('date'),
                'question': question.get('question'),
                'answer_status': question.get('answer_status'),
                'username': f"{user_details.get('first_name', '')} {user_details.get('last_name', '')}"
            }
            questions_with_username.append(question_with_username)

    return render_template('user/pertanyaan.html', questions=questions_with_username)

@app.route('/user/pertanyaan', methods=['POST'])
def submit_pertanyaan():
    
    question = request.form.get('question')
    current_date = datetime.now().strftime('%Y-%m-%d')  
    
    
    user_id = '65812677b5c5ed6f364170f6'  
    
    
    question_collection.insert_one({
        'user_id': ObjectId(user_id),
        'date': current_date,  
        'question': question,
        'answer_status': 'Not answered'
    })

    
    return redirect(url_for('user_pertanyaan'))

@app.route('/admin/bukakk')
def index():
    
    questions = list(question_collection.find().sort('date', -1))  

    
    for question in questions:
        user_id = question.get('user_id')
        if user_id:
            user_data = collection.find_one({'_id': user_id})
            if user_data:
                question['username'] = f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}"

    return render_template('admin/bukakk.html', questions=questions)

@app.route('/submit_answer', methods=['POST'])
def submit_answer():
    if request.method == 'POST':
        try:
            answer_text = request.form['answerText']
            question_id = request.form['questionId']

            if answer_text and question_id:
                question_collection.update_one({'_id': ObjectId(question_id)}, {'$set': {'answer_status': answer_text}})
                return jsonify({'status': 'success', 'message': 'Answer updated successfully'})
            else:
                return jsonify({'status': 'error', 'message': 'Invalid data received'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})
    else:
        return jsonify({'status': 'error', 'message': 'Method not allowed'})



@app.route('/user/kontak')
def user_kontak():
    return render_template('user/kontak.html')


#* ================================================ Auth ======================================================

@app.route('/user/signup')
def signup():
    return render_template('user/signup.html')

@app.route('/signup', methods=['POST'])
def sign_up():
    if request.method == 'POST':
        
        first_name = request.form['nama_depan']
        last_name = request.form['nama_belakang']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['konfirmasi-password']

        
        if password != confirm_password:
            return "Passwords do not match"

        
        user_profile = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': password  
        }

        
        result = collection.insert_one(user_profile)

        if result.inserted_id:
            msg = f"Data inserted with ID: {result.inserted_id}"
            return redirect(url_for('user_signin',msg=msg))
        else:
            return "Failed to insert data"

    return "Invalid request"

#* ================================================ End Auth ======================================================

@app.route('/user/editprofil')
def edit_profile():
    token_receive = request.cookies.get(TOKEN_KEY)
    try:
        payload = decode_token(token_receive)
        user_data = collection.find_one({"email": payload.get("email")})
        print(user_data)
        if user_data:
        
            return render_template('user/editprofil.html', user=user_data)
        
        return "User not found"
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("user_home"))  

@app.route('/update_profile/<userid>', methods=['POST'])
def update_profile(userid):
    if request.method == 'POST':
        print(type(userid))
        old_password = request.form['old_password']
        print(old_password )
        new_password = request.form['new_password']
        foto = request.files.get('foto')

        user_data = collection.find_one({"_id":  ObjectId(userid)})
        print(user_data)
        if not user_data:
            return "User not found"

        if old_password != user_data['password']:
            return "Incorrect old password"

        updated_data = {
            "first_name": request.form.get('nama-depan', user_data.get('first_name')),
            "last_name": request.form.get('nama-belakang', user_data.get('last_name')),
            "email": request.form.get('email', user_data.get('email'))
        }

        if new_password:
            updated_data["password"] = new_password

        if foto and foto.filename != '':
            encoded_image = base64.b64encode(foto.read()).decode('utf-8')
            updated_data["profile_picture"] = encoded_image

        collection.update_one({"_id": userid}, {"$set": updated_data})
        return redirect(url_for('edit_profile'))

    return "Method not allowed"

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
