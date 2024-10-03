from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # Troque por uma chave secreta real
users = {}  # Simulação de um banco de dados com um dicionário

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users.get(email)
        if user and check_password_hash(user['password'], password):
            session['email'] = email
            flash('Login bem-sucedido!')
            return redirect(url_for('menu'))  # Redireciona para a página de menu após login
        else:
            flash('Email ou senha inválidos!')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email in users:
            flash('Email já cadastrado!')
        else:
            users[email] = {'password': generate_password_hash(password)}
            flash('Usuário cadastrado com sucesso!')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/menu')
def menu():
    if 'email' not in session:
        flash('Você precisa estar logado para acessar o menu!')
        return redirect(url_for('login'))
    return render_template('menu.html')  # Renderiza a página de menu

@app.route('/menu1')
def menu1():
    if 'email' not in session:
        flash('Você precisa estar logado para acessar esta página!')
        return redirect(url_for('login'))
    return render_template('menu1.html')  # Renderiza a página para Menu 1

@app.route('/menu2')
def menu2():
    if 'email' not in session:
        flash('Você precisa estar logado para acessar esta página!')
        return redirect(url_for('login'))
    return render_template('menu2.html')  # Renderiza a página para Menu 2

@app.route('/logout')
def logout():
    session.pop('email', None)
    flash('Você foi desconectado!')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
