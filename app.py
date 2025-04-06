from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import hashlib
import db_config

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'

# Configuración DB
app.config['MYSQL_HOST'] = db_config.MYSQL_HOST
app.config['MYSQL_USER'] = db_config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = db_config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = db_config.MYSQL_DB

mysql = MySQL(app)

@app.route('/')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['usuario'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        usuario = request.form['usuario']
        clave = hashlib.sha256(request.form['clave'].encode()).hexdigest()
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM usuarios WHERE usuario = %s AND clave = %s', (usuario, clave,))
        account = cursor.fetchone()
        
        if account:
            session['loggedin'] = True
            session['usuario'] = account['usuario']
            session['rol'] = account['rol']  # ← Guardar el rol en la sesión

            # Redirigir según el rol
            if account['rol'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif account['rol'] == 'profesor':
                return redirect(url_for('profesor_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            msg = 'Usuario o contraseña incorrectos.'
    return render_template('login.html', msg=msg)

# @app.route('/admin')
# def admin_dashboard():
#     if 'loggedin' in session and session.get('rol') == 'admin':
#         return render_template('admin.html', usuario=session['usuario'])
    
#     return redirect(url_for('login'))

@app.route('/admin')
def admin_dashboard():
    if 'loggedin' in session and session.get('rol') == 'admin':
        return redirect(url_for('lista_usuarios'))
    return redirect(url_for('login'))

@app.route('/profesor')
def profesor_dashboard():
    if 'loggedin' in session and session.get('rol') == 'profesor':
        return render_template('profesor.html', usuario=session['usuario'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('usuario', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        usuario = request.form['usuario']
        clave = request.form['clave']
        rol = request.form.get('rol', 'usuario')  # por defecto usuario
        confirm = request.form['confirm']

        # Validaciones
        if not re.match(r'^\w+$', usuario):
            msg = 'Solo se permiten letras, números y guiones bajos.'
        elif clave != confirm:
            msg = 'Las contraseñas no coinciden.'
        elif len(clave) < 6:
            msg = 'La contraseña debe tener al menos 6 caracteres.'
        else:
            hashed_password = hashlib.sha256(clave.encode()).hexdigest()
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM usuarios WHERE usuario = %s', (usuario,))
            account = cursor.fetchone()
            if account:
                msg = 'El usuario ya existe.'
            else:
                
                cursor.execute('INSERT INTO usuarios (usuario, clave, rol) VALUES (%s, %s, %s)', (usuario, hashed_password, rol))
                mysql.connection.commit()
                msg = 'Registro exitoso. ¡Ahora puedes iniciar sesión!'
                return redirect(url_for('login'))
    return render_template('register.html', msg=msg)



# solo admin va acceder
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session or session.get('rol') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/usuarios')
@admin_required
def lista_usuarios():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM usuarios')
    usuarios = cursor.fetchall()
    return render_template('admin_usuarios.html', usuarios=usuarios)


@app.route('/admin/usuarios/crear', methods=['GET', 'POST'])
@admin_required
def crear_usuario():
    msg = ''
    if request.method == 'POST':
        usuario = request.form['usuario']
        clave = request.form['clave']
        rol = request.form['rol']
        hashed_password = hashlib.sha256(clave.encode()).hexdigest()

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO usuarios (usuario, clave, rol) VALUES (%s, %s, %s)', (usuario, hashed_password, rol))
        mysql.connection.commit()
        return redirect(url_for('lista_usuarios'))

    return render_template('crear_usuario.html', msg=msg)


@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_usuario(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        usuario = request.form['usuario']
        rol = request.form['rol']
        cursor.execute('UPDATE usuarios SET usuario = %s, rol = %s WHERE id = %s', (usuario, rol, id))
        mysql.connection.commit()
        return redirect(url_for('lista_usuarios'))

    cursor.execute('SELECT * FROM usuarios WHERE id = %s', (id,))
    usuario = cursor.fetchone()
    return render_template('editar_usuario.html', usuario=usuario)


@app.route('/admin/usuarios/eliminar/<int:id>', methods=['POST'])
@admin_required
def eliminar_usuario(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('DELETE FROM usuarios WHERE id = %s', (id,))
    mysql.connection.commit()
    return redirect(url_for('lista_usuarios'))

#

if __name__ == '__main__':
    app.run(debug=True)
