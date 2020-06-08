import os
from db import get_db
from flask import Flask, render_template, g, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def get_current_user(userName = None, password = None):
    getUser = None
    db = get_db()
    userDb = db.execute('SELECT id, name, password, expert, admin FROM users WHERE name = ?', [userName])
    result = userDb.fetchone()
    if  result is not None and ('active' in session or check_password_hash(result[2], password)):
        session['admin'] = False
        if result['admin'] == 1:
            session['admin'] = True        
        session['active'] = True
        session['user'] = userName
        getUser = result
    elif result is not None:
        getUser = userName
        session['user'] = userName
    elif result is None:
         getUser = None
    print(getUser)
    return getUser


def getValidateUser(user = None):
    if 'user' in session:
        user = get_current_user(session['user'])
    elif user is not None:
        user = get_current_user(user)
    else:
        user = None
    return user


@app.route('/')
def index():
    user = getValidateUser()
    return render_template('home.html', user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user = getValidateUser()
    if request.method == 'POST' and user is None:
        user = getValidateUser(request.form['name'])
        print(user)
        if user is None:
            try:
                db = get_db()
                hashed_pwd = generate_password_hash(request.form['password'], method='sha256')
                db.execute("INSERT INTO users (name, password, expert, admin) values (?,?,?,?)",[request.form['name'], hashed_pwd, '0', '0'])
                db.commit()
                return redirect(url_for('login'))
            except:
                return render_template('register.html', user=user, message='Usuario error.')
        else:
            session.pop('user',None)
            return render_template('register.html', user=None, message='Usuario existe.')
    
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('register.html', user=user, message=None)


@app.route('/login', methods=['GET','POST'])
def login():
    user = getValidateUser()
    if request.method == 'POST' and user is None:
        user = request.form['name']
        password = request.form['password']
        result = get_current_user(user, password)
        if  'active' in session:
            print(session)
            print('<h1>Users: {}, logging.!</h1>'.format(request.form['name']))
            return redirect(url_for('index'))
        else:
            session.pop('user',None)
            print('<h1>Users: {} -> No existe </h1>'.format(request.form['name']))
            return render_template('login.html', user=None, message='Usuario no existe.')
    elif user is not None:
        return redirect(url_for('index'))
    return render_template('login.html', user=user, message=None)


@app.route('/question')
def question():
    user = get_current_user(session['user'])
    return render_template('question.html', user=user)

@app.route('/answer/<question_id>', methods=['GET','POST'])
def answer(question_id):
    user = get_current_user(session['user'])
    db = get_db()
    print(question_id)
    if request.method == 'POST':
        upd = '''
            UPDATE questions SET answer_text = '{}'  WHERE id = {}
        '''.format(request.form['answer'], question_id)
        print(upd)
        db.execute(upd)
        db.commit()
    qry = '''
                SELECT 
                    q.id AS QID,
                    q.question_text AS QTEXT,
                    CASE WHEN answer_text IS NULL THEN '' ELSE answer_text END AS QANSWER
                FROM questions q 
                WHERE q.id = {}
            '''.format(question_id)
    print(qry)
    question_cur = db.execute(qry)
    question_result = question_cur.fetchone()
    return render_template('answer.html', question=question_result, user=user)

@app.route('/ask', methods=['GET','POST'])
def ask():
    try:
        user = get_current_user(session['user'])
        db = get_db()
        if request.method == 'POST':
            print('Question: {}, Expert ID: {}, User ID: {}'.format(request.form['question'], request.form['expert'], user['id']))
            db.execute('INSERT INTO QUESTIONS (question_text, asked_by_id, expert_id) VALUES (?,?,?)',[request.form['question'], user['id'], request.form['expert']])
            db.commit()
            return redirect(url_for('index'))
        expert_cur = db.execute('SELECT id, name FROM users WHERE expert = 1')
        experts_results = expert_cur.fetchall()
        return render_template('ask.html', user=user, experts=experts_results)
    except Exception as e:
        print(e)
        return redirect(url_for('login'))
        
@app.route('/unanswered')
def unanswered():
    try:
        user = get_current_user(session['user'])
        db = get_db()
        qry = '''
                SELECT q.id AS QID, q.question_text AS QTEXT, u.name AS UNAME 
                FROM questions q INNER JOIN users u ON q.asked_by_id = u.id 
                WHERE q.expert_id = {}
            '''.format(user['id'])
        print(qry)
        question_cur = db.execute(qry)
        question_results = question_cur.fetchall()
        print(list(question_results))
        return render_template('unanswered.html', user=user, questions=question_results)
    except Exception as e:
        print(e)
        return redirect(url_for('login'))

@app.route('/users')
def users():
    try:
        user = get_current_user(session['user'])
        if session['active'] == True and session['admin'] == True:
            db = get_db()
            print('he')
            users_lst = db.execute('SELECT id, name, expert, admin FROM users')
            users_lst_rs = users_lst.fetchall()
            return render_template('users.html', user=user, users=users_lst_rs)
        else:
            return redirect(url_for('logout'))
    except:
        return redirect(url_for('index'))
    
    return render_template('users.html', user=user)

@app.route('/logout')
def logout():
    user = None
    session.pop('active',None)
    session.pop('user',None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)