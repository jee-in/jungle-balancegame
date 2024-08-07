from bson import ObjectId
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, json
from flask.json.provider import JSONProvider
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import jwt
import datetime
from functools import wraps
#from dotenv import load_dotenv
import os
import json

app = Flask(__name__)

# MongoDB 설정
client = MongoClient('mongodb+srv://sparta:jungle@cluster0.b3sejq0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client['balancegamedb']
Member_collection = db['Member']

#######################################################################
# MongoDB 조회 결과를 jsonify 메서드를 통해 JSON으로 만들 때
# MongoDB의 ObjectId를 파이썬의 문자열 타입으로 변환해주는 부분
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime.datetime):
            return o.strftime('%Y년 %m월 %d일 %H시 %M분')
        return json.JSONEncoder.default(self, o)


class CustomJSONProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        return json.dumps(obj, **kwargs, cls=CustomJSONEncoder)

    def loads(self, s, **kwargs):
        return json.loads(s, **kwargs)

app.json = CustomJSONProvider(app)
#######################################################################

@app.route('/question/newquestion')
def newQuestion():
    return render_template('newQuestion.html')

@app.route('/api/question/list', methods=['GET'])
def list_question():
    category_mode = request.args.get('categoryMode', 'life')
    sort_mode = request.args.get('sortMode', 'likes')  # 기본 정렬 값: 좋아요 순
    is_desc = -1  # 기본 정렬 방향: 내림차순

    questions_cursor = db.questions.aggregate([
        {'$match': {'category': category_mode}},
        {'$sort': {sort_mode: is_desc}},
        {
            '$lookup': {
                'from': 'Member',
                'localField': 'member_id',
                'foreignField': '_id',
                'as': 'member_info'
            }
        },
        {
            '$unwind': '$member_info'
        },
        {
            '$project': {
                '_id': 1,
                'category': 1,
                'question1': 1,
                'question2': 1,
                'created_at': 1,
                'participant_count': 1,
                'likes_count': 1,
                'nickname': '$member_info.nickname'
            }
        }
    ])

    questions_list = list(questions_cursor)  # Cursor 객체를 리스트로 변환

    return jsonify({'questions': questions_list})


# .env 파일 로드
#load_dotenv()

# 환경 변수에서 secret key 로드
app.secret_key = os.getenv('SECRET_KEY')

# 사용자명(id)에 대한 고유 인덱스 생성
Member_collection.create_index('id', unique=True)

# JWT 토큰을 요구하는 데코레이터
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        elif 'token' in session:
            token = session['token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Member_collection.find_one({'id': data['user']})
            if current_user is None:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# 홈 페이지
@app.route('/')
def home():
    return render_template('index.html')

# 로그인 페이지 및 처리
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['id']
        password = request.form['password']

        user = Member_collection.find_one({'id': user_id})

        if user and check_password_hash(user['password'], password):
            token = jwt.encode({
                'user': user_id,
                'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            session['token'] = token
            return redirect(url_for('home'))
        else:
            return render_template('login.html', message="유효하지 않은 아이디거나 비밀번호가 틀렸습니다.", error=True)
    return render_template('login.html')

# 회원가입 페이지 및 처리
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nickname = request.form['nickname']
        user_id = request.form['id']
        password = request.form['password']
        birthday = request.form['birthday']
        gender = request.form['gender']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        existing_user = Member_collection.find_one({'id': user_id})
        if existing_user:
            return render_template('register.html', message="User already exists", error=True)

        Member_collection.insert_one({
            'nickname': nickname,
            'id': user_id,
            'password': hashed_password,
            'birthday': birthday,
            'gender': gender,
            'participant_questions': [],
            'create_questions': []
        })
        return render_template('login.html', message="You have successfully registered!", error=False)

    return render_template('register.html')

# 보호된 페이지
@app.route('/protected')
@token_required
def protected(current_user):
    return render_template('protected.html', current_user=current_user)

# 마이페이지
@app.route('/mypage', methods = ['GET'])
@token_required
def mypage(current_user):
    return render_template('mypage.html', current_user=current_user)

# 로그아웃
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('token', None)
    flash('You have successfully logged out', 'success')
    return redirect(url_for('home'))

# 질문 페이지
@app.route('/question', methods=['GET'])
def question():
    if 'like_count' not in session:
        session['like_count'] = 10  # 기본 좋아요 수
    if 'click_count' not in session:
        session['click_count'] = 10  # 기본 클릭 수
    if 'comments' not in session:
        session['comments'] = []
    comments = session['comments']
    return render_template('question.html', like_count=session['like_count'], click_count=session['click_count'], comments=comments)

# 좋아요 수 증가 라우트
@app.route('/increment_like', methods=['POST'])
def increment_like():
    if 'like_count' in session:
        session['like_count'] += 1
        return jsonify({'like_count': session['like_count']})
    return jsonify({'error': 'Like count not found'}), 400

# 클릭 수 증가 라우트
@app.route('/increment_click', methods=['POST'])
def increment_click():
    if 'click_count' in session:
        session['click_count'] += 1
        return jsonify({'click_count': session['click_count']})
    return jsonify({'error': 'Click count not found'}), 400


# 댓글 추가 라우트
@app.route('/add_comment', methods=['POST'])
@token_required
def add_comment(current_user):
    comment_text = request.form['comment']
    comment = {
        'nickname': current_user['nickname'],
        'created_at': datetime.datetime.now().strftime('%Y.%m.%d. %H:%M'),
        'text': comment_text
    }
    if 'comments' not in session:
        session['comments'] = []
    session['comments'].append(comment)
    return redirect(url_for('question'))

# 질문 등록
@app.route('/api/question', methods=['POST'])
@token_required
def createQuestion(current_user):
    try:
        category = request.form['category']
        question1 = request.form['question1']
        question2 = request.form['question2']
        createdAt = datetime.datetime.now()

        data = {
            'member_id': current_user['_id'],
            'created_at': createdAt,
            'category': category,
            'question1': question1,
            'question2': question2,
        }
        db.questions.insert_one(data)

        return jsonify({'result': 'success', 'msg': '질문 등록 완료!'})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'result': 'fail', 'msg': '질문 등록 실패!'}), 500

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)