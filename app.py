from bson import ObjectId
from flask import Flask, json, render_template, request, jsonify, redirect, url_for, session
from flask.json.provider import JSONProvider
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from functools import wraps
from dotenv import load_dotenv
import os
import json
import jwt

app = Flask(__name__)

# .env 파일 로드
load_dotenv()

# 환경 변수에서 secret key 로드
SECRET_KEY = os.getenv('SECRET_KEY')
DB_URL = os.getenv('MONGODB_URL')

# MongoDB 설정
client = MongoClient(DB_URL)
db = client['balancegamedb']

Member_collection = db['Member']
Like_collection = db['likes']

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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/mypage')
def mypage():
    return render_template('mypage.html')

@app.route('/question/<question_id>', methods=['GET'])
def question(question_id):
    question_data = db.questions.find_one({'_id': ObjectId(question_id)})
    if not question_data:
        return jsonify({'error': 'Question not found'}), 404
    member_data = db.Member.find_one({'_id': question_data['member_id']})
    like_count = Like_collection.count_documents({'question_id': ObjectId(question_id)})
    participant_count = db.check.count_documents({'question_id': ObjectId(question_id)})  # 실제 응답 수 계산
    comment_count = db.comments.count_documents({'question_id': ObjectId(question_id)})

    return render_template('question.html', like_count=like_count, click_count=participant_count, question=question_data, member=member_data, commentCount=comment_count)

@app.route('/question/new')
def newQuestion():
    return render_template('newQuestion.html')

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({'message': 'Token is missing!'}), 401

        token = auth_header.split()[1]
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            member_id = data['member_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(member_id, *args, **kwargs)
    return wrapper

@app.route("/api/auth/userinfo", methods=["GET"])
@token_required
def get_user_info(member_id):
    user = Member_collection.find_one({'_id': ObjectId(member_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "nickname": user['nickname']
    })

@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    login_id = data.get('id')
    password = data.get('password')

    user = Member_collection.find_one({'id': login_id})

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'member_id': str(user['_id']),
        'exp': datetime.datetime.now() + datetime.timedelta(hours=2)
    }, SECRET_KEY, algorithm='HS256')

    return jsonify({'success': True, 'token': token})

@app.route('/api/register', methods=['POST'])
def register_api():
    data = request.get_json()
    nickname = data.get('nickname')
    member_id = data.get('id')
    password = data.get('password')
    birthday = data.get('birthday')
    gender = data.get('gender')

    existing_user = Member_collection.find_one({'id': member_id})
    if existing_user:
        return jsonify({'success': False, 'message': '이미 가입된 계정입니다.'}), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    Member_collection.insert_one({
        'nickname': nickname,
        'id': member_id,
        'password': hashed_password,
        'birthday': birthday,
        'gender': gender,
        'participant_questions': [],
        'create_questions': []
    })
    return jsonify({'success': True, 'message': '회원가입 성공'})

@app.route('/api/user/mypage', methods=['GET'])
@token_required
def get_mypage(current_user):
    return jsonify({'success': True, 'user': {
        'nickname': current_user['nickname'],
        'id': current_user['id'],
        'birthday': current_user['birthday'],
        'gender': current_user['gender'],
    }})

@app.route('/api/question/list', methods=['GET'])
def list_question():
    category_mode = request.args.get('categoryMode', 'life')
    sort_mode = request.args.get('sortMode', 'likes')
    is_desc = -1

    sort_key = {
        'likes': 'likes_count',
        'participation': 'participant_count',
        'created_at': 'created_at'
    }.get(sort_mode, 'likes_count')  # 안전하게 매핑

    questions_cursor = db.questions.aggregate([
        {'$match': {'category': category_mode}},
        {
            '$lookup': {
                'from': 'Member',
                'localField': 'member_id',
                'foreignField': '_id',
                'as': 'member_info'
            }
        },
        {'$unwind': '$member_info'},
        {
            '$lookup': {
                'from': 'likes',
                'localField': '_id',
                'foreignField': 'question_id',
                'as': 'like_info'
            }
        },
        {
            '$lookup': {
                'from': 'check',
                'localField': '_id',
                'foreignField': 'question_id',
                'as': 'participant_info'
            }
        },
        {
            '$addFields': {
                'likes_count': {'$size': '$like_info'},
                'participant_count': {'$size': '$participant_info'}
            }
        },
        {
            '$sort': {sort_key: is_desc}
        },
        {
            '$project': {
                '_id': 1,
                'category': 1,
                'question1': 1,
                'question2': 1,
                'created_at': 1,
                'likes_count': 1,
                'participant_count': 1,
                'nickname': '$member_info.nickname'
            }
        }
    ])

    questions_list = list(questions_cursor)
    for q in questions_list:
        q['_id'] = str(q['_id'])

    return jsonify({'result': 'success', 'questions': questions_list})

@app.route('/api/questions/<question_id>', methods=['GET'])
def get_question_detail(question_id):
    question = db.questions.find_one({'_id': ObjectId(question_id)})
    if not question:
        return jsonify({'success': False, 'message': '질문 없음'}), 404

    member = db.Member.find_one({'_id': question['member_id']})
    like_count = Like_collection.count_documents({'question_id': ObjectId(question_id)})
    participant_count = db.check.count_documents({'question_id': ObjectId(question_id)})
    comment_count = db.comments.count_documents({'question_id': ObjectId(question_id)})

    question['_id'] = str(question['_id'])
    question['member_nickname'] = member['nickname']
    question['like_count'] = like_count
    question['participant_count'] = participant_count
    question['comment_count'] = comment_count

    return jsonify({'success': True, 'question': question})

@app.route('/api/questions', methods=['POST'])
@token_required
def createQuestion(member_id):
    if not member_id:
        return jsonify({'result': 'fail', 'msg': '로그인 후 사용 가능합니다'}), 401

    category = request.form['category']
    question1 = request.form['question1']
    question2 = request.form['question2']
    createdAt = datetime.datetime.now()

    data = {
        'member_id': ObjectId(member_id),
        'created_at': createdAt,
        'category': category,
        'question1': question1,
        'question2': question2,
    }
    db.questions.insert_one(data)
    return jsonify({'result': 'success', 'msg': '질문 생성 성공'}), 201

@app.route('/api/questions/<question_id>/comments', methods=['POST'])
@token_required
def create_comment(member_id, question_id):
    if not member_id:
        return jsonify({'result': 'fail', 'msg': '로그인 후 사용 가능합니다'}), 401

    data = request.get_json()
    content = data.get('content')
    if not content or not question_id:
        return jsonify({'message': 'post_id and content are required'}), 400

    user = Member_collection.find_one({'_id': ObjectId(member_id)})

    comment = {
        'question_id': ObjectId(question_id),
        'user_id': ObjectId(member_id),
        'nickname': user['nickname'],
        'content': content,
        'created_at': datetime.datetime.now()
    }

    db.comments.insert_one(comment)
    return jsonify({'result': 'success', 'message': 'Comment added'}), 201

@app.route('/api/questions/<question_id>/comments/<comment_id>', methods=['DELETE'])
@token_required
def deleteComment(member_id, question_id, comment_id):
    if not member_id:
        return jsonify({'result': 'fail', 'msg': '로그인 후 사용 가능합니다'}), 401

    db.comments.delete_one({'_id': ObjectId(comment_id), 'user_id': ObjectId(member_id)})
    return jsonify({'result': 'success', 'msg': '댓글 삭제 완료!'})

# 댓글 수정
@app.route('/api/questions/<question_id>/comments/<comment_id>', methods=['PUT'])
@token_required
def updateComment(member_id, question_id, comment_id):
    if not member_id:
        return jsonify({'result': 'fail', 'msg': '로그인 후 사용 가능합니다'}), 401
    
    data = request.get_json()
    content = data['content']
    db.comments.update_one({'_id': ObjectId(comment_id), 'user_id': ObjectId(member_id)}, {'$set': {'content': content}})
    return jsonify({'result': 'success', 'msg': '댓글 수정 완료!'})


# 댓글 리스트 조회
@app.route('/api/questions/<question_id>/comments', methods=['GET'])
def readCommentList(question_id):
    commentList = list(db.comments.find({'question_id': ObjectId(question_id)}))
    return jsonify({'result': 'success', 'commentList': commentList})

# 좋아요 수 증가 및 취소 라우트
@app.route('/api/likes', methods=['POST'])
@token_required
def increment_like(member_id):

    if not member_id:
        return jsonify({'result': 'fail', 'msg': '로그인 후 사용 가능합니다'})

    question_id = request.form['question_id']

    # 좋아요 기록을 like 컬렉션에 삽입
    like_record = {
        'member_id': ObjectId(member_id),
        'question_id': ObjectId(question_id)
    }
    # 중복 좋아요 방지
    existing_like = Like_collection.find_one({'member_id': ObjectId(member_id), 'question_id': ObjectId(question_id)})
    if existing_like:
        Like_collection.delete_one({'_id': existing_like['_id']})
        action = "unliked"
    else:
        Like_collection.insert_one(like_record)
        action = "liked"

    # 해당 질문의 좋아요 수 계산
    like_count = Like_collection.count_documents({'question_id': ObjectId(question_id)})

    return jsonify({'result': 'success', 'like_count': like_count, 'action': action})

# 질문 선택
@app.route('/api/questions/<question_id>/check', methods=['POST'])
@token_required
def clickQuestion(member_id, question_id):

    if not member_id:
        return jsonify({'result': 'fail', 'msg': '로그인 후 사용 가능합니다'})

    check = request.form['questionNum']
    findData = {'member_id': ObjectId(member_id), 'question_id': ObjectId(question_id)}
    checkData = db.check.find_one(findData)

    if not checkData:
        db.check.insert_one({
        'member_id': ObjectId(member_id),
        'question_id': ObjectId(question_id),
        'check': check
        })
    elif check != checkData['check']:
        db.check.update_one(findData, {'$set': {'check': check}})
    participant_count = db.check.count_documents({'question_id': ObjectId(question_id)})
    same_check_count = db.check.count_documents({'question_id': ObjectId(question_id), 'check': check})
    check_percent = round((same_check_count / participant_count) * 100, 2)
    statistics_data = {
        'same_check_count': same_check_count,
        'check_percent': check_percent,
    }
    return jsonify({'result': 'success', 'msg': '질문 선택 완료!', 'participant_count': participant_count, 'statistics_data': statistics_data})


@app.route('/api/questions/<question_id>/check', methods=['GET'])
@token_required
def showQuestionCheck(member_id, question_id):

    if not member_id:
        return jsonify({'result': 'fail', 'msg': '로그인 후 사용 가능합니다'})

    checkData = db.check.find_one({'member_id': ObjectId(member_id), 'question_id': ObjectId(question_id)})
    participant_count = db.check.count_documents({'question_id': ObjectId(question_id)})

    if not checkData:
        return jsonify({'result': 'success', 'msg': '질문 선택 조회 완료!', 'checked': None, 'participant_count': participant_count, 'statistics_data': None})

    same_check_count = db.check.count_documents({'question_id': ObjectId(question_id), 'check': checkData['check']})
    check_percent = round((same_check_count / participant_count) * 100, 2)
    statistics_data = {
        'same_check_count': same_check_count,
        'check_percent': check_percent,
    }

    return jsonify({'result': 'success', 'msg': '질문 선택 조회 완료!', 'checked': checkData['check'], 'participant_count': participant_count, 'statistics_data': statistics_data})

@app.route('/api/questions/participated', methods=['GET'])
@token_required
def questions_participated(member_id):
    participated_question_ids = db.check.distinct('question_id', {'member_id': ObjectId(member_id)})
    
    questions_cursor = db.questions.find({'_id': {'$in': participated_question_ids}})
    questions = list(questions_cursor)
    
    return jsonify({'questions': questions})


@app.route('/api/questions/created', methods=['GET'])
@token_required
def questions_created(member_id):
    questions_cursor = db.questions.find({'member_id': ObjectId(member_id)})
    questions = list(questions_cursor)

    return jsonify({'questions': questions})


@app.route('/api/questions/liked', methods=['GET'])
@token_required
def questions_liked(member_id):
    liked_question_ids = db.likes.distinct('question_id', {'member_id': ObjectId(member_id)})
    
    questions_cursor = db.questions.find({'_id': {'$in': liked_question_ids}})
    questions = list(questions_cursor)

    
    return jsonify({'questions': questions})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5001, debug=True)
