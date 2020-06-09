from flask import render_template, flash, url_for, session, redirect, request, make_response, jsonify
from app import app, db
from .models import User, Event
from .forms import RegistrationForm, LoginForm, EventForm
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from datetime import datetime


@app.route('/',methods=['GET'])
def index():
    return render_template("index.html", title="My Main Page")


@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Credentials incorrect', category='danger')
            return redirect (url_for('login'))

        if check_password_hash(user.password, password):
            session['user'] = user.email
            flash('Successfully Logged in', category='success')
            return redirect(url_for('index'))

    return render_template('login.html', title = 'Login', form = form)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        firstname =  form.firstname.data
        lastname =  form.lastname.data
        email =  form.email.data
        password =  form.password.data

        user = User(firstname = firstname, lastname =  lastname, email=email, password=generate_password_hash(password, method='sha256'))

        db.session.add(user)
        db.session.commit()

        flash('Successfully Registered', category='success')
        return redirect(url_for('index'))

    return render_template('register.html', title = "Register", form = form)


@app.route('/events', methods=['GET'])
def events():
    events = Event.query.all()

    return render_template('events.html', title="Events", user=session['user'], events=events)

@app.route('/events/create',methods=['GET', 'POST'])
def createAnEvent():
    form = EventForm()

    if form.validate_on_submit():
        title = form.title.data
        name = form.name.data
        description = form.description.data
        category = form.category.data
        start_date = form.start_date.data
        end_date = form.end_date.data
        cost = form.cost.data
        venue = form.venue.data   
        flyer = form.flyer.data


        # filename = secure_filename(flyer.filename)
        # flyer.save(os.path.join(
        #     app.config['UPLOAD_FOLDER'], filename
        # ))

        print(session['user'])
        user = User.query.filter_by(email=session['user']).first()
        print("-------------------------->" + str(user))
        creator = user.id
        date_created = datetime.now()

        event = Event(name=name, title=title, description=description, category=category, start_date=start_date, end_date=end_date, cost=cost, venue=venue, flyer="filename", creator=creator, date_created=date_created)
        db.session.add(event)
        db.session.commit()

        flash('Successfully created event', category='success')
        return redirect(url_for('index'))
    return render_template('createEvents.html', title = 'Create An Event', form = form)

@app.route('/logout', methods=['GET'])
def logout():
    if user in session:
        session.pop('user', None)
    flash("You have logged out successfully", category='success')
    return redirect(url_for('login'))

#=========================== REST API ===================================

# Wrapper to check for token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'X-access-token' in request.headers:
            token = request.headers['X-access-token']
        if not token:
            return jsonify({'Message': 'Missing token'}), 401
        try:
            data = jwt.decode(token, app.cofig['SECRET_KEY'])
            current_user = User.query.filter_by(email=data['email']).first()
        except Exception as e:
            print(e)
            return jsonify({'Message':'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


@token_required
def admin_required(f):
    pass

# Create a new user provided that all relevant details are present
@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'],method ='sha256')

    user = User(firstname = data['firstname'], lastname = data['lastname'], username = data['username'], email = data['email'], password =hashed_password, admin = False)
    db.session.add(user)
    db.session.commit()
    return jsonify({'Message':'The user was created'})

# Retrieve all users
@app.route('/user', methods=['GET'])
@token_required
def get_users(current_user):

    if not current_user.admin:  #make into decorater
        return jsonify({'Message':'Sorry, function not permitted!'})

    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data["user_id"] = user.user_id
        user_data["firstname"] = user.firstname
        user_data["lastname"] = user.lastname
        user_data["username"] = user.username
        user_data["email"] = user.email
        user_data["admin"] = user.admin
        output.append(user_data) #dictionary within a list

    return jsonify({'users':output})


# Retrieve a unique user details
@app.route('/user/<user_id>', methods=['GET'])
def get_one_user(user_id):
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({'Messsage':'User does not exist'})

    user_data = {}
    user_data["id"] = user.id
    user_data["firstname"] = user.firstname
    user_data["lastname"] = user.lastname
    user_data["email"] = user.email
    user_data["admin"] = user.admin

    return jsonify({'user':user_data})

# Update a user's details 
@app.route('/user/<user_id>', methods = ['PUT'])
@token_required
def updateUser(current_user,user_id):

    if str(current_user.user_id) != str(user_id):
        return jsonify({'Message':'Sorry, function not permitted!'})
    
    user = User.query.filter_by(user_id = user_id).first()
    if not user:
        return jsonify({'Message':'User does not exist!'})
    
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'],method ='sha256')

    user.firstname = data['firstname']
    user.lastname = data['lastname']
    user.username = data['username']
    user.email = data['email']
    user.password =hashed_password
    user.admin = False

    db.session.commit()

    return jsonify({'Message':'This user with email : %s is now updated' %user.email})


# Promotes a user to admin 
@app.route('/user/promote/<user_id>', methods=['PUT'])
def promote_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({'message': 'User does not exist.'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user with email %s is now admin.' %  user.email})


# Delete a user
@app.route('/user/<user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user,user_id):
    if not current_user.admin:  #could also be a decorater
        return jsonify({'Message':'Sorry, function not permitted!'})

    user = User.query.filter_by(user_id = user_id).first()
    if not user:
        return jsonify({'Message': 'User does not exist!'})
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'Message': 'This user with email: %s is now deleted' % user.email})

# @app.route('/authlogin')
@app.route('/authlogin')
def authlogin():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('User verification failed', 401, {'WWW-Authenticate':'Basic realm="Login Required!"'})

    user = User.query.filter_by(email=auth.username).first()

    
    if not auth or not auth.username or not auth.password:
        return make_response('User verification failed', 401, {'WWW-Authenticate':'Basic realm="Login Required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'email':user.email, 'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    
    return make_response('User verification failed', 401, {'WWW-Authenticate':'Basic realm="Login Required!"'})

# Create an event
@token_required
@app.route('/events', methods=['POST'])
def create_event():
    data = request.get_json()

    event = Event(title=data['title'], description=data['description'], category=data['category'], start_date=data['start_date'], end_date=data['end_date'], cost=data['cost'], venue=data['venue'], flyer=data['flyer'], visibility=data['visibility'])
    db.session.add(event)
    db.session.commit()
    return jsonify({'Message': 'The event was created'})


def save_picture(form_picture):
    random_hex= secrets.token_hex(8)
    f_name,f_ext= os.path.splitext(form_picture.filename)
    picture_fn= random_hex+ f_ext
    picture_path= os.path.join(app.root_path,'static/photos',picture_fn)
    output_size=(650,760)
    i=Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

# Returns a list of all visible events
@app.route('/events', methods = ['GET'])
def getEvents():
    events = Event.query.all()
    event_list = []
    for event in events:
        event_data = {}
        event_data["id"] = event.id
        event_data["name"] = event.name
        event_data["description"] = event.description
        event_data["category"] = event.category
        event_data["title"] = event.title
        event_data["start_dt"] = event.start_dt
        event_data["end_dt"] = event.end_dt
        event_data["cost"] = float(event.cost)
        event_data["venue"] = event.venue
        event_data["flyer"] = event.flyer
        event_data["visibility"] = event.visibility
        event_list.append(event_data)
    return jsonify({'Events':event_list})

# Updates visibility of events
@app.route('/events/viz/<event_id>', methods=['PUT'])  
@token_required
# @adminrequired
def update_event_visibility(id):
    if not current_user.admin:  #could also be a decorater
        return jsonify({'Message':'Sorry, function not permitted!'})

    event = Event.query.filter_by(id = id).first()
    if not event:
        return jsonify({'Message': 'This event is not in the system'})
    
    event.visibility=True
    db.session.commit()

    return jsonify({'Message': 'This event with title: %s is now visible' % event.title})


# Retrieve a particular event details
@app.route('/events/<event_id>', methods = ['GET'])
def getEventDetails(event_id):
    events = Event.query.filter_by(id=event_id).first()

    event_data = {}
    event_data["id"] = event.id
    event_data["name"] = event.name
    event_data["description"] = event.description
    event_data["category"] = event.category
    event_data["title"] = event.title
    event_data["start_dt"] = event.start_dt
    event_data["end_dt"] = event.end_dt
    event_data["cost"] = float(event.cost)
    event_data["venue"] = event.venue
    event_data["flyer"] = event.flyer
    event_data["visibility"] = event.visibility
    return jsonify({'Events':event_data})

# Delete a particular event
@app.route('/events/<event_id>', methods=['DELETE'])
def delete_event(event_id):
    event = Event.query.filter_by(id=event_id).first()
    if not event:
        return jsonify({'message': 'Event does not exist.'})

    db.session.delete(event)
    db.session.commit()
    return jsonify({'message': 'This event is now deleted.' %  event.title})