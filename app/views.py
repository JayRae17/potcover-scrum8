import os
from flask import render_template, flash, url_for, session, redirect, request, make_response, jsonify
from app import app, db
from .models import User, Event
from .forms import RegistrationForm, LoginForm, EventForm
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt, datetime, secrets
from functools import wraps

token_set = set()

@app.route('/',methods=['GET'])
def index():
    return render_template("index.html", title="Main Page")


@app.route('/events', methods=['GET']) #everyone can see
def events():
    events = Event.query.all()
    

    return render_template('events.html', title="Current Events", events=events)


@app.route('/login',methods=['GET','POST'])
def login(): #not connected to authlogin
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
            session['user_id'] = user.id
            flash('Successfully Logged in', category='success')
            return redirect(url_for('userevents', id = session['user_id']))

    return render_template('login.html', title = 'Login', form = form)


@app.route('/register', methods=['POST', 'GET'])
def register(): #not connected to createuser
    form = RegistrationForm()
    if form.validate_on_submit():
        firstname =  form.firstname.data
        lastname =  form.lastname.data
        username =  form.username.data
        email =  form.email.data
        password =  form.password.data

        user = User(firstname = firstname, lastname =  lastname, username =  username, email=email, password=generate_password_hash(password, method='sha256'))

        db.session.add(user)
        db.session.commit()

        flash('Successfully Registered', category='success')
        return redirect(url_for('login'))

    return render_template('register.html', title = "Register", form = form)



@app.route('/events/create',methods=['GET', 'POST'])
def createAnEvent():
    form = EventForm()

    if form.validate_on_submit():
        title = form.title.data
        name = form.name.data
        description = form.description.data
        category = form.category.data
        start_dt = form.start_date.data
        end_dt = form.end_date.data
        cost = form.cost.data
        venue = form.venue.data   
        flyer = request.files['flyer']
       
        filename = secure_filename(flyer.filename)
        flyer.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))   #works

        print(session['user'])
        user = User.query.filter_by(email=session['user']).first()
        print("-------------------------->" + str(user))
        creator = user.id
        date_created = datetime.datetime.now()

        event = Event(name=name, title=title, description=description, category=category, start_dt=start_dt, end_dt=end_dt, cost=cost, venue=venue, flyer=filename, creator=creator, date_created=date_created)
        db.session.add(event)
        db.session.commit()

        flash('Successfully created event', category='success')
        return redirect(url_for('userevents', id = session['user_id']))
    return render_template('createEvents.html', title = 'Create An Event', form = form)


@app.route('/events/<id>', methods=['GET']) #only user can see 
def userevents(id):
    if 'user' in session:
        user = User.query.filter_by(id = id).first()
        userevent = Event.query.filter_by(creator = id).all()
        return render_template('userevents.html', title="Your Events", userevent=userevent, user = user)
    else:
        return redirect(url_for('login'))


# def save_picture(form_picture):
#     random_hex= secrets.token_hex(8)
#     f_name,f_ext= os.path.splitext(form_picture.filename)
#     picture_fn= random_hex+ f_ext
#     picture_path= os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_fn)
#     output_size=(650,760)
#     i=Image.open(form_picture)
#     i.thumbnail(output_size)
#     i.save(picture_path)
#     return picture_fn



@app.route('/logout', methods=['GET'])
def logout(): #not connected to authlogout
    if 'user' in session:
        session.pop('user', None)
    flash("You have logged out successfully", category='success')
    return redirect(url_for('login'))

#=================== REST API =======================#

## Build a functiion decorator.  It can add new functionality to an existing function
#Build out your API in a table
# we use a token for communication and authentication

#try without jwt then with jwt tokens after

#=========== Decorators =================#

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers: 
            token = request.headers['x-access-token']

        if token in token_set: #checks if token in blacklist
            return jsonify({'Message':'Please Login Again'}), 200

        if not token:
            return jsonify({'Message':'Missing Token'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(email = data['email']).first()
        except Exception as e:
            print(e)
            return jsonify({'Message':'Invalid Token'}), 401
        return f(current_user, *args,**kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin = False
        token = request.headers['x-access-token']
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(email = data['email']).first()
            if not current_user.admin:
                return jsonify({'Message':'Sorry, function not permitted!'}), 401
        except Exception as e:
            print(e)
            return jsonify({'Message':'User Not Found'}), 401
        return f(*args,**kwargs)
    return decorated


def authorized_user(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers['x-access-token']
        
        try:

            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(email = data['email']).first()

            try:
                if current_user.id == user_id:
                    print('authorized')

            except Exception as e:
                return jsonify({'Message':'Sorry, not Authorized!'}), 401

            if not current_user.admin:
                return jsonify({'Message':'Sorry, function not permitted!'}), 401

        except Exception as e:
            print(e)
            return jsonify({'Message':'User Not Found'}), 401
        return f(*args,**kwargs)
    return decorated

#============= Users ===================#

# Retrieve all users

@app.route('/user', methods=['GET'])
@admin_required
@token_required
def get_users(current_user):
    users = User.query.filter(User.email != current_user.email).all()  #gets all but admin
    output = []

    for user in users:
        user_data = {}
        user_data["user_id"] = user.id
        user_data["firstname"] = user.firstname
        user_data["lastname"] = user.lastname
        user_data["username"] = user.username
        user_data["email"] = user.email
        user_data["admin"] = user.admin
        output.append(user_data) #dictionary within a list
    return jsonify({'users':output})

# Retrieve a unique user details

@app.route('/user/<user_id>', methods=['GET'])
@token_required
def get_one_user(current_user,user_id):
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({'Messsage':'User does not exist'})

    if current_user.id == user_id:
        user_data = {}
        user_data["id"] = user.id
        user_data["firstname"] = user.firstname
        user_data["lastname"] = user.lastname
        user_data["email"] = user.email
        user_data["admin"] = user.admin
        return jsonify({'user':user_data})
        
    return jsonify({'Messsage':'You are unauthorized'})


#delete a particular user
@app.route('/user/<user_id>', methods=["DELETE"])
@token_required
def delete_user(current_user,user_id):
    
    user = User.query.filter_by(id = user_id).first()
    current_user = User.query.filter_by(email = current_user.email).first()
    if not user:
        return jsonify({'Message': 'User does not exist!'})

    if str(current_user.id) == str(user.id):
        db.session.delete(user)
        db.session.commit()
        return jsonify({'Message': 'This user with email: %s is now deleted' % user.email})

    return jsonify({'Message':'Sorry, function not permitted!'})

#delete a particular user
@app.route('/admin/user/<user_id>', methods=["DELETE"])
@admin_required
@token_required
def admin_delete_user(current_user,user_id):
        
    user = User.query.filter_by(id = user_id).first()
    if not user:
        return jsonify({'Message': 'User does not exist!'})
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'Message': 'This user with email: %s is now deleted' % user.email})

@app.route('/user/<user_id>', methods = ['PUT'])
@token_required
def updateUser(current_user,user_id):

    if str(current_user.id) != str(user_id):
        return jsonify({'Message':'Sorry, function not permitted!'})
    user = User.query.filter_by(id = user_id).first()
    if not user:
        return jsonify({'Message':'User does not exist!'})
    
    data = request.get_json()
    
    if 'firstname' in data:
        user.firstname = data['firstname']
    if 'lastname' in data:
        user.lastname = data['lastname']
    if 'username' in data:
        user.username = data['username']
    if 'email' in data:
        user.email = data['email']
    if 'password' in data:
        hashed_password = generate_password_hash(data['password'],method ='sha256')
        user.password =hashed_password

    db.session.commit()

    return jsonify({'Message':'This user with emain : %s is now updated' %user.email})


#============ Events ####################

# Get all events for all users
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
        if event.visibility == True:
            event_list.append(event_data)
    return jsonify({'Events':event_list})

# Retrieve a particular event details
@app.route('/events/<event_id>', methods = ['GET'])
def getEventDetails(event_id):
    event = Event.query.filter_by(id=event_id).first()
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

# Updates visibility of events
@app.route('/events/visibility/<id>', methods=['PUT'])  
@token_required
@admin_required
def update_event_visibility(id):
    if not current_user.admin:  #could also be a decorater
        return jsonify({'Message':'Sorry, function not permitted!'})

    event = Event.query.filter_by(id = id).first()
    if not event:
        return jsonify({'Message': 'This event is not in the system'})
    
    event.visibility=True
    db.session.commit()

    return jsonify({'Message': 'This event with title: %s is now visible' % event.title})

def getCreator(event_id):
    creator = Event.query.filter_by(id=event_id).first().creator
    details = User.query.filter_by(id = creator).first()
    return details

@app.route('/events/<event_id>', methods = ['PUT'])
@token_required
def updateEvent(current_user,event_id):

    data = request.get_json()
    print(data)
    event = Event.query.filter_by(id=event_id).first()
    if not event:
        return jsonify({'Message':'Event does not exist!'})

    creator = getCreator(event_id)

    if creator.email != current_user.email:
        print(creator.email, current_user.email)
        return jsonify({'Message':'Sorry, function not permitted!'})

    if  'name' in data:
        event.name = data["name"]
    if  'description' in data:
        event.description = data["description"]
    if  'category' in data:
        event.category = data["category"]
    if  'title' in data:
        event.title = data["title"]
    if  'start_dt' in data:
        event.start_dt = data["start_dt"]
    if  'end_dt' in data:
        event.end_dt = data["end_dt"]
    if  'cost' in data:
        event.cost = float(data["cost"])
    if  'venue' in data:
        event.venue = data["venue"]
    if  'flyer' in data:
        event.flyer = data["flyer"]
    
    db.session.commit()
    return jsonify({'Message':'This event with eventID : %s is now updated' %event.id})

#============ Auth Login ===================#

@app.route('/authlogin')
def authlogin():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('User verification failed1', 401,{'WWW-Authenticate': 'Basic realm = "Login Required!"'})
    user = User.query.filter_by(email = auth.username).first()

    if not user:
         return make_response('User verification failed2', 401,{'WWW-Authenticate': 'Basic realm = "Login Required!"'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'email':user.email,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes = 30)}, app.config['SECRET_KEY'])
        return jsonify({'token':token.decode('UTF-8')})

    return make_response('User verification failed3', 401,{'WWW-Authenticate': 'Basic realm = "Login Required!"'})


@app.route('/authlogout')
@token_required
def authlogout(current_user): 
    token = None
    if 'x-access-token' in request.headers: 
        token = request.headers['x-access-token']
    if not token:
        return jsonify({'Message':'Missing Token'}), 401

    token_set.add(token) #blacklist
    return jsonify({'Message':'Successfully Logged Out'}), 200


