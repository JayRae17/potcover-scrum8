from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)

images_folder = './app/static/photos'
app.config['UPLOAD_FOLDER'] = images_folder

app.config.from_object('config')

from app import views