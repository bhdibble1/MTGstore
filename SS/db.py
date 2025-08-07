import os
from . import db, create_app

if os.path.exists('SS/SS.db'):
    os.remove('SS/SS.db')
else:
    print('DB does not exist create new db')
db.create_all(app=create_app()) 
