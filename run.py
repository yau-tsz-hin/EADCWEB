from app2 import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5090', debug=True)


#to start the server: uwsgi --ini uwsgi.ini
