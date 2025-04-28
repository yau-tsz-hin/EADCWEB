import os
from flask import Flask, render_template, redirect, request, send_file, url_for, flash, jsonify, abort, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import socket
from flask import Flask, jsonify, Response, stream_with_context
import subprocess
import threading
import psutil  # 安裝 psutil: pip install psutil
import select
from threading import Thread
from queue import Queue



app = Flask(__name__)
app.config['SECRET_KEY'] = 'fdsjhkFByukeafgsdyrdgj'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 資料庫模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 登入表單
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')

# 註冊表單
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# 初始化資料庫
with app.app_context():
    db.create_all()

import ipaddress

# Cloudflare 的 IP 範圍清單
def load_ips_from_file(file_path="D:/py/dc-web-02/cloudflare_ips.txt"):
#def load_ips_from_file(file_path="/home/dc-web/dc-web/dc-web-02/app2/cloudflare_ips.txt"):
    """從檔案載入 IP 範圍"""
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
        ips = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        print(f"成功載入的 IP 範圍: {ips}")
        return ips
    except FileNotFoundError:
        print(f"檔案 {file_path} 不存在，請檢查！")
        return []

CLOUDFLARE_IPS = load_ips_from_file()

def is_cloudflare_ip(ip):
    """檢查 IP 是否屬於 Cloudflare 的範圍"""
    for cidr in CLOUDFLARE_IPS:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
            return True
    return False

@app.before_request
def limit_remote_addr():
    """限制訪問來源 IP"""
    if not is_cloudflare_ip(request.remote_addr):
        abort(403)  # 拒絕訪問

# 首頁
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/IMG_0810.jpg')
def serve_image():
    return send_from_directory('static', 'IMG_0810.jpg')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon_1.ico')

@app.route('/qwer.png')
@login_required
def qwer():
    return send_from_directory('static', 'qwer.png')

# 登入頁面
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

# 註冊頁面
@app.route('/register', methods=['GET', 'POST'])
#@login_required
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user is None:
            # 在註冊時使用 pbkdf2:sha256 加密
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose a different one.', 'danger')
    return render_template('register.html', form=form)

# 儀表板頁面
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# 登出
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# 處理表單提交
@app.route('/submit', methods=['POST'])
def submit():
    id = request.form.get('id')
    
    if id == "buy_gbl":
        return redirect('https://youtu.be/FtutLA63Cp8?si=2Gm-0NyAV14V-Nfp')
    
    elif id == "download_mc_mod":
        return render_template('download_mod.html')
    
    elif id == "dlmcmodac":
        return render_template('home.html')
    
    elif id == "video":
        return render_template('video.html')
                
    else:
        return render_template('404.html')
    
@app.route('/download_mc_mod')
def download_mc_mod ():
    return render_template('download_mod.html')

@app.route('/buy_gbl')
def buy_gbl():
    return redirect('https://youtu.be/FtutLA63Cp8?si=2Gm-0NyAV14V-Nfp')

@app.route('/video')
def video():
    return render_template('video.html')

# 文件下載
@app.route('/download', methods=['GET', 'POST'])
def download_file():
    try:
        # 獲取當前腳本的目錄
        dir_path = os.path.dirname(os.path.realpath(__file__))
        # 使用相對路徑構建檔案路徑
        file_path = os.path.join(dir_path, 'static', 'mods.zip')
        
        # 檢查檔案是否存在
        if not os.path.exists(file_path):
            return render_template('404.html')
        
        return send_file(file_path, as_attachment=True)
    
    except Exception as e:
        return str(e)
    

# 影片資料
video_data = {
    1: {"title": "香港國安法教育", "description": "香港國安法教育-第一章：羽毛球篇", "video_file": "video1.mp4"},
    2: {"title": "香港國安法教育", "description": "香港國安法教育-第二章：新屋嶺安全屋篇。", "video_file": "video2.mp4"},
    #3: {"title": "使用教學", "description": "巨軟系統的使用教學。", "video_file": "video3.mp4"}
}

# 影片播放頁面
@app.route('/playvideo/<int:video_id>')
def playvideo(video_id):
    video = video_data.get(video_id, {"title": "影片未找到", "description": "抱歉，我們找不到該影片。", "video_file": ""})
    return render_template('playvideo.html', video_title=video['title'], video_description=video['description'], video_file=video['video_file'])


# 檢查Minecraft伺服器是否在線
def is_minecraft_server_online(ip, port=25565):
    try:
        with socket.create_connection((ip, port), timeout=10):
            return True
    except OSError:
        return False

# Minecraft伺服器狀態檢查路由
@app.route('/check_server_status')
@login_required
def check_server_status():
    #ip = "192.168.0.209"
    ip = "192.168.0.52"
    if is_minecraft_server_online(ip):
        return jsonify(status='online')
    else:
        return jsonify(status='offline')

@app.route('/confirm-force-stop', methods=['GET', 'POST'])
@login_required
def confirm_force_stop():
    if request.method == 'GET':
        # 返回確認頁面
        return render_template(
            'confirm.html',
            status="warning",
            message="進程對象丟失或已退出，是否強制關閉所有 Java 進程？",
            confirm_url=url_for('confirm_stop_server'),
            cancel_url=url_for('dashboard'),
            title="強制關閉確認"
        )

@app.route('/confirm-stop-server') 
@login_required
def confirm_stop_server():
    try:
         # 執行強制關閉所有 Java 進程的邏輯
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            try:
                if proc.info['name'] == 'java.exe' or proc.info['name'] == 'java':
                    proc.terminate()  # 發送結束信號
                    proc.wait(timeout=10)  # 等待進程結束
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                pass

        return render_template(
            'status.html',
            status="success",
            message="所有 Java 進程已成功強制關閉。"
        )
    except Exception as e:
        return render_template(
            'status.html',
            status="error",
            message=f"強制關閉失敗: {str(e)}"
        )


# 統一404錯誤處理
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


#______________minecraft server_________________

import os
import subprocess
import psutil
import threading
from queue import Queue
from flask import render_template, request, stream_with_context
from flask_login import login_required
from werkzeug.wrappers import Response as WerkResponse

# 儲存伺服器的進程物件和輸出隊列
minecraft_process = None
output_queue = Queue()

# 儲存進程 ID 到文件
def save_process_id(pid):
    with open("minecraft_server_pid.txt", "w") as f:
        f.write(str(pid))

# 從文件讀取進程 ID
def get_saved_process_id():
    if os.path.exists("minecraft_server_pid.txt"):
        with open("minecraft_server_pid.txt", "r") as f:
            pid = f.read().strip()
            return int(pid)
    return None

# 啟動伺服器路由
@app.route('/start-server', methods=['GET'])
@login_required
def start_server():
    global minecraft_process

    # 檢查伺服器是否已經運行
    saved_pid = get_saved_process_id()
    if saved_pid and psutil.pid_exists(saved_pid):
        return render_template(
            'status.html',
            status="error",
            message="Server is already running"
        )

    try:
        jar_path = os.path.join(os.getcwd(), 'app2', 'static', 'server.jar')
        if not os.path.exists(jar_path):
            raise FileNotFoundError(f"server.jar not found at: {jar_path}")

        # 嘗試執行 Minecraft 伺服器命令
        command = ["java", "-Xmx4000M", "-Xms4000M", "-jar", jar_path, "nogui"]
        try:
            minecraft_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True
            )
        except Exception as e:
            app.logger.error(f"執行伺服器命令時發生錯誤: {e}")
            return render_template(
                'status.html',
                status="error",
                message=f"執行伺服器命令時發生錯誤: {e}"
            )

        save_process_id(minecraft_process.pid)
        read_server_output()
        return render_template('status.html', status="success", message="Server starting, please wait 1 or 2 min")
    except FileNotFoundError as e:
        app.logger.error(f"Server jar not found: {e}")
        return render_template('status.html', status="error", message="Server jar file is missing.")
    except Exception as e:
        app.logger.error(f"Failed to start server: {e}")
        return render_template('status.html', status="error", message=str(e))

# 停止伺服器路由
@app.route('/stop-server', methods=['GET'])
@login_required
def stop_server():
    global minecraft_process

    # 檢查伺服器是否已運行
    saved_pid = get_saved_process_id()
    if (
        saved_pid is None or
        not psutil.pid_exists(saved_pid) or
        not is_minecraft_server_online  # 自定義判斷伺服器是否在線的邏輯
    ):
        return render_template(
            'status.html',
            status="error",
            message="Server is not running"
        )

    try:
        # 如果進程對象丟失或已退出
        if minecraft_process is None or minecraft_process.poll() is not None:
            app.logger.warning("Minecraft process lost or exited unexpectedly.")
            return redirect(url_for('confirm_force_stop'))

        # 發送 /stop 命令到伺服器
        minecraft_process.stdin.write("/stop\n")
        minecraft_process.stdin.flush()

        # 等待伺服器進程結束
        minecraft_process.wait(timeout=30)
        minecraft_process = None

        # 刪除保存的進程 ID 文件
        os.remove("minecraft_server_pid.txt")

        return render_template(
            'status.html',
            status="success",
            message="Server stopped"
        )
    except Exception as e:
        # 發生異常時強制終止伺服器進程
        if minecraft_process is not None:
            minecraft_process.terminate()
        app.logger.error(f"Failed to stop server: {e}")
        return render_template(
            'status.html',
            status="error",
            message=f"Failed to stop server: {str(e)}"
        )



from flask import Response, stream_with_context
import queue
#
# 啟動監聽伺服器輸出
def read_server_output():
    global minecraft_process
    if minecraft_process is None or minecraft_process.poll() is not None:
        return

    def listen_to_output():
        while minecraft_process and minecraft_process.poll() is None:
            try:
                line = minecraft_process.stdout.readline().strip()
                if line:
                    output_queue.put(line)
            except Exception as e:
                app.logger.error(f"Error reading server output: {e}")
                break

    # 啟動守護執行緒
    thread = threading.Thread(target=listen_to_output, daemon=True)
    thread.start()

@app.route('/server-output', methods=['GET'])
@login_required
def server_output():
    global minecraft_process
    if minecraft_process is None or minecraft_process.poll() is not None:
        return render_template(
            'status.html',
            status="error",
            message="伺服器未運行 或 讀取伺服器輸出時出錯 或 Minecraft進程遺失 或 意外退出"
        )

    def generate_output():
        while True:
            try:
                # 非阻塞式獲取隊列內容
                line = output_queue.get(timeout=1)
                yield f"{line}<br>"
            except queue.Empty:
                # 队列为空时继续等待，不中断输出
                continue
            except Exception as e:
                app.logger.error(f"Error generating server output: {e}")
                break

    # 使用流式返回伺服器輸出
    return Response(
        stream_with_context(generate_output()),
        mimetype='text/html'
    )


# 發送命令到伺服器路由
@app.route('/send-command', methods=['POST'])
@login_required
def send_command():
    global minecraft_process
    if minecraft_process is None or minecraft_process.poll() is not None:
        return render_template(
            'status.html',
            status="error",
            message="伺服器未運行或讀取伺服器輸出時出錯或 Minecraft 進程遺失或意外退出"
        )

    try:
        command = request.json.get("command", "").strip()
        if not command:
            return render_template(
                'status.html',
                status="error",
                message="No command provided"
            )

        minecraft_process.stdin.write(command + "\n")
        minecraft_process.stdin.flush()
        return render_template(
            'status.html',
            status="success",
            message="Command sent: " + command
        )
    except Exception as e:
        app.logger.error(f"Failed to send command: {e}")
        return render_template(
            'status.html',
            status="error",
            message=str(e)
        )


