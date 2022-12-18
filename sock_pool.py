from database import Systems, ActivityLogs, db, Users
from concurrent.futures import ThreadPoolExecutor
from websocket import WebSocketApp
from modules.smtp_email import send_mail


class WebSocConn:

    def __init__(self, system, app):
        self.system = system
        self.retried = False
        self.app = app
        self.ws = WebSocketApp(
            url=f"wss://{system.ip_addr}",
            on_open=self.on_open,
            on_close=self.on_close,
            on_error=self.on_error,
            on_message=self.on_message,
            keep_running=True
        )

    def run(self):
        print('running', self.system)
        self.ws.run_forever()

    def on_open(self, ws):
        connections[self.system.sys_id] = self
        print(self.system.name, ":", "Connection opened")

    def on_close(self, ws, close_status, close_msg):
        print(self.system.name, ":", "Connection closed")
        if self.retried:
            if not self.is_down():

                with self.app.app_context():
                    ActivityLogs.new(sys_id=self.system.sys_id,
                                     act_type="DOWN",
                                     desc="trying to connect but couldn't, maybe system is down for some unknown reason",
                                     message="system down!")
                    send_mail(
                        to=Users.get_user(user_id=self.system.user_id).email_addr,
                        subject=f"{self.system.name} is down!",
                        message="trying to connect but couldn't, maybe system is down for some unknown reason",
                    )

            self.destruct()

        else:
            print(self.system.name, ":", "Connecting again...")
            self.retried = True
            self.run()

    def on_message(self, ws, message):
        print(self.system.name, ":", message.decode(encoding='utf-8'))

    def on_error(self, ws, e):
        print(self.system.name, ":", e)

    def is_down(self):
        with self.app.app_context():
            log = ActivityLogs.query.filter(ActivityLogs.system_id == self.system.sys_id).order_by(
                db.desc(ActivityLogs.activity_id)).first()
            print(log)
            if log and log.type in ["SHUTDOWN", "DOWN"]:
                print('system is down')
                return True
            print('system is not down')
            return False

    def destruct(self):
        print('destructing')
        del connections[self.system.sys_id]
        del self


class Runner:

    def __init__(self):
        self.pool = ThreadPoolExecutor()

    def add_system(self, system, app):
        wsc = WebSocConn(system, app)
        self.pool.submit(wsc.run)

    def end_pool(self):
        self.pool.shutdown()

    def init_app(self, app):
        with app.app_context():
            systems = Systems.query.filter(Systems.enable_mon == 'true', Systems.ip_addr != 'null').all()
            print(systems)
            for s in systems:
                print('adding', s)
                self.add_system(s, app)


connections = dict()
runner = Runner()
