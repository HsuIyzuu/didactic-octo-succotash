import psycopg2
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# 数据库连接参数
DB_HOST = '10.26.4.51'
DB_PORT = '5432'
DB_NAME = 'ruoyi_cs_pro'
DB_USER = 'ruoyi_cs_pro'
DB_PASSWORD = '7D171BCnGm5gfYJH'

# SMTP服务器参数
SMTP_HOST = 'smtp.ctsec.com'
SMTP_PORT = 465
EMAIL_USER = 'zhusy@ctsec.com'
EMAIL_PASSWORD = 'syhx0372!!'


# 连接数据库
def connect_db():

    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME,
    )

    return conn

# 提交commit&关闭数据库
def close_db_conn(cur,conn):
    conn.commit()
    cur.close()
    conn.close()

# 周-访问数据库-以人名为筛选项-整合个人弱口令发送
# 月-访问数据库-以部门/团队为筛选项-整合部门/团队弱口令发送（抄送）
# 邮件模板
# 发送

# 查询语句
SELECT_QUERY = """
    SELECT email,cmdb_config_manager_cn,t1.ip,service,group_name,cmdb_application_system,username
    FROM vuln_weakpwd_entry t1
    JOIN sys_user t2 ON t1.cmdb_config_manager = t2.login_name
    WHERE t1."vuln_status"='1'
    ORDER BY email,t1.ip,service
    """

def fetch_data():

    conn=connect_db()

    cursor = conn.cursor()
    cursor.execute(SELECT_QUERY)
    weakpwd_db = cursor.fetchall()
    close_db_conn()

    # 创建以email为键的字典
    data_by_email={}
    for weakpwd in weakpwd_db:
        key=weakpwd[0:2]
        if key not in data_by_email:
            data_by_email[key]=[]
        data_by_email[key].append(weakpwd[1:])

        # ('wangpeng@ctsec.com', '王鹏'): [('10.20.100.22', 'oracle_db', '总部数据中心-核心交易外网', 'OTC撮合系统', 'otcchdb\\SYSTEM'), ('10.20.100.22', 'oracle_db', '总部数据中心-核心交易外网', 'OTC撮合系统', 'otcchdb\\SYSMAN'), ('10.20.100.22', 'oracle_db', '总部数据中心-核心交易外网', 'OTC撮合系统', 'otcchdb\\DBSNMP'), ('10.20.100.22', 'oracle_db', '总部数据中心-核心交易外网', 'OTC撮合系统', 'otcchdb\\SYS')],

    return data_by_email


def send_emails(data_by_email):
    for one,weakpwd in data_by_email.items():

        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = one[0]
        msg['Subject'] = f'弱口令整改通知--{one[1]}'

        body="""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Alert: Weak Password Detected</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    padding: 20px;
                    color: #333;
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                }
                th, td {
                    border: 1px solid #ddd;
                    text-align: left;
                    padding: 8px;
                }
                th {
                    background-color: #f2f2f2;
                }
                .alert-header {
                    font-size: 24px;
                    color: #d8000c;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div>
                <div class="alert-header">Security Alert: Weak Password Detected</div>
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Service</th>
                            <th>Application System</th>
                            <th>Hostname</th>
                            <th>Username</th>
                        </tr>
                    </thead>
        """
        for weakpwd_details in weakpwd:
            body+=f"""
                    <tbody>
                        <tr>
                            <td>{weakpwd_details[0]}</td>
                            <td>{weakpwd_details[1]}</td>
                            <td>{weakpwd_details[2]}</td>
                            <td>{weakpwd_details[3]}</td>
                            <td>{weakpwd_details[4]}</td>
                        </tr>
                    </tbody>
                    """
        body+="""
                </table>
                <p>Please be informed that weak passwords have been detected in the services mentioned above. Immediate action is required to address these security concerns.</p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)

