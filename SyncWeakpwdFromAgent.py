import requests
import json
from configparser import ConfigParser
import psycopg2
from psycopg2.extras import execute_batch

# 连接数据库
def connect_db():
    # Retrieve PostgreSQL connection details from the Resource
    # Use the details to connect to the database
    conn = psycopg2.connect(
        host="10.26.23.23",
        port="5432",
        user="hsuiyzuu",
        password="7D1777777",
        dbname="weak_password",
        sslmode="disable",
    )

    return conn

# 提交commit&关闭数据库
def close_db_conn(cur,conn):
    conn.commit()
    cur.close()
    conn.close()

# 安骑士弱口令接口
def agent_weakpwd(params):

    url = "https://10.26.23.23/rpc"

    payload = json.dumps({
        "id": "ffffffff-eeee-6666-8888",
        "jsonrpc": "2.0",
        "method": "WeakPasswdService.List",
        "params":params #dict
       })

    headers = {
    'Content-Type': 'application/json',
    'Cookie': 'API-Token=Ssssssssssss; sessionid=aaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    }

    response = requests.request("POST", url, headers=headers, data=payload,verify=False)
    data=response.json()

    return data
    #返回dict

# 获取接口中的条目|返回条目集合
# state:'安骑⼠-事件状态(1:有⻛险,2:已忽略,3:已处理)'
def get_api_entry_id(state,count):

    id_api_dict=agent_weakpwd({"offset":0,"count":count,"state":state})
    id_api_list = id_api_dict["result"]["data"]

    id_api_set=set()
    for s in id_api_list:
        id_api_set.add(s['id'])

    return(id_api_set)

# 修改数据库为已修复
def update_state(id_tuple):
    sql='''
    UPDATE vuln_weakpwd_entry
    SET "vuln_status"='6'
    # 最近更新时间早于7天的设置为已修复
    WHERE entry_id IN %s or create_time < NOW() - INTERVAL '7 days'
   '''

    # print(sql)
    conn = connect_db()
    cur = conn.cursor()

    cur.execute(sql %(id_tuple,))

    print("update succ")

    close_db_conn(cur,conn)

# 获取数据库中所有的条目
def id_db_set(coloum,table_name):
    id_database=set()

    sql="select %s from %s"

    conn = connect_db()
    cur = conn.cursor()

    cur.execute(sql %(coloum,table_name))
    data=cur.fetchall()

    for r in data:
        id_database.add(r[0])

    close_db_conn(cur,conn)


# 向数据库插入新的条目
def create_vwe(id_list):
    sql="""
    INSERT INTO "vuln_weakpwd_entry" (entry_id, group_name, service, username, password,event_state, can_login, path,create_time, hostname, ip, host_state,host_last_seen_time)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, to_timestamp(%s), %s, %s, %s, %s)
    ON CONFLICT (entry_id) DO UPDATE
    SET
    host_last_seen_time = EXCLUDED.host_last_seen_time,
    group_name = EXCLUDED.group_name,
    service = EXCLUDED.service,
    username = EXCLUDED.username,
    password = EXCLUDED.password,
    event_state = EXCLUDED.event_state,
    can_login = EXCLUDED.can_login,
    path = EXCLUDED.path,
    hostname = EXCLUDED.hostname,
    ip = EXCLUDED.ip,
    create_time = EXCLUDED.create_time,
    update_time=NOW()
    ;
    """
    # 同步系统、管理员及部门
    SQL1='''
    UPDATE vuln_weakpwd_entry t2
    SET
        cmdb_config_manager = t1.oa,
        cmdb_config_manager_cn = t1.uname,
        cmdb_application_system = t1.cmdb_category,
        department = t1.department
    FROM asset_cmdb_os t1
    WHERE t2.department is NULL and t1.ip::inet = t2.ip;
    '''
    conn = connect_db()
    cur = conn.cursor()

    cur.executemany(sql,id_list)
    cur.execute(SQL1)
    print("create succ")

    close_db_conn(cur,conn)

# 将接口数据形成新的字段
def add_new(new_list):
    new_data=agent_weakpwd({"offset":0,"count":2000,"id":new_list})
    # print("new_data: " + str((new_data)))
    new_data_list = new_data["result"]["data"]
    user_records=[]
    user_tuple=()
    for d in new_data_list:

        user_tuple = (
            d['id'],
            d['group_name'],
            d['service'],
            d['username'],
            d['password'],
            d['state'],
            d['can_login'],
            d['path'],
            d['updated_at']
            # psycopg2.TimestampFromTicks(d['updated_at']), # 传递 Unix 时间戳
            # DatatypeMismatch: column "create_time" is of type timestamp without time zone but expression is of type numeric
            d['host_view']['host_name'],
            d['host_view']['host_ip'],
            d['host_view']['host_state'],
            d['host_view']['host_last_seen_at']
        )
        user_records.append(user_tuple)

    create_vwe(user_records)

def main():

    total=agent_weakpwd({"offset":0,"count":1})
    total_count = total["result"]['total']

    # 1|获取已修复的条目->更新数据库中的状态为6
    id_api_fixed=tuple(get_api_entry_id([3],total_count))
    # print(id_api_fixed)
    update_state(id_api_fixed)

    # 2|获取接口中所有的条目->集合做差得到新增的条目(id-entry_id)->更新新增的条目|返回所有条目集合
    id_api_new=get_api_entry_id([1],total_count)
    if id_api_new is not None:
    # print(id_api_new)
        id_db=id_db_set('entry_id','vuln_weakpwd_entry')

        if id_db is None:
            new_list=list(id_api_new)
        else:
            new_list=list(id_api_new-id_db)
        print(len(new_list))
        add_new(new_list)