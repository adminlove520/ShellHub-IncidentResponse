import pymysql
import os
import time

# 数据库连接配置
db_config = {
    'host': 'host',
    'user': 'root',
    'port': 3306,
    'password': 'root',
    'db': 'db'
}

# 延时函数，用于在导入文件之间添加延时
def delay(seconds):
    time.sleep(seconds)

# 批量导入SQL文件
def batch_import_sql_files(sql_folder_path, db_config, delay_seconds=5):
    try:
        # 连接数据库
        connection = pymysql.connect(**db_config)

        # 创建cursor对象
        with connection.cursor() as cursor:
            # 遍历文件夹中的所有文件
            for filename in os.listdir(sql_folder_path):
                if filename.endswith('.sql'):
                    file_path = os.path.join(sql_folder_path, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as file:
                            sql_script = file.read()
                            # 执行SQL脚本
                            cursor.execute(sql_script)
                            connection.commit()
                            print(f'{filename} has been imported successfully.')
                    except pymysql.MySQLError as e:
                        print(f'Error importing {filename}: {e}')
                    finally:
                        # 在导入每个文件后添加延时
                        delay(delay_seconds)

    except pymysql.MySQLError as e:
        print(f'Database error: {e}')
    except Exception as e:
        print(f'An error occurred: {e}')
    finally:
        # 关闭数据库连接
        if connection.open:
            connection.close()

# 调用函数，传入SQL文件所在的文件夹路径和数据库配置
batch_import_sql_files('.\sqls_datas', db_config, delay_seconds=5)