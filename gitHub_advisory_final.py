#coding: utf-8

"""需要把项目的默认所有编码换成utf-8,pycharm中setting-Eidtor-file encodings,有选择编码的三个全换成utf-8"""

import requests
from bs4 import BeautifulSoup
import lxml
import re # 正则表达式
from time import time
from time import sleep#延时
import random# 随机数
from requests.packages import urllib3
import json
import pandas as pd

from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler

#全局变量
list_GHSA = []


advisory_url = 'https://github.com/advisories'
main_url = 'https://api.github.com/repos/github/advisory-database/contents/advisories/'
json_url = 'https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed'#下载内容地址
headers = {
    'Authorization' : 'token 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',
    # 可以换成自己的密钥,需要定期更新
    'Accept': 'application/vnd.github.v3+json',
    'Content-type' : 'application/json'
}
# 解除限制，提高到5000条

#GitHub reviewed
print("-----github-reviewed--------")
def get_first_info():
    r_url = main_url + 'github-reviewed' # 注意不要带 ‘/’

    urllib3.disable_warnings()#忽略报错
    response_r_year = requests.get(r_url,headers=headers,verify = False)
    if response_r_year.status_code ==200 :
        print("reviesed_url 请求成功")
    response_r_dict_list = response_r_year.json()#变成一个列表，其中的元素是字典

    """获取年份"""
    print("-----year--------")
    list_year = []
    for each in response_r_dict_list:
        list_year.append(each['name'])

    """获取月份"""
    print("-------month---------")
    list_month = []
    list_month_url = []
    for each in list_year:
        #
        r = requests.get(r_url + '/'+ each,headers=headers,verify = False)
        if r.status_code == 200:
            print(f"{each}年 请求成功")
            response_r_dict_list = r.json()
            for part in response_r_dict_list:
                #
                list_month_url.append(r_url + '/' + each + '/' + part['name'])
                list_month.append(part['name'])
        else:
            list_month.append('')
            print(f"{each}年 跳过")

        sleep(random.uniform(0.5, 1))


    """获取编号"""
    print("-----item_GHSA--------")
    global list_GHSA
    for each in list_month_url:
        month = re.search('/\d{4}/(.*?)$', each).group(1)
        year = re.search('github-reviewed/(.*?)/\d{2}$', each).group(1)
        r = requests.get(each, headers=headers, verify=False)
        if r.status_code == 200:
            print(f"{year}年{month}月 请求成功")

            response_r_dict_list = r.json()
            for part in response_r_dict_list:
                list_GHSA.append(year + '/' + month + '/' + part['name'])
        else:
            list_GHSA.append('')
            print(r.json()['message'])

            print(f"{year}年{month}月 跳过")

        sleep(random.uniform(0.5, 1))

def get_detail(int):
    """获取详细的json格式信息"""
    list_GHSA_2 = []
    print("-----get detailed json info--------")
    """缺失数"""
    miss = 0
    """每个文件的序号  order,从第几条开始爬序号就是几，"""
    """这几行控制爬取的数量"""
    order = 1
    for num in range(0,len(list_GHSA)):
        """控制爬取条数，range(a,b)对应获取 [a,b) 内的所有整数，索引从0开始，这里是从list_GHSA抽出序号a,a+1,a+2,...,b-1的记录加入list_GHSA_2,不改就是慢悠悠地爬9000多条"""
        list_GHSA_2.append(list_GHSA[num])
    # list_GHSA_2.append(list_GHSA[9692])

    data_list = []
    data_dict = {
        'order':[],
        'GHSA_ID':[],
        'advisory_database_url':[],
        'summary':[],
        'modified':[],
        'published':[],
        'CVE':[],
        'CVSS_score':[],
        'CVSS_severity':[],
        'CVSS_base_metrics':[],
        'references':[],
        'details':[],
        'cwe_ids':[],
        'affected':[]

    }

    k = 0
    #start_time = time()
    for item in list_GHSA_2:
        month = re.search('\d{4}/(.*?)/', item).group(1)
        year = re.search('^(.*?)/\d{2}', item).group(1)
        name = re.search('/\d{2}/(.*?)$',item).group(1)
        if k < len(list_GHSA_2):
            """这里k不要超过实际爬取条数，就是 list_GHSA_2的元素个数"""
            r_json = requests.get(json_url + '/' + item + '/' + name + '.json',headers=headers,verify = False)
            if r_json.status_code == 200 :
                print(f"第{order}条 编号{name} 请求成功")
                sleep(0.5)
               #获取CVSS评分
                r_CVSS_score = requests.get(advisory_url + '/' + name, headers=headers, verify=False)
                soup = BeautifulSoup(r_CVSS_score.text,'lxml')
                span = soup.select('div.gutter-lg.gutter-condensed.clearfix > div.col-12.col-md-3.float-left.pt-3.pt-md-0 > div:nth-child(1) > div.d-flex.flex-items-baseline.pb-1 > div > div > span')
                if not span:
                    score = 'None'
                else:
                    score_match = re.search('\w{4}">(.*?)</', str(span))
                    if not score_match:
                        score = "Not match"
                    else:
                        score = score_match.group(1)
                descript_dict = r_json.json()
                descript_dict['CVSS_score'] = score
                descript_dict['url'] = advisory_url + '/' + name
                # GitHub安全咨询数据库的对应链接

                data_list.append(descript_dict)
                # 用于最后写入一个大文件里

                #准备写入csv文件
                data_dict['order'].append(order)

                try:
                    data_dict['GHSA_ID'].append(descript_dict['id'])
                except:
                    data_dict['GHSA_ID'].append('')

                try:
                    data_dict['advisory_database_url'].append(descript_dict['url'])
                except:
                    data_dict['advisory_database_url'].append('')

                try:
                    data_dict['summary'].append(descript_dict['summary'])
                except:
                    data_dict['summary'].append('')

                try:
                    data_dict['modified'].append(descript_dict['modified'])
                except:
                    data_dict['modified'].append('')

                try:
                    data_dict['published'].append(descript_dict['published'])
                except:
                    data_dict['published'].append('')

                try:
                    temp_aliases = []
                    for each in descript_dict['aliases']:
                        temp_aliases.append(each)
                    data_dict['CVE'].append(temp_aliases)
                except:
                    data_dict['CVE'].append('')

                try:
                    data_dict['CVSS_score'].append(descript_dict['CVSS_score'])
                except:
                    data_dict['CVSS_score'].append('')

                try:
                    data_dict['CVSS_severity'].append(descript_dict['database_specific']['severity'])
                except:
                    data_dict['CVSS_severity'].append('')

                temp_severities = []
                for severity in descript_dict['severity']:
                    temp_severities.append(severity['score'])
                data_dict['CVSS_base_metrics'].append(temp_severities)

                try:
                    data_dict['references'].append(descript_dict['references'])
                except:
                    data_dict['references'] = dict()

                try:
                    data_dict['details'].append([descript_dict['details']])
                except:
                    data_dict['details'].append('')

                try:
                    data_dict['affected'].append(descript_dict['affected'])
                except:
                    data_dict['affected'] = dict()

                temp_cwe = []
                # 可能不止一个
                for cwe_id in descript_dict['database_specific']['cwe_ids']:
                    temp_cwe.append(cwe_id)
                data_dict['cwe_ids'].append(temp_cwe)

                """单独写入文件夹"""
                """json是自己建立的文件夹，也可以换成别的"""
                with open('json\\'+ str(order) + '_' + year + '_' + month + '_' + name + '_' + str(int)+'.json','w',encoding='utf-8') as f:
                    json.dump(descript_dict,f,indent=True,ensure_ascii=False)
            else:
                data_list.append({})
                print(f"编号{item} 跳过")
                miss += 1
            order += 1
            k += 1
            """设置每次循环等待多长时间，random.uniform(0.5, 1)随机生成在（a，b）内的一个实数，sleep(c)，等待c秒"""
            sleep(random.uniform(0.5, 1))
        else:
            break

    # end_time = time()
    # print(f'time: {end_time-start_time}')

    print(f'总数:{order-1}')
    print(f'缺失数:{miss}')
    """写入json文件"""
    print("-----input json_file--------")
    with open('GitHub.json', 'w',encoding='utf-8') as f:
        json.dump(data_list, f, indent=True, ensure_ascii=False)
    # ensure_ascii=False确保可以输出中文
    """写入csv文件"""
    print("-----input csv_file--------")
    out = pd.DataFrame(data_dict)  # 使用pandas生成数据框
    out.to_csv('GitHub.csv')  # 输出到csv文件




"-----------定时抽取---------------"

def get_new_detail(int):
    """获取详细的json格式信息"""
    print("-----get detailed json info--------")
    """缺失数"""
    miss = 0
    """每个文件的序号  order,从第几条开始爬序号就是几，"""
    """这几行控制爬取的数量"""
    order = 1
    list_GHSA_2 = []
    for num in range(0,len(list_GHSA)):
        """控制爬取条数，range(a,b)对应获取 [a,b) 内的所有整数，索引从0开始，这里是从list_GHSA抽出序号a,a+1,a+2,...,b-1的记录加入list_GHSA_2,不改就是慢悠悠地爬9000多条"""
        list_GHSA_2.append(list_GHSA[num])
    # list_GHSA_2.append(list_GHSA[1])

    data_list = []
    data_dict = {
        'order':[],
        'GHSA_ID':[],
        'advisory_database_url':[],
        'summary':[],
        'modified':[],
        'published':[],
        'CVE':[],
        'CVSS_score':[],
        'CVSS_severity':[],
        'CVSS_base_metrics':[],
        'references':[],
        'details':[],
        'cwe_ids':[],
        'affected':[]

    }

    k = 0
    # start_time = time()
    for item in list_GHSA_2:
        month = re.search('\d{4}/(.*?)/', item).group(1)
        year = re.search('^(.*?)/\d{2}', item).group(1)
        name = re.search('/\d{2}/(.*?)$',item).group(1)
        if k < len(list_GHSA_2):
            """这里k不要超过实际爬取条数，就是 list_GHSA_2的元素个数"""
            r_json = requests.get(json_url + '/' + item + '/' + name + '.json',headers=headers,verify = False)
            if r_json.status_code == 200 :
                print(f'{round(k/len(list_GHSA_2),2)}%')
                #print(f"第{order}条 编号{name} 请求成功")

                descript_dict = r_json.json()
                modify_time = descript_dict['modified']
                modify_time = modify_time.replace('T', ' ')
                modify_time = modify_time.replace('Z', '')
                modify_time = modify_time.strip()
                modify_time = datetime.strptime(modify_time, '%Y-%m-%d %H:%M:%S')
                if modify_time > time0:
                   #获取CVSS评分
                    r_CVSS_score = requests.get(advisory_url + '/' + name, headers=headers, verify=False)
                    soup = BeautifulSoup(r_CVSS_score.text,'lxml')
                    span = soup.select('div.gutter-lg.gutter-condensed.clearfix > div.col-12.col-md-3.float-left.pt-3.pt-md-0 > div:nth-child(1) > div.d-flex.flex-items-baseline.pb-1 > div > div > span')
                    if not span:
                        score = 'None'
                    else:
                        score_match = re.search('\w{4}">(.*?)</', str(span))
                        if not score_match:
                            score = "Not match"
                        else:
                            score = score_match.group(1)

                    descript_dict['CVSS_score'] = score
                    descript_dict['url'] = advisory_url + '/' + name
                    # GitHub安全咨询数据库的对应链接

                    data_list.append(descript_dict)
                    # 用于最后写入一个大文件里

                    #准备写入csv文件
                    data_dict['order'].append(order)

                    try:
                        data_dict['GHSA_ID'].append(descript_dict['id'])
                    except:
                        data_dict['GHSA_ID'].append('')

                    try:
                        data_dict['advisory_database_url'].append(descript_dict['url'])
                    except:
                        data_dict['advisory_database_url'].append('')

                    try:
                        data_dict['summary'].append(descript_dict['summary'])
                    except:
                        data_dict['summary'].append('')

                    try:
                        data_dict['modified'].append(descript_dict['modified'])
                    except:
                        data_dict['modified'].append('')

                    try:
                        data_dict['published'].append(descript_dict['published'])
                    except:
                        data_dict['published'].append('')

                    try:
                        temp_aliases = []
                        for each in descript_dict['aliases']:
                            temp_aliases.append(each)
                        data_dict['CVE'].append(temp_aliases)
                    except:
                        data_dict['CVE'].append('')

                    try:
                        data_dict['CVSS_score'].append(descript_dict['CVSS_score'])
                    except:
                        data_dict['CVSS_score'].append('')

                    try:
                        data_dict['CVSS_severity'].append(descript_dict['database_specific']['severity'])
                    except:
                        data_dict['CVSS_severity'].append('')

                    temp_severities = []
                    for severity in descript_dict['severity']:
                        temp_severities.append(severity['score'])
                    data_dict['CVSS_base_metrics'].append(temp_severities)

                    try:
                        data_dict['references'].append(descript_dict['references'])
                    except:
                        data_dict['references'] = dict()

                    try:
                        data_dict['details'].append([descript_dict['details']])
                    except:
                        data_dict['details'].append('')

                    try:
                        data_dict['affected'].append(descript_dict['affected'])
                    except:
                        data_dict['affected'] = dict()

                    temp_cwe = []
                    # 可能不止一个
                    for cwe_id in descript_dict['database_specific']['cwe_ids']:
                        temp_cwe.append(cwe_id)
                    data_dict['cwe_ids'].append(temp_cwe)

                    """单独写入文件夹"""
                    """json是自己建立的文件夹，也可以换成别的"""
                    with open('json\\' + str(order) + '_' + year + '_' + month + '_' + name + '_' + str(int) + '.json',
                              'w',encoding='utf-8') as f:
                        json.dump(descript_dict, f, indent=True, ensure_ascii=False)

                else:
                    data_list.append(dict())
                    data_dict['order'].append(order)
                    data_dict['GHSA_ID'].append('')
                    data_dict['advisory_database_url'].append('')
                    data_dict['summary'].append('')
                    data_dict['modified'].append('')
                    data_dict['published'].append('')
                    data_dict['CVE'].append('')
                    data_dict['CVSS_score'].append('')
                    data_dict['CVSS_severity'].append('')
                    data_dict['CVSS_base_metrics'].append('')
                    data_dict['references'] = dict()
                    data_dict['details'].append('')
                    data_dict['affected'] = dict()
                    data_dict['cwe_ids'].append('')


            else:
                data_list.append({})
                print(f"编号{item} 跳过")
                miss += 1
            order += 1
            k += 1
            """设置每次循环等待多长时间，random.uniform(0.5, 1)随机生成在（a，b）内的一个实数，sleep(c)，等待c秒"""
            sleep(random.uniform(0.5, 1))
        else:
            break
    # end_time = time()
    # print(f'time: {end_time-start_time}')
    print(f'总数:{order-1}')
    print(f'缺失数:{miss}')
    """写入json文件"""
    print("-----input json_file--------")
    with open('GitHub.json', 'w',encoding='utf-8') as f:
        json.dump(data_list, f, indent=True, ensure_ascii=False)
    # ensure_ascii=False确保可以输出中文
    """写入csv文件"""
    print("-----input csv_file--------")
    out = pd.DataFrame(data_dict)  # 使用pandas生成数据框
    out.to_csv('GitHub.csv')  # 输出到csv文件

'''记录上次爬取的时间，下次爬取时把修改时间和上次记录时间比较，如果修改时间在上次爬取时间之后，就认为更新了'''
'''把新数据爬取下来，未更新数据用空格表示，方便下次查找更新的部分'''
def data_update(int):
    time_temp = datetime.now()
    print('运行时间: %s' % time_temp)
    print('正在更新')
    get_first_info()
    get_new_detail(int)
    global time0
    time0=time_temp
    int += 1
    print('新数据已存储')


int = 1
'''初次爬取'''
get_first_info()
get_detail(0)
time0 = datetime.now()
'''定时爬取'''
scheduler = BlockingScheduler()
scheduler.add_job(data_update, trigger='cron', day_of_week='mon',hour=1,minute=30, id="dosth", args=[int], timezone="Asia/Shanghai")
"""设置每周一，凌晨1：30自动爬取"""
scheduler.start()