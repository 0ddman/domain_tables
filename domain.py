import requests
import random
import json
import IPy
import os
import prettytable as pt
import argparse

def api_subdomains(domain,apikey,pages):
    url = "https://api.securitytrails.com/v1/domains/list"
    querystring = {"include_ips":"true","page":"1","scroll":"false"}
    querystring["page"]=pages
    payload = "{\"filter\":{\"apex_domain\":\""+str(domain)+"\"}}"
    headers = {'content-type': 'application/json',
               'apikey': "xxxxxx"}   #（1）此处只要填一个api
    headers['apikey']=apikey
    response = requests.request("POST", url, data=payload, headers=headers, params=querystring)
    txt_name = domain + '_' + pages
    direct = os.getcwd()+"\subdomain\\" + domain
    path = os.getcwd()+"\subdomain\\" + domain+'\\' +txt_name+'.txt'
    path= r'{0}'.format(path)
    if not os.path.exists(direct):
        os.makedirs(direct)
    print(txt_name)

    with open(path, 'w',encoding='utf8') as f:
        b = f.write(response.text)

def path(domain):
    txt_name = domain + '_1'
    path_1st_txt = os.getcwd() + "\subdomain\\" + domain + '\\' + txt_name + '.txt'
    direct = os.getcwd() + "\subdomain\\" + domain

    if not os.path.exists(direct):
        os.makedirs(direct)
    path = [path_1st_txt,direct]
    return path

def Max_Pages(path):
    with open(path[0], 'r',encoding='utf8') as f:
        json_data = f.read()
        data=json.loads(json_data)
        return data['meta']['max_page']

def api_usage(apikey):
    url = "https://api.securitytrails.com/v1/account/usage"
    headers = {
        'accept': "application/json",
        'apikey': "xxxxxxxxxx"  # （2）此处也需要一个apikey
    }
    headers['apikey'] = apikey
    response = requests.request("GET", url, headers=headers)
    response = dict(json.loads(response.text))
    if 'current_monthly_usage' in response.keys():
        response1 =[response['current_monthly_usage'],response['allowed_monthly_usage']]
        return response1
    else:
        response1 = [50,50]
        return response1

def api_remain(api_key):
    api_usage_list = api_usage(api_key)  
    api_remain_num = api_usage_list[1] - api_usage_list[0]
    return api_remain_num

def api_key_random(API_LIST):
    api_key = random.choice(API_LIST)
    return api_key

def useful_api():
    if API_LIST != []:
        api_key = api_key_random(API_LIST)
        api_remain_num = api_remain(api_key)
        while api_remain_num == 0:
            API_LIST.remove(api_key)
            api_key = api_key_random(API_LIST)
            api_remain_num = api_remain(api_key)

        else:
            return api_key
    else:
        print('API已用完')

def domain_list(path,max_page,domain):
    Domain=[]
    Domain_ip=[]
    for i in range(max_page):   
        txt_name = domain + '_' + str(int(i)+1)
        rule_path = path+'\\'+txt_name+'.txt'
        with open(rule_path, 'r',encoding='utf8') as f:
            json_data = f.read()
            data=json.loads(json_data)
            for k in range(len(data['records'])):
                x_domain = data['records'][k]['hostname']
                ip = data['records'][k]['ips']
                Domain.append(x_domain)
                Domain_ip.append(ip)
    return [Domain,Domain_ip]

def subdomains_txt(Domain,Domain_ip,path,tb):
    rule_path = path + '\\subdomains.txt'
    with open(rule_path,'w') as p:
        for d in range(len(Domain)):
            i=len(Domain_ip[d])
            if i>0:
                domain_ip_real = Domain_ip[d][0]
            else:
                domain_ip_real = ''

            for e in range(len(Domain_ip[d])):
                r = ','
                if i>e+1:
                    domain_ip_real=str(Domain_ip[d][e])+r+domain_ip_real
            tb.add_row([Domain[d],domain_ip_real])
        p.write(str(tb))
    return tb

def c_ip(domain_ip):
        ip_dict = {}
        for i in range(len(domain_ip)):
            for k in range(len(domain_ip[i])):
                ip_netmask = str(IPy.IP(str(domain_ip[i][k])).make_net('255.255.255.0'))
                # print(ip_netmask,type(str(ip_netmask)))
                if ip_netmask not in ip_dict.keys():
                    ip_dict[ip_netmask] = 1
                else:
                    ip_dict[ip_netmask] = ip_dict[ip_netmask]+1
        return ip_dict

def c_ip_txt(domain,ip_dict):
    #写入文本
    direct = os.getcwd()+"\subdomain\\" + domain
    path = os.getcwd()+"\subdomain\\" + domain+'\\' +'subdomains.txt'
    path= r'{0}'.format(path)

    if not os.path.exists(direct):
        os.makedirs(direct)

    g = sorted(ip_dict.items(),key=lambda x:x[1],reverse=True)

    bc = pt.PrettyTable()
    bc.field_names = ["network","count"]
    bc.align = 'l'

    g = sorted(ip_dict.items(),key=lambda x:x[1],reverse=True)

    bc = pt.PrettyTable()
    bc.field_names = ["network","count"]
    bc.align = 'l'

    with open(path, 'a') as f:
        for i in g:
            bc.add_row([i[0],i[1]])
        s = "\n"+ str(bc)
        f.write(s)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d','--domain', metavar='domain', required=True,help='find subdomain and ip')
    args = vars(parser.parse_args())
    domain = str(args['domain'])

    pages='1'
    API_LIST =['xxxxx','xxxxxxxxx']   #（3）这里填上你的api key列表，因为会有次数限制，建议多注册一些轮循

    apikey = useful_api()
    path = path(domain)        
    api_subdomains(domain,apikey,pages)
    max_page = Max_Pages(path)
    for i in range(int(max_page)-1):
        apikey = useful_api()
        pages = str(i+2)
        api_subdomains(domain, apikey, pages)

    list = domain_list(path[1],max_page,domain)
    tb = pt.PrettyTable()
    tb.field_names = ["domain","domain_ip"]
    tb.align = 'l'
    subdomains_txt(list[0],list[1],path[1],tb)
    c_ip = c_ip(list[1])
    c_ip_txt = c_ip_txt(domain,c_ip)



