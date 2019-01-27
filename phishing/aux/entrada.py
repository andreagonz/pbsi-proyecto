import json

def lee_txt(f):
    return [x.strip() for x in f.split('\n')]

def lee_csv(f):
    urls = []
    for x in f.split('\n'):
        for y in x.split(','):
            y = y.strip()
            if y.startswith('http://') or y.startswith('https://'):
                urls.append(y)
    return urls

def itera_json(j, e):
    if isinstance(j, dict):
        for k,v in j.items():
            itera_json(v, e)
    elif isinstance(j, list):
        for x in j:
            itera_json(x, e)
    else:
        e.append(j.strip() if isinstance(j, str) else j)
    
def lee_json(f):
    urls = []
    j = json.loads(f)
    e = []
    itera_json(j, e)
    for y in e:
        y = str(y)
        if y.startswith('http://') or y.startswith('https://'):
            urls.append(y)
    return urls
