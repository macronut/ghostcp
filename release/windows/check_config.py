f = open('config')
hostsmap = {}

level = 0
for line in f.readlines():
    line = line.replace('\n', '')
    if line == '':
        pass
    elif line[0] == '#':
        if line == '#LEVEL2':
            level = 2
    else:
        v = line.split('=')
        hostsmap[v[0]] = level
f.close()

f = open('config')
level = 0
out = ""
domainmap={}
for line in f.readlines():
    line = line.replace('\n', '')
    if line == '':
        out += line + '\n'
    elif line[0] == '#':
        out += line + '\n'
        if line == '#LEVEL2':
            level = 2
    else:
        v = line.split('=')
        has_domain = False
        if level < 2 and hostsmap[v[0]] > 1:
            continue
        try:
            has_domain = domainmap[v[0]]
        except:
            out += line + '\n'
            domainmap[v[0]] = True

f.close()
f = open('config.new', 'w')
f.write(out)
f.close()
