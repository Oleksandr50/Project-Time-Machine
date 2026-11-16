"""AST-based review hints, with stable identities and no source excerpts or secret values."""
import ast
import hashlib
import json
import re
from .scanner import category

SEVERITIES=('critical','high','medium','low','info')
RULES={
 'shell':('high','subprocess'), 'dynamic':('high','execution'),
 'timeout':('medium','http'), 'tls':('high','http'), 'bind':('medium','bind'),
 'sql':('high','sql'), 'secret':('high','secrets'), 'exit':('low','exit'),
 'syntax':('info','syntax'), 'read':('info','parse'), 'limit':('info','parse'),
 'plugin':('info','parse'), 'secret_file':('info','secrets'), 'private_key':('critical','secrets')}


def identity(rule,path,anchor):
    return hashlib.sha256(json.dumps([rule,path,anchor],ensure_ascii=True,separators=(',',':')).encode()).hexdigest()


def finding(rule,path,line=None,anchor=''):
    severity,cat=RULES[rule]
    return dict(severity=severity,category=cat,path=path,lineno=line,
                message='rules.'+rule+'.message',evidence=None,rule_id='python.'+rule,
                fingerprint=identity('python.'+rule,path,anchor),
                explanation='rules.'+rule+'.why',remediation='rules.'+rule+'.fix',
                analyzer_id='python',file_category=category(path),occurrences=[line] if line else [])


def deduplicate(findings):
    grouped={}
    for row in findings:
        row=dict(row)
        key=row.get('fingerprint') or identity('legacy',row.get('path'),[row.get('category'),row.get('lineno'),row.get('message')])
        row['fingerprint']=key
        if key in grouped:
            grouped[key]['occurrences']=sorted(set(grouped[key].get('occurrences',[])+row.get('occurrences',[])))[:1000]
        else:grouped[key]=row
    return list(grouped.values())


class Shape(ast.NodeTransformer):
    def visit_Constant(self,node):
        return ast.copy_location(ast.Constant(value='<literal>'),node)


def shape(node):
    # Reparse a structural dump through deepcopy, never change the AST used for entities.
    import copy
    return ast.dump(Shape().visit(copy.deepcopy(node)),include_attributes=False)


def inspect_tree(tree,path):
    result=[];aliases={}
    for n in ast.walk(tree):
        if isinstance(n,ast.Import):
            for a in n.names:aliases[a.asname or a.name.split('.')[0]]=a.name if a.asname else a.name.split('.')[0]
        elif isinstance(n,ast.ImportFrom):
            for a in n.names:aliases[a.asname or a.name]=(n.module or '')+'.'+a.name
    def name(n):
        if isinstance(n,ast.Name):return aliases.get(n.id,n.id)
        if isinstance(n,ast.Attribute):return name(n.value)+'.'+n.attr
        return ''
    def emit(rule,n):result.append(finding(rule,path,getattr(n,'lineno',None),shape(n)))
    for n in ast.walk(tree):
        if isinstance(n,ast.Call):
            call=name(n.func);kw={x.arg:x.value for x in n.keywords}
            if call=='os.system' or call.startswith('subprocess.') and isinstance(kw.get('shell'),ast.Constant) and kw['shell'].value is True:emit('shell',n)
            if call in ('eval','exec','pickle.loads','pickle.load','yaml.unsafe_load'):emit('dynamic',n)
            if call in ('requests.get','requests.post','requests.put','requests.delete','requests.request','httpx.get','httpx.post'):
                if 'timeout' not in kw or isinstance(kw['timeout'],ast.Constant) and kw['timeout'].value is None:emit('timeout',n)
                if isinstance(kw.get('verify'),ast.Constant) and kw['verify'].value is False:emit('tls',n)
            if call in ('os._exit','sys.exit'):emit('exit',n)
            if call.endswith(('.execute','.executemany')) and n.args:
                value=n.args[0]
                if isinstance(value,(ast.JoinedStr,ast.BinOp)) or isinstance(value,ast.Call) and isinstance(value.func,ast.Attribute) and value.func.attr=='format':emit('sql',n)
        if isinstance(n,(ast.Assign,ast.AnnAssign)):
            targets=n.targets if isinstance(n,ast.Assign) else [n.target]
            if isinstance(n.value,ast.Constant) and isinstance(n.value.value,str) and len(n.value.value)>=8:
                if any(re.search(r'(?i)(?:token|password|passwd|secret|api_?key)',name(x)) for x in targets):emit('secret',n)
        if isinstance(n,ast.Constant) and isinstance(n.value,str):
            if n.value=='0.0.0.0':emit('bind',n)
            if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',n.value):emit('private_key',n)
    return deduplicate(result)
