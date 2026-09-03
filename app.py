from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
from http.cookies import SimpleCookie
from html import escape
from pathlib import Path
from datetime import datetime, timedelta
import sqlite3, hashlib, secrets, os, argparse

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'blog.db'
STATIC_DIR = BASE_DIR / 'static'


def now_iso():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 150000).hex()
    return f'{salt}${digest}'


def verify_password(password, stored):
    try:
        salt, digest = stored.split('$', 1)
    except ValueError:
        return False
    test = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 150000).hex()
    return secrets.compare_digest(test, digest)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    conn = db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        visibility TEXT NOT NULL CHECK(visibility IN ('public','request')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS follows(
        follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        followed_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        PRIMARY KEY(follower_id, followed_id)
    );
    CREATE TABLE IF NOT EXISTS tags(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS post_tags(
        post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
        PRIMARY KEY(post_id, tag_id)
    );
    CREATE TABLE IF NOT EXISTS comments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS access_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
        created_at TEXT NOT NULL,
        UNIQUE(post_id, requester_id)
    );
    ''')
    if conn.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        users = [
            ('demo', 'Демо-пользователь', hash_password('demo123'), now_iso()),
            ('author', 'Анна Петрова', hash_password('author123'), now_iso()),
            ('student', 'Илья Смирнов', hash_password('student123'), now_iso()),
        ]
        conn.executemany('INSERT INTO users(username,display_name,password_hash,created_at) VALUES(?,?,?,?)', users)
        ids = {r['username']: r['id'] for r in conn.execute('SELECT id,username FROM users')}
        posts = [
            (ids['author'], 'Как я организую учебные заметки', 'Короткие заметки удобно хранить по темам: отдельно идеи, ссылки, задачи и выводы. Такой подход помогает быстро возвращаться к материалу.', 'public', now_iso(), now_iso()),
            (ids['student'], 'Мой первый проект на Python', 'В проекте я использовал встроенный HTTP-сервер, SQLite и обычный JavaScript. Главной задачей было связать формы, маршруты и данные.', 'public', now_iso(), now_iso()),
            (ids['author'], 'Черновик будущей статьи', 'Эта публикация открывается только после запроса доступа. В ней хранятся рабочие заметки, которые автор пока не публикует для всех.', 'request', now_iso(), now_iso()),
        ]
        conn.executemany('INSERT INTO posts(author_id,title,body,visibility,created_at,updated_at) VALUES(?,?,?,?,?,?)', posts)
        conn.execute('INSERT INTO follows(follower_id,followed_id) VALUES(?,?)', (ids['demo'], ids['author']))
        tag_map = {1:['обучение','организация'],2:['python','веб-разработка'],3:['черновик']}
        for post_id, names in tag_map.items():
            for name in names:
                conn.execute('INSERT OR IGNORE INTO tags(name) VALUES(?)', (name,))
                tid = conn.execute('SELECT id FROM tags WHERE name=?',(name,)).fetchone()['id']
                conn.execute('INSERT OR IGNORE INTO post_tags(post_id,tag_id) VALUES(?,?)',(post_id,tid))
        conn.execute('INSERT INTO comments(post_id,user_id,body,created_at) VALUES(?,?,?,?)', (1, ids['demo'], 'Полезная идея с разделением заметок по темам.', now_iso()))
    conn.commit(); conn.close()


def page(title, body, user=None, flash=''):
    auth = ''
    if user:
        auth = f'''<span class="user-chip">{escape(user['display_name'])}</span>
        <a href="/feed">Моя лента</a><a href="/users">Пользователи</a><a href="/requests">Запросы</a><a href="/post/new" class="btn small">Новый пост</a><a href="/logout">Выйти</a>'''
    else:
        auth = '<a href="/login">Войти</a><a href="/register" class="btn small">Регистрация</a>'
    flash_html = f'<div class="flash">{escape(flash)}</div>' if flash else ''
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)} — ПрактикаBlog</title><link rel="stylesheet" href="/static/style.css"></head><body>
    <header><div class="wrap nav"><a class="brand" href="/">Практика<span>Blog</span></a><nav><a href="/">Публичные посты</a>{auth}</nav></div></header>
    <main class="wrap">{flash_html}{body}</main><footer><div class="wrap">Учебное веб-приложение для производственной практики</div></footer></body></html>'''


def redirect(handler, location, cookie=None):
    handler.send_response(303); handler.send_header('Location', location)
    if cookie: handler.send_header('Set-Cookie', cookie)
    handler.end_headers()


def tags_for(conn, post_id):
    return [r['name'] for r in conn.execute('SELECT t.name FROM tags t JOIN post_tags pt ON pt.tag_id=t.id WHERE pt.post_id=? ORDER BY t.name',(post_id,))]


def can_view(conn, post, user):
    if post['visibility'] == 'public': return True
    if user and user['id'] == post['author_id']: return True
    if user:
        row = conn.execute('SELECT status FROM access_requests WHERE post_id=? AND requester_id=?',(post['id'], user['id'])).fetchone()
        return bool(row and row['status']=='approved')
    return False


def post_card(conn, p, show_private=False):
    tags = ''.join(f'<a class="tag" href="/?tag={quote(t)}">#{escape(t)}</a>' for t in tags_for(conn,p['id']))
    badge = '<span class="badge private">по запросу</span>' if p['visibility']=='request' else '<span class="badge">публичный</span>'
    body = escape(p['body'][:220]) + ('…' if len(p['body'])>220 else '')
    return f'''<article class="card"><div class="meta">{escape(p['display_name'])} · {escape(p['created_at'][:16])} {badge}</div><h2><a href="/post/{p['id']}">{escape(p['title'])}</a></h2><p>{body}</p><div class="tags">{tags}</div></article>'''


class Handler(BaseHTTPRequestHandler):
    server_version = 'PracticeBlog/1.0'

    def log_message(self, fmt, *args):
        print('[blog]', fmt % args)

    def parse_post(self):
        length = int(self.headers.get('Content-Length','0') or 0)
        data = self.rfile.read(length).decode('utf-8', errors='replace')
        parsed = parse_qs(data, keep_blank_values=True)
        return {k:v[-1] for k,v in parsed.items()}

    def current_user(self, conn):
        cookie = SimpleCookie(self.headers.get('Cookie',''))
        if 'session' not in cookie: return None
        token = cookie['session'].value
        row = conn.execute('''SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?''',(token, now_iso())).fetchone()
        return row

    def send_html(self, html, status=200):
        data = html.encode('utf-8'); self.send_response(status); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        parsed=urlparse(self.path); path=parsed.path; q={k:v[-1] for k,v in parse_qs(parsed.query).items()}
        if path.startswith('/static/'):
            fp = STATIC_DIR / path[len('/static/'):]
            if fp.exists() and fp.is_file():
                data=fp.read_bytes(); ctype='text/css' if fp.suffix=='.css' else 'application/octet-stream'; self.send_response(200); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data); return
            self.send_error(404); return
        conn=db(); user=self.current_user(conn)
        try:
            if path=='/':
                tag=q.get('tag',''); sort=q.get('sort','newest'); order={'newest':'p.created_at DESC','oldest':'p.created_at ASC','title':'p.title COLLATE NOCASE ASC'}.get(sort,'p.created_at DESC')
                sql='''SELECT p.*,u.display_name FROM posts p JOIN users u ON u.id=p.author_id WHERE p.visibility='public' '''; params=[]
                if tag:
                    sql += 'AND EXISTS(SELECT 1 FROM post_tags pt JOIN tags t ON t.id=pt.tag_id WHERE pt.post_id=p.id AND t.name=?) '; params.append(tag)
                sql += f'ORDER BY {order}'
                posts=conn.execute(sql,params).fetchall(); cards=''.join(post_card(conn,p) for p in posts) or '<div class="empty">Публикаций не найдено.</div>'
                filterbar=f'''<form class="filterbar" method="get"><input name="tag" placeholder="Тег" value="{escape(tag)}"><select name="sort"><option value="newest" {'selected' if sort=='newest' else ''}>Сначала новые</option><option value="oldest" {'selected' if sort=='oldest' else ''}>Сначала старые</option><option value="title" {'selected' if sort=='title' else ''}>По названию</option></select><button>Применить</button></form>'''
                body=f'<section class="hero"><div><h1>Публичные публикации</h1><p>Читайте посты, выбирайте темы по тегам и общайтесь в комментариях.</p></div></section>{filterbar}<section class="grid">{cards}</section>'
                self.send_html(page('Публичные публикации',body,user)); return
            if path=='/register':
                body='''<div class="form-card"><h1>Регистрация</h1><form method="post"><label>Логин<input name="username" required minlength="3"></label><label>Имя<input name="display_name" required></label><label>Пароль<input type="password" name="password" required minlength="6"></label><button class="btn">Создать аккаунт</button></form></div>'''; self.send_html(page('Регистрация',body,user)); return
            if path=='/login':
                body='''<div class="form-card"><h1>Вход</h1><p class="hint">Демо: demo / demo123</p><form method="post"><label>Логин<input name="username" required></label><label>Пароль<input type="password" name="password" required></label><button class="btn">Войти</button></form></div>'''; self.send_html(page('Вход',body,user)); return
            if path=='/logout':
                cookie=SimpleCookie(self.headers.get('Cookie','')); token=cookie['session'].value if 'session' in cookie else ''
                if token: conn.execute('DELETE FROM sessions WHERE token=?',(token,)); conn.commit()
                redirect(self,'/','session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'); return
            if path=='/feed':
                if not user: redirect(self,'/login'); return
                posts=conn.execute('''SELECT p.*,u.display_name FROM posts p JOIN users u ON u.id=p.author_id JOIN follows f ON f.followed_id=p.author_id WHERE f.follower_id=? AND p.visibility='public' ORDER BY p.created_at DESC''',(user['id'],)).fetchall()
                cards=''.join(post_card(conn,p) for p in posts) or '<div class="empty">Подпишитесь на пользователей, чтобы сформировать персональную ленту.</div>'
                self.send_html(page('Моя лента',f'<div class="page-head"><h1>Лента по подпискам</h1><p>Список формируется только из публичных постов пользователей, на которых вы подписаны.</p></div><section class="grid">{cards}</section>',user)); return
            if path=='/users':
                if not user: redirect(self,'/login'); return
                rows=conn.execute('SELECT * FROM users WHERE id<>? ORDER BY display_name',(user['id'],)).fetchall(); items=[]
                for r in rows:
                    followed=conn.execute('SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?',(user['id'],r['id'])).fetchone()
                    action='unfollow' if followed else 'follow'; label='Отписаться' if followed else 'Подписаться'
                    items.append(f'''<div class="user-row"><div><strong>{escape(r['display_name'])}</strong><div class="muted">@{escape(r['username'])}</div></div><form method="post" action="/{action}?user_id={r['id']}"><button class="{'ghost' if followed else 'btn small'}">{label}</button></form></div>''')
                self.send_html(page('Пользователи',f'<div class="page-head"><h1>Пользователи</h1><p>Подписки влияют на содержимое персональной ленты.</p></div><div class="list-card">{"".join(items)}</div>',user)); return
            if path=='/post/new':
                if not user: redirect(self,'/login'); return
                self.send_html(page('Новый пост', self.post_form(), user)); return
            if path.startswith('/post/') and path.endswith('/edit'):
                if not user: redirect(self,'/login'); return
                try: pid=int(path.split('/')[2])
                except: self.send_error(404); return
                p=conn.execute('SELECT * FROM posts WHERE id=?',(pid,)).fetchone()
                if not p or p['author_id']!=user['id']: self.send_error(403); return
                self.send_html(page('Редактирование', self.post_form(p, ', '.join(tags_for(conn,pid))), user)); return
            if path.startswith('/post/'):
                try: pid=int(path.split('/')[2])
                except: self.send_error(404); return
                p=conn.execute('SELECT p.*,u.display_name,u.username FROM posts p JOIN users u ON u.id=p.author_id WHERE p.id=?',(pid,)).fetchone()
                if not p: self.send_error(404); return
                if not can_view(conn,p,user):
                    status=None
                    if user:
                        rq=conn.execute('SELECT status FROM access_requests WHERE post_id=? AND requester_id=?',(pid,user['id'])).fetchone(); status=rq['status'] if rq else None
                    if not user: action='<a class="btn" href="/login">Войти и запросить доступ</a>'
                    elif status=='pending': action='<div class="notice">Запрос уже отправлен и ожидает решения автора.</div>'
                    elif status=='rejected': action='<div class="notice">Автор отклонил запрос. Повторный запрос можно отправить после изменения статуса автором.</div>'
                    else: action=f'<form method="post" action="/post/{pid}/request"><button class="btn">Запросить доступ</button></form>'
                    body=f'<div class="form-card"><span class="badge private">по запросу</span><h1>{escape(p["title"])}</h1><p>Автор: {escape(p["display_name"])}</p><p>Содержимое скрыто. Для просмотра необходимо разрешение автора.</p>{action}</div>'
                    self.send_html(page('Закрытый пост',body,user)); return
                tag_html=''.join(f'<span class="tag">#{escape(t)}</span>' for t in tags_for(conn,pid))
                comments=conn.execute('SELECT c.*,u.display_name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.created_at',(pid,)).fetchall()
                comm_html=''.join(f'<div class="comment"><strong>{escape(c["display_name"])}</strong><span>{escape(c["created_at"][:16])}</span><p>{escape(c["body"])}</p></div>' for c in comments) or '<p class="muted">Комментариев пока нет.</p>'
                edit=''
                if user and user['id']==p['author_id']:
                    edit=f'<div class="actions"><a class="ghost" href="/post/{pid}/edit">Редактировать</a><form method="post" action="/post/{pid}/delete" onsubmit="return confirm(\'Удалить пост?\')"><button class="danger">Удалить</button></form></div>'
                comment_form=f'<form class="comment-form" method="post" action="/post/{pid}/comment"><textarea name="body" required placeholder="Напишите комментарий"></textarea><button class="btn">Отправить</button></form>' if user else '<p><a href="/login">Войдите</a>, чтобы оставить комментарий.</p>'
                body=f'''<article class="post-full"><div class="meta">{escape(p['display_name'])} · {escape(p['created_at'][:16])}</div><h1>{escape(p['title'])}</h1><div class="tags">{tag_html}</div><div class="post-body">{escape(p['body']).replace(chr(10),'<br>')}</div>{edit}</article><section class="comments"><h2>Комментарии</h2>{comm_html}{comment_form}</section>'''
                self.send_html(page(p['title'],body,user)); return
            if path=='/requests':
                if not user: redirect(self,'/login'); return
                rows=conn.execute('''SELECT ar.id,ar.status,ar.created_at,p.title,u.display_name FROM access_requests ar JOIN posts p ON p.id=ar.post_id JOIN users u ON u.id=ar.requester_id WHERE p.author_id=? ORDER BY ar.created_at DESC''',(user['id'],)).fetchall()
                items=[]
                for r in rows:
                    controls=''
                    if r['status']=='pending':
                        controls=f'''<form method="post" action="/request/{r['id']}/approve"><button class="btn small">Разрешить</button></form><form method="post" action="/request/{r['id']}/reject"><button class="ghost">Отклонить</button></form>'''
                    items.append(f'<div class="request-row"><div><strong>{escape(r["display_name"])}</strong> запрашивает «{escape(r["title"])}»<div class="muted">Статус: {escape(r["status"])}</div></div><div class="actions">{controls}</div></div>')
                self.send_html(page('Запросы',f'<div class="page-head"><h1>Запросы на скрытые посты</h1></div><div class="list-card">{"".join(items) if items else "<div class=empty>Запросов пока нет.</div>"}</div>',user)); return
            self.send_error(404)
        finally:
            conn.close()

    def post_form(self,p=None,tags=''):
        title=escape(p['title']) if p else ''; body=escape(p['body']) if p else ''; vis=p['visibility'] if p else 'public'; action=f'/post/{p["id"]}/edit' if p else '/post/new'
        return f'''<div class="form-card wide"><h1>{'Редактирование поста' if p else 'Новый пост'}</h1><form method="post" action="{action}"><label>Заголовок<input name="title" value="{title}" required></label><label>Текст<textarea name="body" rows="10" required>{body}</textarea></label><label>Теги через запятую<input name="tags" value="{escape(tags)}" placeholder="python, практика, заметки"></label><label>Доступ<select name="visibility"><option value="public" {'selected' if vis=='public' else ''}>Публичный</option><option value="request" {'selected' if vis=='request' else ''}>Только по запросу</option></select></label><button class="btn">Сохранить</button></form></div>'''

    def do_POST(self):
        parsed=urlparse(self.path); path=parsed.path; q={k:v[-1] for k,v in parse_qs(parsed.query).items()}; form=self.parse_post(); conn=db(); user=self.current_user(conn)
        try:
            if path=='/register':
                username=form.get('username','').strip().lower(); display=form.get('display_name','').strip(); password=form.get('password','')
                if len(username)<3 or len(password)<6 or not display: self.send_html(page('Ошибка','<div class="notice">Проверьте заполнение формы.</div>')); return
                try:
                    conn.execute('INSERT INTO users(username,display_name,password_hash,created_at) VALUES(?,?,?,?)',(username,display,hash_password(password),now_iso())); conn.commit()
                except sqlite3.IntegrityError:
                    self.send_html(page('Ошибка','<div class="notice">Такой логин уже занят.</div>')); return
                redirect(self,'/login'); return
            if path=='/login':
                row=conn.execute('SELECT * FROM users WHERE username=?',(form.get('username','').strip().lower(),)).fetchone()
                if not row or not verify_password(form.get('password',''),row['password_hash']): self.send_html(page('Вход','<div class="notice">Неверный логин или пароль.</div>')); return
                token=secrets.token_urlsafe(32); exp=(datetime.now()+timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S'); conn.execute('INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)',(token,row['id'],exp)); conn.commit(); redirect(self,'/feed',f'session={token}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax'); return
            if not user: redirect(self,'/login'); return
            if path in ('/follow','/unfollow'):
                try: target=int(q.get('user_id','0'))
                except: target=0
                if target and target!=user['id']:
                    if path=='/follow': conn.execute('INSERT OR IGNORE INTO follows(follower_id,followed_id) VALUES(?,?)',(user['id'],target))
                    else: conn.execute('DELETE FROM follows WHERE follower_id=? AND followed_id=?',(user['id'],target))
                    conn.commit()
                redirect(self,'/users'); return
            if path=='/post/new':
                title=form.get('title','').strip(); body=form.get('body','').strip(); vis=form.get('visibility','public') if form.get('visibility') in ('public','request') else 'public'
                if not title or not body: self.send_html(page('Ошибка','<div class="notice">Заголовок и текст обязательны.</div>',user)); return
                cur=conn.execute('INSERT INTO posts(author_id,title,body,visibility,created_at,updated_at) VALUES(?,?,?,?,?,?)',(user['id'],title,body,vis,now_iso(),now_iso())); pid=cur.lastrowid; self.save_tags(conn,pid,form.get('tags','')); conn.commit(); redirect(self,f'/post/{pid}'); return
            if path.startswith('/post/') and path.endswith('/edit'):
                pid=int(path.split('/')[2]); p=conn.execute('SELECT * FROM posts WHERE id=?',(pid,)).fetchone()
                if not p or p['author_id']!=user['id']: self.send_error(403); return
                title=form.get('title','').strip(); body=form.get('body','').strip(); vis=form.get('visibility','public') if form.get('visibility') in ('public','request') else 'public'
                conn.execute('UPDATE posts SET title=?,body=?,visibility=?,updated_at=? WHERE id=?',(title,body,vis,now_iso(),pid)); conn.execute('DELETE FROM post_tags WHERE post_id=?',(pid,)); self.save_tags(conn,pid,form.get('tags','')); conn.commit(); redirect(self,f'/post/{pid}'); return
            if path.startswith('/post/') and path.endswith('/delete'):
                pid=int(path.split('/')[2]); conn.execute('DELETE FROM posts WHERE id=? AND author_id=?',(pid,user['id'])); conn.commit(); redirect(self,'/'); return
            if path.startswith('/post/') and path.endswith('/comment'):
                pid=int(path.split('/')[2]); p=conn.execute('SELECT * FROM posts WHERE id=?',(pid,)).fetchone(); text=form.get('body','').strip()
                if p and text and can_view(conn,p,user): conn.execute('INSERT INTO comments(post_id,user_id,body,created_at) VALUES(?,?,?,?)',(pid,user['id'],text,now_iso())); conn.commit()
                redirect(self,f'/post/{pid}'); return
            if path.startswith('/post/') and path.endswith('/request'):
                pid=int(path.split('/')[2]); p=conn.execute('SELECT * FROM posts WHERE id=?',(pid,)).fetchone()
                if p and p['visibility']=='request' and p['author_id']!=user['id']:
                    conn.execute('INSERT OR IGNORE INTO access_requests(post_id,requester_id,status,created_at) VALUES(?,?,?,?)',(pid,user['id'],'pending',now_iso())); conn.commit()
                redirect(self,f'/post/{pid}'); return
            if path.startswith('/request/'):
                parts=path.strip('/').split('/'); rid=int(parts[1]); action=parts[2]
                row=conn.execute('''SELECT ar.id,p.author_id FROM access_requests ar JOIN posts p ON p.id=ar.post_id WHERE ar.id=?''',(rid,)).fetchone()
                if not row or row['author_id']!=user['id']: self.send_error(403); return
                status='approved' if action=='approve' else 'rejected'; conn.execute('UPDATE access_requests SET status=? WHERE id=?',(status,rid)); conn.commit(); redirect(self,'/requests'); return
            self.send_error(404)
        finally:
            conn.close()

    def save_tags(self,conn,pid,raw):
        names=[]
        for x in raw.split(','):
            name=x.strip().lower().lstrip('#')[:30]
            if name and name not in names: names.append(name)
        for name in names[:8]:
            conn.execute('INSERT OR IGNORE INTO tags(name) VALUES(?)',(name,)); tid=conn.execute('SELECT id FROM tags WHERE name=?',(name,)).fetchone()['id']; conn.execute('INSERT OR IGNORE INTO post_tags(post_id,tag_id) VALUES(?,?)',(pid,tid))


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--port',type=int,default=int(os.getenv('PORT','8001'))); args=parser.parse_args(); init_db(); print(f'PracticeBlog: http://127.0.0.1:{args.port}'); ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()

if __name__=='__main__': main()
