package main

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "net/http/pprof"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/bytedance/sonic"
	"github.com/coocood/freecache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

var (
	db    *sqlx.DB
	store *gsm.MemcacheStore
	cache *freecache.Cache
	// getIndexTemplate   *template.Template
	getPostsIDTemplate *template.Template
	getPostsTemplate   *template.Template
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	User         User      `db:"users"`
	CommentCount int
	Comments     []Comment
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User      `db:"users"`
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient := memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	// getIndexTemplate = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	// 	getTemplPath("layout.html"),
	// 	getTemplPath("index.html"),
	// 	getTemplPath("posts.html"),
	// 	getTemplPath("post.html"),
	// ))
	getPostsIDTemplate = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	))
	getPostsTemplate = template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
		// "ALTER TABLE `users` ADD INDEX `idx_account_name_del_flg` (`account_name`, `del_flg`)",
		// "ALTER TABLE `comments` ADD INDEX `idx_post_id` (`post_id`)",
		// "ALTER TABLE `comments` ADD INDEX `idx_post_id_created_at` (`post_id`, `created_at` DESC)",
		// "ALTER TABLE `posts` ADD INDEX `idx_user_id_created_at` (`user_id`, `created_at` DESC)",
		// "ALTER TABLE `posts` ADD INDEX `idx_created_at` (`created_at` DESC)",
		// "ALTER TABLE `comments` ADD INDEX `idx_user_id` (`user_id`)",
		// "ALTER TABLE `posts` ADD INDEX `idx_created_at_desc` (`created_at` DESC)",
		// "ALTER TABLE `users` ADD INDEX `idx_authority_del_flg_created_at` (`authority`, `del_flg`, `created_at` DESC)",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

var templateLayoutByteArray = [...][]byte{
	[]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Iscogram</title><link href="/css/style.css" media="screen" rel="stylesheet" type="text/css"></head><body><div class="container"><div class="header"><div class="isu-title"><h1><a href="/">Iscogram</a></h1></div><div class="isu-header-menu">`),
	// {{ if eq .Me.ID 0}}
	[]byte(`<div><a href="/login">ログイン</a></div>`),
	// {{ else }}
	[]byte(`<div><a href="/@`),
	// {{.Me.AccountName}}
	[]byte(`"><span class="isu-account-name">`),
	// {{.Me.AccountName}}
	[]byte(`</span>さん</a></div>`),
	// {{ if eq .Me.Authority 1 }}
	[]byte(`<div><a href="/admin/banned">管理者用ページ</a></div>`),
	// {{ end }}
	[]byte(`<div><a href="/logout">ログアウト</a></div>`),
	// {{ end }}
	[]byte(`</div></div>`),
	// {{ template "content" . }}
	[]byte(`</div><script src="/js/timeago.min.js"></script><script src="/js/main.js"></script></body></html>`),
}

func templateLayout(w http.ResponseWriter, me User, content func(w http.ResponseWriter)) {
	w.Write(templateLayoutByteArray[0])
	if me.ID == 0 {
		w.Write(templateLayoutByteArray[1])
	} else {
		w.Write(templateLayoutByteArray[2])
		w.Write([]byte(me.AccountName))
		w.Write(templateLayoutByteArray[3])
		w.Write([]byte(me.AccountName))
		w.Write(templateLayoutByteArray[4])
		if me.Authority == 1 {
			w.Write(templateLayoutByteArray[5])
		}
		w.Write(templateLayoutByteArray[6])
	}
	w.Write(templateLayoutByteArray[7])
	content(w)
	w.Write(templateLayoutByteArray[8])
}

var templatePostByteArray = [...][]byte{
	[]byte(`<div class="isu-post" id="pid_`), //[0]
	// {{ .ID }}
	[]byte(`" data-created-at="`), // [1]
	// {{.CreatedAt.Format "2006-01-02T15:04:05-07:00"}}
	[]byte(`"><div class="isu-post-header"><a href="/@`), // [2]
	// {{.User.AccountName}}
	[]byte(`" class="isu-post-account-name">`), // [3]
	// {{ .User.AccountName }}
	[]byte(`</a><a href="/posts/`), // [4]
	// {{.ID}}
	[]byte(`" class="isu-post-permalink"><time class="timeago" datetime="`), // [5]
	// {{.CreatedAt.Format "2006-01-02T15:04:05-07:00"}}
	[]byte(`"></time></a></div><div class="isu-post-image"><img src="`), // [6]
	// {{imageURL .}}
	[]byte(`" class="isu-image"></div><div class="isu-post-text"><a href="/@`), // [7]
	// {{.User.AccountName}}
	[]byte(`" class="isu-post-account-name">`), // [8]
	// {{ .User.AccountName }}
	[]byte(`</a>`), // [9]
	// {{ .Body }}
	[]byte(`</div><div class="isu-post-comment"><div class="isu-post-comment-count">comments: <b>`), // [10]
	// {{ .CommentCount }}
	[]byte(`</b></div>`), // [11]
	// {{ range .Comments }}
	[]byte(`<div class="isu-comment"><a href="/@`), // [12]
	// {{.User.AccountName}}
	[]byte(`" class="isu-comment-account-name">`), // [13]
	// {{.User.AccountName}}
	[]byte(`</a><span class="isu-comment-text">`), // [14]
	// {{.Comment}}
	[]byte(`</span></div>`), // [15]
	// {{ end }}
	[]byte(`<div class="isu-comment-form"><form method="post" action="/comment"><input type="text" name="comment"><input type="hidden" name="post_id" value="`), // [16]
	// {{.ID}}
	[]byte(`"><input type="hidden" name="csrf_token" value="`), // [17]
	// {{.CSRFToken}}
	[]byte(`"><input type="submit" name="submit" value="submit"></form></div></div></div>`), // [18]
}

func templatePost(w http.ResponseWriter, p Post) {
	w.Write(templatePostByteArray[0])
	w.Write([]byte(strconv.Itoa(p.ID)))
	w.Write(templatePostByteArray[1])
	w.Write([]byte(p.CreatedAt.Format(ISO8601Format)))
	w.Write(templatePostByteArray[2])
	w.Write([]byte(p.User.AccountName))
	w.Write(templatePostByteArray[3])
	w.Write([]byte(p.User.AccountName))
	w.Write(templatePostByteArray[4])
	w.Write([]byte(strconv.Itoa(p.ID)))
	w.Write(templatePostByteArray[5])
	w.Write([]byte(p.CreatedAt.Format(ISO8601Format)))
	w.Write(templatePostByteArray[6])
	w.Write([]byte(imageURL(p)))
	w.Write(templatePostByteArray[7])
	w.Write([]byte(p.User.AccountName))
	w.Write(templatePostByteArray[8])
	w.Write([]byte(p.User.AccountName))
	w.Write(templatePostByteArray[9])
	w.Write([]byte(p.Body))
	w.Write(templatePostByteArray[10])
	w.Write([]byte(strconv.Itoa(p.CommentCount)))
	w.Write(templatePostByteArray[11])
	for _, c := range p.Comments {
		w.Write(templatePostByteArray[12])
		w.Write([]byte(c.User.AccountName))
		w.Write(templatePostByteArray[13])
		w.Write([]byte(c.User.AccountName))
		w.Write(templatePostByteArray[14])
		w.Write([]byte(c.Comment))
		w.Write(templatePostByteArray[15])
	}
	w.Write(templatePostByteArray[16])
	w.Write([]byte(strconv.Itoa(p.ID)))
	w.Write(templatePostByteArray[17])
	w.Write([]byte(p.CSRFToken))
	w.Write(templatePostByteArray[18])
}

var templatePostsByteArray = [...][]byte{
	[]byte(`<div class="isu-posts">`),
	// {{ range . }}
	// {{ template "post.html" . }}
	// {{ end }}
	[]byte(`</div>`),
}

func templatePosts(w http.ResponseWriter, posts []Post) {
	w.Write(templatePostsByteArray[0])
	for _, p := range posts {
		templatePost(w, p)
	}
	w.Write(templatePostsByteArray[1])
}

var templateIndexByteArray = [...][]byte{
	[]byte(`<div class="isu-submit"><form method="post" action="/" enctype="multipart/form-data"><div class="isu-form"><input type="file" name="file" value="file"></div><div class="isu-form"><textarea name="body"></textarea></div><div class="form-submit"><input type="hidden" name="csrf_token" value="`),
	// {{.CSRFToken}},
	[]byte(`"><input type="submit" name="submit" value="submit"></div>`),
	// {{if .Flash}},
	[]byte(`<div id="notice-message" class="alert alert-danger">`),
	// {{.Flash}},
	[]byte(`</div>`),
	// {{end}},
	[]byte(`</form></div>`),
	// {{ template "posts.html" .Posts }},
	[]byte(`<div id="isu-post-more"><button id="isu-post-more-btn">もっと見る</button><img class="isu-loading-icon" src="/img/ajax-loader.gif"></div>`),
	// {{ end }},
}

func templateIndex(w http.ResponseWriter, posts []Post, csrfToken string, flash string) {
	w.Write(templateIndexByteArray[0])
	w.Write([]byte(csrfToken))
	w.Write(templateIndexByteArray[1])
	if flash != "" {
		w.Write(templateIndexByteArray[2])
		w.Write([]byte(flash))
		w.Write(templateIndexByteArray[3])
	}
	w.Write(templateIndexByteArray[4])
	for _, p := range posts {
		templatePosts(w, []Post{p})
	}
	w.Write(templateIndexByteArray[5])
}

func tryLogin(accountName, password string) *User {
	u := User{}
	cacheUserKey := fmt.Sprintf("user_%s", accountName)
	b, err := cache.Get([]byte(cacheUserKey))
	if err == nil {
		err = sonic.Unmarshal(b, &u)
		if err != nil {
			log.Print(err)
			return nil
		}
	} else {
		err := db.Get(&u, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
		if err != nil {
			return nil
		}

		b, err = sonic.Marshal(u)
		if err != nil {
			log.Print(err)
			return nil
		}

		err = cache.Set([]byte(cacheUserKey), b, 86400)
		if err != nil {
			log.Print(err)
			return nil
		}
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

func digest(src string) string {
	hasher := sha512.New()
	_, err := hasher.Write([]byte(src))
	if err != nil {
		log.Print(err)
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	u := User{}

	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post

	for _, p := range results {
		cacheCommentCountKey := fmt.Sprintf("comment_count_%d", p.ID)
		b, err := cache.Get([]byte(cacheCommentCountKey))
		if err == nil {
			p.CommentCount, _ = strconv.Atoi(string(b))
		} else {
			err := db.Get(&p.CommentCount, "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?", p.ID)
			if err != nil {
				return nil, err
			}
			err = cache.Set([]byte(cacheCommentCountKey), []byte(strconv.Itoa(p.CommentCount)), 86400)
			if err != nil {
				return nil, err
			}
		}

		cacheCommentsKey := fmt.Sprintf("comments_%d_%t", p.ID, allComments)
		var comments []Comment
		b, err = cache.Get([]byte(cacheCommentsKey))
		if err == nil {
			err = sonic.Unmarshal(b, &comments)
			if err != nil {
				return nil, err
			}
		} else {
			query := "SELECT c.`id`, c.`post_id`, c.`user_id`, c.`comment`, c.`created_at`, u.`account_name` AS \"users.account_name\" FROM `comments` AS c STRAIGHT_JOIN `users` AS u ON c.`user_id` = u.`id` WHERE c.`post_id` = ? ORDER BY c.`created_at` DESC"
			if !allComments {
				query += " LIMIT 3"
			}
			err = db.Select(&comments, query, p.ID)
			if err != nil {
				return nil, err
			}
			b, err = sonic.Marshal(comments)
			if err != nil {
				return nil, err
			}
			err = cache.Set([]byte(cacheCommentsKey), b, 86400)
			if err != nil {
				return nil, err
			}
		}

		// reverse
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}

		p.Comments = comments

		if p.User.AccountName == "" {
			err = db.Get(&p.User, "SELECT * FROM `users` WHERE `id` = ?", p.UserID)
			if err != nil {
				return nil, err
			}
		}

		p.CSRFToken = csrfToken

		if p.User.DelFlg == 0 {
			posts = append(posts, p)
		}
		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}
	cacheUserKey := fmt.Sprintf("user_%s", accountName)
	cache.Del([]byte(cacheUserKey))

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}
	err := db.Select(&results, "SELECT p.`id`, p.`user_id`, p.`body`, p.`mime`, p.`created_at`, u.`account_name` AS \"users.account_name\" FROM `posts` AS p STRAIGHT_JOIN `users` AS u ON p.user_id = u.id WHERE u.del_flg = 0 ORDER BY p.`created_at` DESC LIMIT ?", postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	// getIndexTemplate.Execute(w, struct {
	// 	Posts     []Post
	// 	Me        User
	// 	CSRFToken string
	// 	Flash     string
	// }{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})

	templateLayout(w, me, func(w http.ResponseWriter) {
		templateIndex(w, posts, getCSRFToken(r), getFlash(w, r, "notice"))
	})
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := r.PathValue("accountName")
	user := User{}
	cacheUserKey := fmt.Sprintf("user_%s", accountName)
	b, err := cache.Get([]byte(cacheUserKey))
	if err == nil {
		err = sonic.Unmarshal(b, &user)
		if err != nil {
			log.Print(err)
			return
		}
	} else {
		err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
		if err != nil {
			log.Print(err)
			return
		}
		b, err = sonic.Marshal(user)
		if err != nil {
			log.Print(err)
			return
		}
		cache.Set([]byte(cacheUserKey), b, 86400)
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	err = db.Select(&results, "SELECT p.`id`, p.`user_id`, p.`body`, p.`mime`, p.`created_at`, u.`account_name` AS \"users.account_name\" FROM `posts` AS p STRAIGHT_JOIN `users` AS u ON p.`user_id` = u.`id` WHERE p.`user_id` = ? AND u.`del_flg` = 0 ORDER BY p.`created_at` DESC LIMIT 20", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT p.`id`, p.`user_id`, p.`body`, p.`mime`, p.`created_at`, u.`account_name` AS \"users.account_name\" FROM `posts` AS p STRAIGHT_JOIN `users` AS u ON p.`user_id` = u.`id` WHERE p.`created_at` <= ? AND u.`del_flg` = 0 ORDER BY p.`created_at` DESC LIMIT 20", t.Format(ISO8601Format))
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	getPostsTemplate.Execute(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT p.`id`, p.`user_id`, p.`body`, p.`mime`, p.`created_at`, u.`account_name` AS \"users.account_name\" FROM `posts` AS p STRAIGHT_JOIN `users` AS u ON p.`user_id` = u.`id` WHERE p.`id` = ? AND u.`del_flg` = 0 LIMIT 1", pid)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	getPostsIDTemplate.Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
			ext = "jpg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
			ext = "png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
			ext = "gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		[]byte(""),
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	filename := fmt.Sprintf("../public/image/%d.%s", pid, ext)
	os.WriteFile(filename, filedata, 0644)

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	err = db.Get(&post, "SELECT mime, imgdata FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	ext := r.PathValue("ext")

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		w.Header().Set("Content-Type", post.Mime)
		// _, err := w.Write(post.Imgdata)
		// if err != nil {
		// 	log.Print(err)
		// 	return
		// }
		// return
	}

	filename := fmt.Sprintf("../public/image/%d.%s", pid, ext)
	os.WriteFile(filename, post.Imgdata, 0644)

	w.Header().Set("X-Accel-Redirect", fmt.Sprintf("/image/%d.%s", pid, ext))

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	cacheCommentsKey := fmt.Sprintf("comments_%d_%t", postID, true)
	cache.Del([]byte(cacheCommentsKey))

	cacheCommentsKey = fmt.Sprintf("comments_%d_%t", postID, false)
	cache.Del([]byte(cacheCommentsKey))

	cacheCommentCountKey := fmt.Sprintf("comment_count_%d", postID)
	cache.Del([]byte(cacheCommentCountKey))

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	go func() {
		log.Fatal(http.ListenAndServe(":6060", nil))
	}()

	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.SetMaxOpenConns(100)
	db.SetMaxIdleConns(100)
	defer db.Close()

	cache = freecache.NewCache(10 * 1024 * 1024)

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}
