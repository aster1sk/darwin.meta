package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	rice "github.com/GeertJohan/go.rice"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/foolin/gin-template/supports/gorice"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	uuid "github.com/google/uuid"
	"github.com/gorilla/websocket"
	m "github.com/keighl/metabolize"
	irc "github.com/thoj/go-ircevent"
	xurls "mvdan.cc/xurls/v2"

	"database/sql"

	_ "github.com/mattn/go-sqlite3" // Import go-sqlite3 library
)

// App is application
type App struct {
	Mutex   sync.Mutex
	IRCOut  chan *IRCEvent           `json:"-"` // outbound IRC messages
	IRCIn   chan *IRCEvent           `json:"-"` // inbound irc messages (auth etc)
	HTTPIn  chan *IRCEvent           `json:"-"` // inbound messages from HTTP -> IRC
	WSOut   chan *DBMessage          `json:"-"` // inbound messages from HTTP -> IRC
	Users   map[string]string        `json:"-"`
	Clients map[*websocket.Conn]bool `json:"-"`
	DB      *sql.DB                  `json:"-"`
}

// DBMessage is a flattened ircevent
type DBMessage struct {
	Timestamp   time.Time `json:"timestamp"`
	User        string    `json:"user"`
	Message     string    `json:"message"`
	Channel     string    `json:"channel"`
	Title       string    `meta:"og:title,og:site_name,title" json:"title"`
	Description string    `meta:"og:description,description" json:"description"`
	Image       string    `meta:"og:image" json:"image"`
	Width       int64     `meta:"og:video:width" json:"width"`
	Height      int64     `meta:"og:video:height" json:"height"`
	ContentType string    `json:"content_type"`
	URLString   string    `json:"url_string"`
	UUID        string    `json:"uid"`
	Path        string    `json:"path"`
}

// NewApp is new application
func NewApp() *App {

	if !fileExists("data.db") {
		file, err := os.Create("data.db") // Create SQLite file
		if err != nil {
			log.Fatal(err.Error())
		}
		file.Close()
	}
	db, _ := sql.Open("sqlite3", "./data.db")

	app := &App{
		IRCOut: make(chan *IRCEvent),
		IRCIn:  make(chan *IRCEvent),
		HTTPIn: make(chan *IRCEvent),
		WSOut:  make(chan *DBMessage),
		Users:  make(map[string]string),
		DB:     db,
	}
	app.CreateTables()
	return app
}

var identityKey = "id"

func (app *App) loginSuccess(c *gin.Context, i int, token string, t time.Time) {
	c.Redirect(301, fmt.Sprintf("/app"))
}

var wsupgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// RegisterClient registers websocket client
func (app *App) RegisterClient(conn *websocket.Conn) {
	app.Mutex.Lock()
	defer app.Mutex.Unlock()
	// If the client doesn't exist in the pool already, create it
	if ok := app.Clients[conn]; !ok {
		app.Clients[conn] = true
	}
}

// HandleWS handles websocket connections
func (app *App) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsupgrader.Upgrade(w, r, nil)
	if err != nil {
		panic(err)
	}
	app.RegisterClient(conn)
}

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

// User demo
type User struct {
	UserName string `json:"username"`
	Token    string `json:"token"`
}

func main() {

	app := NewApp()
	go app.RunIRC()

	port := os.Getenv("PORT")
	r := gin.New()
	r.MaxMultipartMemory = 8 << 20 // 8 MiB
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// CORS handler
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"*"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"*"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "*"
		},
		MaxAge: 12 * time.Hour,
	}))

	app.Clients = make(map[*websocket.Conn]bool)
	r.GET("/ws", func(c *gin.Context) {
		app.HandleWS(c.Writer, c.Request)
	})

	if staticBox, err := rice.FindBox("dist"); err != nil {
		panic(err)
	} else {
		r.GET("/", func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, "/app/")
		})
		r.StaticFS("/app", staticBox.HTTPBox())
		r.HTMLRender = gorice.New(staticBox)
		r.NoRoute(func(c *gin.Context) {
			c.HTML(http.StatusOK, "index.html", gin.H{})
		})
	}

	port = "8001"

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "acablabs.com",
		Key:         []byte("xzw4RH0015cZPdHSBUXJte0M7Cy1yay43SswGdq8SlguwIpYauHoaENVQsmWwc7"),
		Timeout:     time.Hour * 3600,
		MaxRefresh:  time.Hour * 3600,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey: v.UserName,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			token := jwt.GetToken(c)
			return &User{
				Token:    token,
				UserName: claims[identityKey].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var authCreds login
			if err := c.ShouldBind(&authCreds); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			userID := authCreds.Username
			if ok := app.Users[userID]; ok != "" {
				if ok == authCreds.Password {
					// User is authenticated, do something about it
					msg := IRCEvent{
						Channel: userID,
						User:    userID,
						Message: "",
					}
					app.IRCOut <- &msg
					return &User{
						UserName: userID,
					}, nil
				}
			}
			return nil, jwt.ErrFailedAuthentication
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			return true
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
		TokenLookup:    "header: Authorization, query: token, cookie: token",
		TokenHeadName:  "Bearer",
		TimeFunc:       time.Now,
		SendCookie:     true,
		SecureCookie:   true,
		CookieHTTPOnly: false,
		CookieMaxAge:   time.Duration(time.Hour * 3600),
		CookieName:     "token",
		LoginResponse:  app.loginSuccess,
	})
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	errInit := authMiddleware.MiddlewareInit()
	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	r.GET("/auth", authMiddleware.LoginHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	r.GET("/v/:uid", func(c *gin.Context) {
		uid, _ := c.Params.Get("uid")
		evt := app.GetEvent(uid)
		path := evt.Path
		if path == "" || !fileExists(path) {
			c.Redirect(302, evt.URLString)
			return
		}
		c.File(path)
	})

	upload := r.Group("/u")
	upload.Use(authMiddleware.MiddlewareFunc())

	// File upload handler
	upload.POST("/", func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		token := jwt.GetToken(c)
		_ = token
		file, err := c.FormFile("file")
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
			return
		}
		title := c.PostForm("title")
		description := c.PostForm("description")
		if description == "" {
			description = "File upload"
		}
		if title == "" {
			title = "Upload"
		}

		uid := uuid.New().String()
		contentType := file.Header.Get("content-type")
		ext := strings.Split(contentType, "/")[1]
		savePath := fmt.Sprintf("./uploads/%s.%s", uid, ext)

		if err := c.SaveUploadedFile(file, savePath); err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
			return
		}
		ftype := contentType
		if contentType == "image/jpeg" || contentType == "image/png" || contentType == "image/gif" {
			ftype = "image"
		}
		user := claims["id"].(string)
		metadata := MetaData{
			Title:       title,
			Description: description,
			Type:        ftype,
			ContentType: contentType,
			URLString:   fmt.Sprintf("https://acablabs.com/v/%s", uid),
			Image:       fmt.Sprintf("https://acablabs.com/v/%s", uid),
			UUID:        uid,
			Path:        savePath,
		}
		msg := IRCEvent{
			Timestamp: time.Now(),
			User:      user,
			Channel:   "#darwin",
			Message:   fmt.Sprintf(`%s shared "%s" : https://acablabs.com/v/%s`, user, metadata.Title, uid),
		}
		msg.MetaData = append(msg.MetaData, &metadata)
		app.SaveEvent(&msg)
		dbMsg := DBMessage{
			Timestamp:   msg.Timestamp,
			User:        msg.User,
			Channel:     msg.Channel,
			Message:     msg.Message,
			Title:       metadata.Title,
			Description: description,
			ContentType: metadata.ContentType,
			URLString:   metadata.URLString,
			UUID:        metadata.UUID,
			Image:       metadata.URLString,
		}
		app.WSOut <- &dbMsg
		app.HTTPIn <- &msg
		c.String(http.StatusOK, fmt.Sprintf(metadata.URLString+"\n"))
	})

	api := r.Group("/api/v1")
	api.Use(authMiddleware.MiddlewareFunc())
	api.GET("me", func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		token := jwt.GetToken(c)
		c.JSON(200, gin.H{"username": claims["id"], "token": token})
	})
	api.GET("events", func(c *gin.Context) {
		// claims := jwt.ExtractClaims(c)
		// token := jwt.GetToken(c)
		events := app.GetEvents(0, 0)
		c.JSON(200, events)
	})

	defer app.DB.Close()
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}

}

// IRCEvent is an irc event type
type IRCEvent struct {
	Timestamp time.Time
	User      string      `json:"user"`
	Message   string      `json:"message"`
	Channel   string      `json:"channel"`
	MetaData  []*MetaData `json:"metadata"`
}

// MetaData html metadata
type MetaData struct {
	Title       string  `meta:"og:title" json:"title"`
	Description string  `meta:"og:description,description" json:"description"`
	Type        string  `meta:"og:type" json:"type"`
	Image       string  `meta:"og:image" json:"image"`
	Width       int64   `meta:"og:video:width" json:"width"`
	Height      int64   `meta:"og:video:height" json:"height"`
	ContentType string  `json:"content_type"`
	URL         url.URL `meta:"og:url" json:"url"`
	URLString   string  `json:"url_string"`
	UUID        string  `json:"uid"`
	Path        string  `json:"path"`
}

// RunIRC runs irc client
func (app *App) RunIRC() {

	ircnick1 := "pybot"
	irccon := irc.IRC(ircnick1, "pybot")
	// irccon.VerboseCallbackHandler = true
	// irccon.Debug = true
	irccon.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	irccon.UseTLS = true
	irccon.AddCallback("001", func(e *irc.Event) { irccon.Join("#darwin") })
	irccon.AddCallback("366", func(e *irc.Event) {})
	irccon.AddCallback("367", func(e *irc.Event) {})
	err := irccon.Connect("irc.darwin.network:6697")
	// err := irccon.Connect("localhost:6697")
	if err != nil {
		fmt.Printf("Err %s", err)
		return
	}

	irccon.AddCallback("PRIVMSG", func(event *irc.Event) {
		evt := IRCEvent{
			Timestamp: time.Now(),
			Message:   event.Message(),
			User:      event.Nick,
			Channel:   event.Arguments[0],
		}
		// Look for URL's in the privmsgs
		rxStrict := xurls.Strict()
		urls := rxStrict.FindAllString(evt.Message, -1)

		// Get metadata for URL
		go func() {
			for _, url := range urls {
				nuid := uuid.New().String()
				client := http.Client{
					Timeout: 5 * time.Second,
				}
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					log.Println(err)
					return
				}
				req.Header.Set("User-Agent", "Mozilla Firefox Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0")
				res, err := client.Do(req)
				if err != nil {
					log.Println(err)
					return
				}

				defer res.Body.Close()

				data := new(MetaData)
				err = m.Metabolize(res.Body, data)
				if err != nil {
					log.Println(err)
					return
				}
				data.URLString = url
				data.ContentType = res.Header.Get("Content-Type")
				ct := data.ContentType
				if ct == "image/png" || ct == "image/jpeg" || ct == "image/webm" || ct == "image/gif" {
					data.Title = "Image"
					data.Description = "Image"
					data.Type = ct
					data.URLString = url
					ext := strings.Split(data.ContentType, "/")[1]
					path := fmt.Sprintf("uploads/%s.%s", nuid, ext)
					data.Path = path
					data.Image = fmt.Sprintf("https://acablabs.com/v/%s", nuid)
					DownloadFile(path, url)
				}
				if data.Image == "" {
					data.Image = "https://acablabs.com/v/e3bec577-7279-46ad-8e92-68a9a5620111"
				}
				data.UUID = nuid
				// irccon.Privmsg(evt.Channel, data.Image)
				evt.MetaData = append(evt.MetaData, data)
				evt.Message = fmt.Sprintf("%s shared https://acablabs.com/v/%s", evt.User, nuid)
				evt.Channel = "vivi"
				app.IRCIn <- &evt
				// js, _ := json.MarshalIndent(data, "", "    ")
				// fmt.Println(string(js))

				app.WSOut <- &DBMessage{
					Timestamp:   evt.Timestamp,
					User:        evt.User,
					Message:     evt.Message,
					Channel:     evt.Channel,
					Title:       data.Title,
					Description: data.Description,
					Image:       data.Image,
					Width:       data.Width,
					Height:      data.Height,
					ContentType: data.ContentType,
					URLString:   data.URLString,
					UUID:        data.UUID,
					Path:        data.Path,
				}

			}
			app.SaveEvent(&evt)
		}()

		// auth
		if evt.Message == "auth" {
			uid := uuid.New().String()
			app.Users[evt.User] = uid
			irccon.Privmsg(evt.User, fmt.Sprintf("https://acablabs.com/auth?username=%s&password=%s", evt.User, uid))
		}

		if evt.Message == "latest" {
			app.GetEvents(0, 0)
		}
	})

	// What to do when we receive an HTTP event
	go func() {
		for msg := range app.HTTPIn {
			irccon.Privmsg(msg.Channel, msg.Message)
		}
	}()

	// What to do when we receive a PRIVMSG
	go func() {
		for msg := range app.IRCIn {
			irccon.Privmsg(msg.Channel, msg.Message)
		}
	}()

	// Send websocket messages
	go func() {
		for msg := range app.WSOut {
			for c := range app.Clients {
				c.WriteJSON(msg)
			}
		}
	}()

	// What to do when we receive a PRIVMSG
	go func() {
		for msg := range app.IRCOut {
			irccon.Privmsg(msg.Channel, msg.Message)
		}
	}()

	irccon.Loop()

}

// DownloadFile downloads a file
func DownloadFile(filepath string, url string) error {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// SaveEvent saves events
func (app *App) SaveEvent(event *IRCEvent) {

	user := event.User
	channel := event.Channel
	timestamp := event.Timestamp
	message := event.Message

	for _, m := range event.MetaData {
		_ = m
		query := `INSERT INTO event(
			timestamp,
			user,
			channel,
			message,
			title,
			description,
			ftype,
			image,
			contentType,
			width,
			height,
			url,
			uid,
			path
		) VALUES (
			?, 
			?, 
			?, 
			?, 
			?, 
			?, 
			?, 
			?, 
			?, 
			?, 
			?, 
			?, 
			?,
			?
			)`
		statement, err := app.DB.Prepare(query)
		if err != nil {
			log.Fatalln(err.Error())
		}
		title := m.Title
		description := m.Description
		ftype := m.Type
		image := m.Image
		width := m.Width
		height := m.Height
		url := m.URLString
		uid := m.UUID
		path := m.Path
		contentType := m.ContentType
		_, err = statement.Exec(timestamp, user, channel, message, title, description, ftype, image, contentType, width, height, url, uid, path)
		if err != nil {
			log.Fatalln(err.Error())
		}
	}
}

// CreateTables creates the database tables
func (app *App) CreateTables() {
	table := `CREATE TABLE IF NOT EXISTS event (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,		
		"user" TEXT,
		"channel" TEXT,
		"message" TEXT,
		"timestamp" DATETIME,
		"title" TEXT,
		"description" TEXT,
		"ftype" TEXT,
		"image" TEXT,
		"contentType" TEXT,
		"width" INT,
		"height" INT,
		"url" TEXT,
		"uid" TEXT,
		"path" TEXT
	  );`
	statement, err := app.DB.Prepare(table)
	if err != nil {
		log.Fatal(err.Error())
	}
	_, err = statement.Exec()
	if err != nil {
		log.Println(err)
	}
}

// GetEvents displays events
func (app *App) GetEvents(offset, limit int) (events []*DBMessage) {
	if limit == 0 {
		limit = 1000
	}
	query := fmt.Sprintf(`SELECT * FROM event ORDER BY timestamp DESC LIMIT %d`, limit)
	row, err := app.DB.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer row.Close()
	for row.Next() { // Iterate and fetch the records from result cursor
		var id int
		var user string
		var channel string
		var message string
		var timestamp time.Time
		var title string
		var description string
		var ftype string
		var image string
		var contentType string
		var width int64
		var height int64
		var url string
		var uid string
		var path string
		row.Scan(
			&id,
			&user,
			&channel,
			&message,
			&timestamp,
			&title,
			&description,
			&ftype,
			&image,
			&contentType,
			&width,
			&height,
			&url,
			&uid,
			&path,
		)
		msg := &DBMessage{
			Timestamp:   timestamp,
			User:        user,
			Message:     message,
			Channel:     channel,
			Title:       title,
			Description: description,
			Image:       image,
			Width:       width,
			Height:      height,
			ContentType: contentType,
			URLString:   url,
			UUID:        uid,
			Path:        path,
		}
		events = append(events, msg)
	}
	return events
}

// GetEvent displays events
func (app *App) GetEvent(uid string) *DBMessage {
	query := fmt.Sprintf(`SELECT * FROM event WHERE uid="%s" ORDER BY timestamp DESC`, uid)
	row, err := app.DB.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer row.Close()
	for row.Next() { // Iterate and fetch the records from result cursor
		var id int
		var user string
		var channel string
		var message string
		var timestamp time.Time
		var title string
		var description string
		var ftype string
		var image string
		var contentType string
		var width int64
		var height int64
		var url string
		var uid string
		var path string
		row.Scan(
			&id,
			&user,
			&channel,
			&message,
			&timestamp,
			&title,
			&description,
			&ftype,
			&image,
			&contentType,
			&width,
			&height,
			&url,
			&uid,
			&path,
		)
		return &DBMessage{
			Timestamp:   timestamp,
			User:        user,
			Message:     message,
			Channel:     channel,
			Title:       title,
			Description: description,
			Image:       image,
			Width:       width,
			Height:      height,
			ContentType: contentType,
			URLString:   url,
			UUID:        uid,
			Path:        path,
		}
	}
	return nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
