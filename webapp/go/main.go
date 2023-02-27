package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/kaz/pprotein/integration/echov4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/oklog/ulid/v2"
	"golang.org/x/sync/errgroup"
)

var jst = time.FixedZone("Asia/Tokyo", 9*60*60)

func main() {
	host := getEnvOrDefault("DB_HOST", "localhost")
	port := getEnvOrDefault("DB_PORT", "3306")
	user := getEnvOrDefault("DB_USER", "isucon")
	pass := getEnvOrDefault("DB_PASS", "isucon")
	name := getEnvOrDefault("DB_NAME", "isulibrary")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Asia%%2FTokyo", user, pass, host, port, name)

	var err error
	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	var key string
	err = db.Get(&key, "SELECT `key` FROM `key` WHERE `id` = (SELECT MAX(`id`) FROM `key`)")
	// TODO: なぜかno rowsになることがある
	if errors.Is(err, sql.ErrNoRows) {
		key = strings.Repeat("a", 16)
	} else if err != nil {
		log.Panic(err)
	}

	block, err = aes.NewCipher([]byte(key))
	if err != nil {
		log.Panic(err)
	}

	e := echo.New()
	e.Debug = true
	e.JSONSerializer = &sonicJSONSerializer{}
	e.Use(middleware.Logger())

	api := e.Group("/api")
	{
		api.POST("/initialize", initializeHandler)

		membersAPI := api.Group("/members")
		{
			membersAPI.POST("", postMemberHandler)
			membersAPI.GET("", getMembersHandler)
			membersAPI.GET("/:id", getMemberHandler)
			membersAPI.PATCH("/:id", patchMemberHandler)
			membersAPI.DELETE("/:id", banMemberHandler)
			membersAPI.GET("/:id/qrcode", getMemberQRCodeHandler)
		}

		booksAPI := api.Group("/books")
		{
			booksAPI.POST("", postBooksHandler)
			booksAPI.GET("", getBooksHandler)
			booksAPI.GET("/:id", getBookHandler)
			booksAPI.GET("/:id/qrcode", getBookQRCodeHandler)
		}

		lendingsAPI := api.Group("/lendings")
		{
			lendingsAPI.POST("", postLendingsHandler)
			lendingsAPI.GET("", getLendingsHandler)
			lendingsAPI.POST("/return", returnLendingsHandler)
		}
	}

	// pprotein
	// TODO: 後で消す
	echov4.Integrate(e)

	e.Logger.Fatal(e.Start(":8080"))
}

var (
	bookCache    sync.Map
	memberCache  sync.Map
	memberCount  atomic.Int64
	lendingCache sync.Map
)

func initCache() {
	books := []Book{}
	if err := db.SelectContext(context.Background(), &books, "SELECT * FROM `book`"); err != nil {
		log.Panic(err)
	}

	for _, book := range books {
		bookCache.Store(book.ID, book)
	}

	members := []Member{}
	if err := db.SelectContext(context.Background(), &members, "SELECT * FROM `member`"); err != nil {
		log.Panic(err)
	}

	memberCount.Store(int64(len(members)))

	for _, member := range members {
		memberCache.Store(member.ID, member)
	}
	updateMemberCacheIndex()

	lendings := []Lending{}
	if err := db.SelectContext(context.Background(), &lendings, "SELECT * FROM `lending`"); err != nil {
		log.Panic(err)
	}

	for _, lending := range lendings {
		lendingCache.Store(lending.BookID, lending)
	}
}

func getMember(id string, allowBanned bool) (Member, bool) {
	member, ok := memberCache.Load(id)
	if !ok || (!allowBanned && member.(Member).Banned) {
		return Member{}, false
	}

	return member.(Member), true
}

func updateMemberCacheIndex() {
	members := make([]Member, 0, memberCount.Load())
	memberCache.Range(func(_, v interface{}) bool {
		members = append(members, v.(Member))
		return true
	})

	needUpdates := make(map[string]struct{}, len(members))

	sort.Slice(members, func(i, j int) bool {
		return members[i].ID < members[j].ID
	})

	for i, m := range members {
		if m.IDIndex != i {
			needUpdates[m.ID] = struct{}{}
			m.IDIndex = i
		}
	}

	sort.Slice(members, func(i, j int) bool {
		return members[i].Name < members[j].Name
	})

	for i, m := range members {
		if m.NameIndex != i {
			needUpdates[m.ID] = struct{}{}
			m.NameIndex = i
		}
	}

	for _, member := range members {
		if _, ok := needUpdates[member.ID]; ok {
			memberCache.Store(member.ID, member)
		}
	}
}

/*
---------------------------------------------------------------
Domain Models
---------------------------------------------------------------
*/

// 会員
type Member struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Address     string    `json:"address" db:"address"`
	PhoneNumber string    `json:"phone_number" db:"phone_number"`
	Banned      bool      `json:"banned" db:"banned"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`

	IDIndex   int `json:"-" db:"-"`
	NameIndex int `json:"-" db:"-"`
}

// 図書分類
type Genre int

// 国際十進分類法に従った図書分類
const (
	General         Genre = iota // 総記
	Philosophy                   // 哲学・心理学
	Religion                     // 宗教・神学
	SocialScience                // 社会科学
	Vacant                       // 未定義
	Mathematics                  // 数学・自然科学
	AppliedSciences              // 応用科学・医学・工学
	Arts                         // 芸術
	Literature                   // 言語・文学
	Geography                    // 地理・歴史
)

// 蔵書
type Book struct {
	ID        string    `json:"id" db:"id"`
	Title     string    `json:"title" db:"title"`
	Author    string    `json:"author" db:"author"`
	Genre     Genre     `json:"genre" db:"genre"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// 貸出記録
type Lending struct {
	ID        string    `json:"id" db:"id"`
	MemberID  string    `json:"member_id" db:"member_id"`
	BookID    string    `json:"book_id" db:"book_id"`
	Due       time.Time `json:"due" db:"due"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

/*
---------------------------------------------------------------
Utilities
---------------------------------------------------------------
*/

// ULIDを生成
func generateID() string {
	return ulid.Make().String()
}

var db *sqlx.DB

func getEnvOrDefault(key string, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}

	return defaultValue
}

var (
	block cipher.Block
)

// AES + CTRモード + base64エンコードでテキストを暗号化
func encrypt(plainText string) (string, error) {
	cipherText := make([]byte, aes.BlockSize+len([]byte(plainText)))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

// AES + CTRモード + base64エンコードで暗号化されたテキストを複合
func decrypt(cipherText string) (string, error) {
	cipherByte, err := base64.URLEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	decryptedText := make([]byte, len([]byte(cipherByte[aes.BlockSize:])))
	decryptStream := cipher.NewCTR(block, []byte(cipherByte[:aes.BlockSize]))
	decryptStream.XORKeyStream(decryptedText, []byte(cipherByte[aes.BlockSize:]))
	return string(decryptedText), nil
}

var mux = sync.Mutex{}

// QRコードを生成
func generateQRCode(id string) ([]byte, error) {
	mux.Lock()
	defer mux.Unlock()

	encryptedID, err := encrypt(id)
	if err != nil {
		return nil, err
	}

	qrCodeFileName := "../images/qr.png"

	/*
		生成するQRコードの仕様
		 - PNGフォーマット
		 - QRコードの1モジュールは1ピクセルで表現
		 - バージョン6 (41x41ピクセル、マージン含め49x49ピクセル)
		 - エラー訂正レベルM (15%)
	*/
	err = exec.
		Command("sh", "-c", fmt.Sprintf("echo \"%s\" | qrencode -o %s -t PNG -s 1 -v 6 --strict-version -l M", encryptedID, qrCodeFileName)).
		Run()
	if err != nil {
		return nil, err
	}

	file, err := os.Open(qrCodeFileName)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	return io.ReadAll(file)
}

/*
---------------------------------------------------------------
Initialization API
---------------------------------------------------------------
*/

type InitializeHandlerRequest struct {
	Key string `json:"key"`
}

type InitializeHandlerResponse struct {
	Language string `json:"language"`
}

// 初期化用ハンドラ
func initializeHandler(c echo.Context) error {
	// pprotein
	// TODO: 後で消す
	go func() {
		if _, err := http.Get("http://pprotein.ras.trap.show/api/group/collect"); err != nil {
			log.Printf("failed to communicate with pprotein: %v", err)
		}
	}()

	var req InitializeHandlerRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if len(req.Key) != 16 {
		return echo.NewHTTPError(http.StatusBadRequest, "key must be 16 characters")
	}

	cmd := exec.Command("sh", "../sql/init_db.sh")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_, err = db.ExecContext(c.Request().Context(), "INSERT INTO `key` (`key`) VALUES (?)", req.Key)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	block, err = aes.NewCipher([]byte(req.Key))
	if err != nil {
		log.Panic(err.Error())
	}

	// sc
	initCache()

	return c.JSON(http.StatusOK, InitializeHandlerResponse{
		Language: "Go",
	})
}

/*
---------------------------------------------------------------
Members API
---------------------------------------------------------------
*/

type PostMemberRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	PhoneNumber string `json:"phone_number"`
}

// 会員登録
func postMemberHandler(c echo.Context) error {
	var req PostMemberRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" || req.Address == "" || req.PhoneNumber == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, address, phoneNumber are required")
	}

	id := generateID()
	res := Member{
		ID:          id,
		Name:        req.Name,
		Address:     req.Address,
		PhoneNumber: req.PhoneNumber,
		Banned:      false,
		CreatedAt:   time.Now().In(jst),
	}

	memberCache.Store(id, res)
	updateMemberCacheIndex()
	memberCount.Add(1)

	return c.JSON(http.StatusCreated, res)
}

const memberPageLimit = 100

type GetMembersResponse struct {
	Members []Member `json:"members"`
	Total   int      `json:"total"`
}

// 会員一覧を取得 (ページネーションあり)
func getMembersHandler(c echo.Context) error {
	pageStr := c.QueryParam("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// 前ページの最後の会員ID
	// シーク法をフロントエンドでは実装したが、バックエンドは力尽きた
	_ = c.QueryParam("last_member_id")

	order := c.QueryParam("order")
	if order != "" && order != "name_asc" && order != "name_desc" {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid order")
	}

	_members := make([]Member, memberCount.Load())
	memberCache.Range(func(_, value interface{}) bool {
		m := value.(Member)
		switch order {
		case "name_asc":
			_members[m.NameIndex] = m
		case "name_desc":
			_members[len(_members)-m.NameIndex-1] = m
		// default is id asc
		default:
			_members[m.IDIndex] = m
		}

		return true
	})

	members := make([]Member, 0, len(_members))
	for _, m := range _members {
		if !m.Banned {
			members = append(members, m)
		}
	}

	if s := (page - 1) * memberPageLimit; s < 0 || s >= len(members) {
		return echo.NewHTTPError(http.StatusNotFound, "no members to show in this page (invalid index)", s)
	}
	end := len(members)
	if page*memberPageLimit < end {
		end = page * memberPageLimit
	}
	members = members[(page-1)*memberPageLimit : end]
	if len(members) == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "no members to show in this page")
	}

	return c.JSON(http.StatusOK, GetMembersResponse{
		Members: members,
		Total:   int(memberCount.Load()),
	})
}

// 会員を取得
func getMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	encrypted := c.QueryParam("encrypted")
	if encrypted == "true" {
		var err error
		id, err = decrypt(id)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	} else if encrypted != "" && encrypted != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "encrypted must be boolean value")
	}

	member, ok := getMember(id, false)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	return c.JSON(http.StatusOK, member)
}

type PatchMemberRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	PhoneNumber string `json:"phone_number"`
}

// 会員情報編集
func patchMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	var req PatchMemberRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" && req.Address == "" && req.PhoneNumber == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, address or phoneNumber is required")
	}

	// 会員の存在を確認
	member, ok := getMember(id, false)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	if req.Name != "" {
		member.Name = req.Name
	}
	if req.Address != "" {
		member.Address = req.Address
	}
	if req.PhoneNumber != "" {
		member.PhoneNumber = req.PhoneNumber
	}
	memberCache.Store(id, member)
	updateMemberCacheIndex()

	return c.NoContent(http.StatusNoContent)
}

// 会員をBAN
func banMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	// 会員の存在を確認
	member, ok := getMember(id, false)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	member.Banned = true
	memberCache.Store(id, member)
	updateMemberCacheIndex()

	lendingCache.Range(func(k, v interface{}) bool {
		if v.(Lending).MemberID == id {
			lendingCache.Delete(k)
		}
		return true
	})

	return c.NoContent(http.StatusNoContent)
}

// 会員証用のQRコードを取得
func getMemberQRCodeHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	eg := errgroup.Group{}

	eg.Go(func() error {
		// 会員の存在確認
		if _, ok := getMember(id, false); !ok {
			return echo.NewHTTPError(http.StatusNotFound, "member not found")
		}
		return nil
	})

	var qrCode []byte
	eg.Go(func() error {
		_qrCode, err := generateQRCode(id)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		qrCode = _qrCode
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return c.Blob(http.StatusOK, "image/png", qrCode)
}

/*
---------------------------------------------------------------
Books API
---------------------------------------------------------------
*/

type PostBooksRequest struct {
	Title  string `json:"title"`
	Author string `json:"author"`
	Genre  Genre  `json:"genre"`
}

// 蔵書を登録 (複数札を一気に登録)
func postBooksHandler(c echo.Context) error {
	var reqSlice []PostBooksRequest
	if err := c.Bind(&reqSlice); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	res := make([]Book, 0, len(reqSlice))
	createdAt := time.Now().In(jst)

	for _, req := range reqSlice {
		if req.Title == "" || req.Author == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "title, author is required")
		}
		if req.Genre < 0 || req.Genre > 9 {
			return echo.NewHTTPError(http.StatusBadRequest, "genre is invalid")
		}

		id := generateID()
		record := Book{
			ID:        id,
			Title:     req.Title,
			Author:    req.Author,
			Genre:     req.Genre,
			CreatedAt: createdAt,
		}
		bookCache.Store(id, record)
		res = append(res, record)
	}

	return c.JSON(http.StatusCreated, res)
}

const bookPageLimit = 50

type GetBooksResponse struct {
	Books []GetBookResponse `json:"books"`
	Total int               `json:"total"`
}

// 蔵書を検索
func getBooksHandler(c echo.Context) error {
	title := c.QueryParam("title")
	author := c.QueryParam("author")
	genre := c.QueryParam("genre")
	var genreInt int
	if genre != "" {
		_genreInt, err := strconv.Atoi(genre)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		genreInt = _genreInt

		if genreInt < 0 || genreInt > 9 {
			return echo.NewHTTPError(http.StatusBadRequest, "genre is invalid")
		}
	}
	if genre == "" && title == "" && author == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "title, author or genre is required")
	}

	pageStr := c.QueryParam("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// 前ページの最後の蔵書ID
	// シーク法をフロントエンドでは実装したが、バックエンドは力尽きた
	_ = c.QueryParam("last_book_id")

	var total int
	var berr error
	books := make([]Book, 0, 10000)
	bookCache.Range(func(_, value interface{}) bool {
		book := value.(Book)
		if genre != "" && book.Genre != Genre(genreInt) {
			return true
		}
		if title != "" && !strings.Contains(book.Title, title) {
			return true
		}
		if author != "" && !strings.Contains(book.Author, author) {
			return true
		}
		total++
		books = append(books, book)
		return true
	})
	if berr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, berr.Error())
	}
	if total == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "no books found")
	}

	sort.Slice(books, func(i, j int) bool {
		return books[i].ID < books[j].ID
	})

	if s := (page - 1) * bookPageLimit; s < 0 || s >= len(books) {
		return echo.NewHTTPError(http.StatusBadRequest, "page is invalid")
	}
	end := len(books)
	if page*bookPageLimit < end {
		end = page * bookPageLimit
	}
	books = books[(page-1)*bookPageLimit : end]
	if len(books) == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "no books to show in this page")
	}

	res := GetBooksResponse{
		Books: make([]GetBookResponse, len(books)),
		Total: total,
	}

	lengingsMapByGroupID := make(map[string]struct{})
	lendingCache.Range(func(_, v interface{}) bool {
		b := v.(Lending)
		lengingsMapByGroupID[b.BookID] = struct{}{}
		return true
	})

	for i, book := range books {
		res.Books[i].Book = book
		_, ok := lengingsMapByGroupID[book.ID]
		res.Books[i].Lending = ok
	}

	return c.JSON(http.StatusOK, res)
}

type GetBookResponse struct {
	Book
	Lending bool `json:"lending"`
}

// 蔵書を取得
func getBookHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	encrypted := c.QueryParam("encrypted")
	if encrypted == "true" {
		var err error
		id, err = decrypt(id)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	} else if encrypted != "" && encrypted != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "encrypted must be boolean value")
	}

	book, ok := bookCache.Load(id)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "book not found")
	}

	res := GetBookResponse{
		Book: book.(Book),
	}

	res.Lending = false
	lendingCache.Range(func(_, v interface{}) bool {
		b := v.(Lending)
		if b.BookID == id {
			res.Lending = true
			return false
		}
		return true
	})

	return c.JSON(http.StatusOK, res)
}

// 蔵書のQRコードを取得
func getBookQRCodeHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	eg := errgroup.Group{}
	var qrCode []byte
	eg.Go(func() error {
		_qrCode, err := generateQRCode(id)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		qrCode = _qrCode
		return nil
	})

	// 蔵書の存在確認
	if _, ok := bookCache.Load(id); !ok {
		return echo.NewHTTPError(http.StatusNotFound, "book not found")
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	return c.Blob(http.StatusOK, "image/png", qrCode)
}

/*
---------------------------------------------------------------
Lending API
---------------------------------------------------------------
*/

// 貸出期間(ミリ秒)
const LendingPeriod = 3000

type PostLendingsRequest struct {
	BookIDs  []string `json:"book_ids"`
	MemberID string   `json:"member_id"`
}

type PostLendingsResponse struct {
	Lending
	MemberName string `json:"member_name"`
	BookTitle  string `json:"book_title"`
}

// 本を貸し出し
func postLendingsHandler(c echo.Context) error {
	var req PostLendingsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.MemberID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "member_id is required")
	}
	if len(req.BookIDs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "at least one book_ids is required")
	}

	// 会員の存在確認
	member, ok := getMember(req.MemberID, true)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	lendingTime := time.Now()
	due := lendingTime.Add(LendingPeriod * time.Millisecond)
	res := make([]PostLendingsResponse, len(req.BookIDs))

	bookTitleMap := make(map[string]string)
	bookCache.Range(func(_, v interface{}) bool {
		book := v.(Book)
		for _, id := range req.BookIDs {
			if book.ID == id {
				bookTitleMap[book.ID] = book.Title
				return true
			}
		}
		return true
	})
	if len(bookTitleMap) == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "book not found")
	}

	// 貸し出し中かどうか確認
	lendingMap := make(map[string]struct{})
	lendingCache.Range(func(_, v interface{}) bool {
		lending := v.(Lending)
		for _, bookID := range req.BookIDs {
			if lending.BookID == bookID {
				lendingMap[lending.BookID] = struct{}{}
				return true
			}
		}
		return true
	})

	lendings := make([]Lending, len(req.BookIDs))
	newLendingIDs := make([]string, len(req.BookIDs))
	for i, bookID := range req.BookIDs {
		bookTitle, ok := bookTitleMap[bookID]
		if !ok {
			return echo.NewHTTPError(http.StatusNotFound, "book not found")
		}

		if _, ok := lendingMap[bookID]; ok {
			return echo.NewHTTPError(http.StatusConflict, "this book is already lent")
		}

		id := generateID()
		newLendingIDs[i] = id
		lendings[i] = Lending{
			ID:        id,
			BookID:    bookID,
			MemberID:  req.MemberID,
			Due:       due,
			CreatedAt: lendingTime,
		}
		lendingCache.Store(id, lendings[i])

		res[i].MemberName = member.Name
		res[i].BookTitle = bookTitle
	}

	lendingCache.Range(func(_, v interface{}) bool {
		lending := v.(Lending)
		for i, id := range newLendingIDs {
			if lending.ID == id {
				res[i].Lending = lending
				return true
			}
		}
		return true
	})

	return c.JSON(http.StatusCreated, res)
}

type GetLendingsResponse struct {
	Lending
	MemberName string `json:"member_name" db:"member_name"`
	BookTitle  string `json:"book_title" db:"book_title"`
}

func getLendingsHandler(c echo.Context) error {
	overDue := c.QueryParam("over_due")
	if overDue != "" && overDue != "true" && overDue != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "over_due must be boolean value")
	}

	now := time.Now()
	var res []GetLendingsResponse
	lendingCache.Range(func(_, v interface{}) bool {
		lending := v.(Lending)

		if overDue == "true" && lending.Due.Before(now) {
			return true
		}

		r := GetLendingsResponse{Lending: lending}

		b, ok := bookCache.Load(r.BookID)
		if ok {
			r.BookTitle = b.(Book).Title
		}

		m, ok := memberCache.Load(r.MemberID)
		if ok {
			r.MemberName = m.(Member).Name
		}

		res = append(res, r)
		return true
	})

	sort.Slice(res, func(i, j int) bool {
		return res[i].ID < res[j].ID
	})

	return c.JSON(http.StatusOK, res)
}

type ReturnLendingsRequest struct {
	BookIDs  []string `json:"book_ids"`
	MemberID string   `json:"member_id"`
}

// 蔵書を返却
func returnLendingsHandler(c echo.Context) error {
	var req ReturnLendingsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.MemberID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "member_id is required")
	}
	if len(req.BookIDs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "at least one book_ids is required")
	}

	// 会員の存在確認
	if _, ok := getMember(req.MemberID, true); !ok {
		return echo.NewHTTPError(http.StatusNotFound, "member not found")
	}

	lendingCache.Range(func(k, v interface{}) bool {
		lending := v.(Lending)
		for _, bookID := range req.BookIDs {
			if lending.BookID == bookID && lending.MemberID == req.MemberID {
				lendingCache.Delete(k)
			}
		}
		return true
	})

	return c.NoContent(http.StatusNoContent)
}
