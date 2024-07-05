package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// r := gin.Default()
	// r.GET("/ping", func(c *gin.Context) {
	// 	c.JSON(200, gin.H{
	// 		"message": "pong",
	// 	})
	// })
	// r.Run()
	// db, err := sqlx.Open("mysql", "root:123456@tcp(127.0.0.1:3306)/login")
	// fmt.Println("connect seccest", db, err)
	// if err != nil {
	// 	panic("Failed to connect to login")
	// }
	// defer db.Close()
	// Khởi tạo dữ liệu người dùng
	// user := &Credentials{
	// 	Username: "cuong",
	// 	Password: "123456",
	// }

	// Câu lệnh SQL chèn dữ liệu với tham số được đặt tên
	// query := `INSERT INTO loginn(Username, Password) VALUES  (?, ?)`
	// db.MustExec(query, "cuong", "123456")
	// log.Println("User inserted successfully")

	// var user Credentials
	// err = db.Get(&user, "SELECT id, username, password FROM users WHERE username=?", "user1")
	// if err == nil {

	// 	fmt.Println("err !!!")

	// } else {
	// 	fmt.Println("no user fould")
	// }

	// user.Password = "newpassword"
	// _, err = db.NamedExec(`UPDATE users SET Password=:password WHERE Username=:username`, &user)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// fmt.Println("User updated successfully")
	// Thực thi câu lệnh SQL với NamedExec

	// defer db.Close()
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/welcome", welcome)
	http.HandleFunc("/refresh", Refresh)
	http.HandleFunc("/logout", Logout)
	fmt.Println("Server is running on port 8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

var jwtKey = []byte("my_secret_key")

var users = map[string]string{
	"user1": "cuong",
	"user2": "123456",
}

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func Signin(w http.ResponseWriter, r *http.Request) {
	// Khai báo một biến để giữ thông tin đăng nhập được giải mã
	var creds Credentials

	// Giải mã nội dung JSON từ request body vào biến 'creds'
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// Nếu có lỗi khi giải mã request body, trả về mã lỗi HTTP 400 Bad Request
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Lấy mật khẩu dự kiến từ map 'user' dựa trên username đã nhận
	expectedPassword, ok := users[creds.Username]

	// Nếu username không tồn tại trong map hoặc mật khẩu không khớp
	if !ok || expectedPassword != creds.Password {
		// Trả về mã lỗi HTTP 401 Unauthorized
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Thiết lập thời gian hết hạn của token là 5 phút kể từ hiện tại
	expirationTime := time.Now().Add(5 * time.Minute)

	// Tạo các yêu cầu JWT, bao gồm username và thời gian hết hạn
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			// Thiết lập thời gian hết hạn của token
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Tạo token JWT với phương thức ký hiệu và các yêu cầu
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Ký token với khóa bí mật để lấy chuỗi token hoàn chỉnh
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// Nếu có lỗi khi ký token, trả về mã lỗi HTTP 500 Internal Server Error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Thiết lập cookie HTTP chứa token JWT với thời gian hết hạn đã chỉ định
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

func welcome(w http.ResponseWriter, r *http.Request) {
	// Lấy cookie tên "token" từ yêu cầu
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// Nếu cookie không tồn tại, trả về mã trạng thái 401 (Unauthorized)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Nếu có lỗi khác khi lấy cookie, trả về mã trạng thái 400 (Bad Request)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Lấy giá trị của token từ cookie
	tknStr := c.Value
	claims := &Claims{}

	// Phân tích JWT và lưu trữ thông tin vào `claims`
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Finally, return the welcome message to the user, along with their
	// username given in the token
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}
func Refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := c.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if time.Until(claims.ExpiresAt.Time) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
func Logout(w http.ResponseWriter, r *http.Request) {
	// immediately clear the token cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
}
