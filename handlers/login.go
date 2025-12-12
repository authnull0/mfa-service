package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	db "github.com/authnull0/mfa-service/db"
	"github.com/authnull0/mfa-service/models"
	"github.com/authnull0/mfa-service/models/dto"
	services "github.com/authnull0/mfa-service/service"
	util "github.com/authnull0/mfa-service/utils"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
	"github.com/okta/okta-sdk-golang/okta"
)

// Jwk and Jwks structs remain the same as defined previously
type Jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type Jwks struct {
	Keys []Jwk `json:"keys"`
}

// Define global variable to hold the generated JWK struct
var publicJWK *Jwk
var signingKid string

type LoginHandler struct {
	Service *services.LoginService
}

func NewLoginHandler() *LoginHandler {
	return &LoginHandler{
		Service: services.NewLoginService(),
	}
}

type RootElement struct {
	XMLName xml.Name
}

type User struct {
	Name              string   `json:"name"`
	PlaintextPassword *string  `json:"password,omitempty"` // not stored
	HashedPassword    []byte   `json:"hashed_password,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Email             string   `json:"email,omitempty"`
	CommonName        string   `json:"common_name,omitempty"`
	Surname           string   `json:"surname,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	ScopedAffiliation string   `json:"scoped_affiliation,omitempty"`
}

var (
	key = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuDCN6W7icOrNo
RJISmtDv89DJUZcyX1keurrdauOreKhxnpOP56N7EUSnzxKHEqdJ/ZKXAWiFIHlL
7CGgpRP7Xi1CFRim7KJbLUW2+g02DBV6b46dereWYAyYU4HmEMfagm9wAyamOLtM
d4WuHBfZQYTwLom/pQC+rmQFtnncTPIyytTsoGA6hViNwjuWOT27NJueJ7fdMBGR
aey8FnRfB06sChqJFhFi0Zhns/Kes6FuWy43fiy018SWqCX2hRWIVwWrC/aytT0c
dIW1jmBs2F9jF2o9T5SWgEpI41FHkwSCCewjnvYrzQiGZemHvRSUiW3eDQsXlDTd
bR0RpJNdAgMBAAECggEADpXN008kZVM1/aLhatW2dKVF9dj0hrAe08hqKGvwsEno
M71KOGD8/i8wRa/AqbkSc8zgH+9qRt21zHr5RnEO/52gxUznR/XElUdx9Cd4O/M/
SYdXuDK0d9GMvKci15jIZrNPi194Oa2/ZGUPust35CjtbwM3X+v/5/rNPv1PsPpN
9dVyeWSYetoVSzPkR9396xKHWJK19ZZXpItDFy8ySZ3aYOhD0fgjMurwt012OUHl
BSnEJ6DNaexxsElnzaXjBUligDKkuAgImE43PyWpFLzHietcNuAKI17d61K/MK15
fTYbhmV61LZ1rwLds7T4+r5VS7bCfQNmRZbFyujbgQKBgQD2HeaLrBzT5+6xmlfG
LdC54QDarQiCN72o1dbZqh2ZcOQ7fRJuDzd05Y5QzJRYnhz3p3uayde3W7vAK3LJ
qX8UxPRQ9y24g3WZqyl1jEbLOYKjxL5jfUbcvMyqh98JCTl7WVTKub/EJnZ+TYYh
hh8xxgxrZwC8SzYWVLFt/CKlWQKBgQC1CVv5gRHpM7RKmL6SsTSZDvKRn+tB8DNU
pc+Aly3s+m+1FR0d6/sVipZ0b8PLqJPCnng4MBN8Hqm9WJr5JuiDIeX6jHkkhAy1
I8jA2u1UM/51wmJvnnXusfC4czwZ1/TACZa0UKdjg+EmNvvnBidFFKBvElxhRIq3
AbFFeSLppQKBgHYAdA83oELBiyJAPCFayh61ELHIELJOg3K1xGNsOvDcvbEAEJwQ
U6iKf6ehzuaGOKFM/eiDKhhRtT04F7s0tyeAHxvKx3MWJIZfGGuxrCe4FTjsFdSh
th4Tr5V7u6YbdCH9/LeOQ7GKN3nrNYpRQhedO0srgaDF9tLSHJf9MadRAoGAYNCo
hz4nPfeQq3QUNo7d+hysTIShY5n5WYNy/OncfadQph6se5v/ov2CiLJcm0WD/8iP
sjzDrtUXIVOJTUUpgzdVrjABeS3FPfntGnX6BdXod0GFMvwjRYuTmJDHy2paUXjP
R476dZXJio5NGLeJuL/XLI89KCdnp4cYLnch3KECgYEAqf2VoAVaKDhf3569wJ7w
P0fHJKAAclvrF7kCSscXO95Reec4GuEXsL3IxcTMYycqV0AF66KiD/F219L31avx
pO5gA7PPOL2kC95WOWBUHYi8/tZypFzHBtHOx6fAH5x0Qchb/mBfhpzZdKxslcOt
1QlZQ+zHxfc8fyq6sOHBeiE=
-----END PRIVATE KEY-----
`)
	cert = []byte(`-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIUYIKfjoEFNr6XPHHQh+WaFnJzvNAwDQYJKoZIhvcNAQEL
BQAwRDEVMBMGA1UEAwwMYXV0aG51bGwuY29tMREwDwYDVQQKDAhBdXRobnVsbDEL
MAkGA1UECwwCSVQxCzAJBgNVBAYTAlVTMB4XDTI1MDUwNjExMDQyOFoXDTM1MDUw
NDExMDQyOFowRDEVMBMGA1UEAwwMYXV0aG51bGwuY29tMREwDwYDVQQKDAhBdXRo
bnVsbDELMAkGA1UECwwCSVQxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEArgwjelu4nDqzaESSEprQ7/PQyVGXMl9ZHrq63Wrjq3io
cZ6Tj+ejexFEp88ShxKnSf2SlwFohSB5S+whoKUT+14tQhUYpuyiWy1FtvoNNgwV
em+OnXq3lmAMmFOB5hDH2oJvcAMmpji7THeFrhwX2UGE8C6Jv6UAvq5kBbZ53Ezy
MsrU7KBgOoVYjcI7ljk9uzSbnie33TARkWnsvBZ0XwdOrAoaiRYRYtGYZ7PynrOh
blsuN34stNfElqgl9oUViFcFqwv2srU9HHSFtY5gbNhfYxdqPU+UloBKSONRR5ME
ggnsI572K80IhmXph70UlIlt3g0LF5Q03W0dEaSTXQIDAQABo1MwUTAdBgNVHQ4E
FgQUB7Fj2XzcsEvNPGFYC8a1Uro8A5wwHwYDVR0jBBgwFoAUB7Fj2XzcsEvNPGFY
C8a1Uro8A5wwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEALHVq
Y3boPb9pugmQ5ajQLltuEt8XdSUX4jHWWpqdj3zLEz+nGeZOVAOimYpNCOzk0TEQ
L2tL8BXUZT8oI9mPAeN5o3aykZC0aweT7OqFRn/kAkd9c5KA7LF1WLlBHzWACxYB
PmC2ZmH4kU6JNTYwSOTPrAPgTqvF/4136JJ/U9nI0yrgifuTBrYKoq4A/NOfAdJc
q8h60rZroG7jYUig/TMUDDcrdvmUVGY0q9AS6hTvYPmFxqm58ycTbgdLPPTkiKhi
t63L1HxML32gC7Jpzj7zTVZril+QR87jZL/McRBXfhQNUEFTHXnmNAgwGVkGD8Ih
+wQvGk8jR9ybv5HgCQ==
-----END CERTIFICATE-----
`)
)

var sessionMaxAge = time.Minute * 20

var rootURLstr string

var idpMetadataURLstr string

var samlSP *samlsp.Middleware

var Server samlidp.Server

var storage samlidp.MemoryStore

var keyPair tls.Certificate

func Init() {

	//rootURLstr = os.Getenv("ROOT_URL")
	rootURLstr = "https://www.okta.com/exkd34w6nxTiIRwaW5d7"

	//idpMetadataURLstr = os.Getenv("IDP_METADATA_URL")
	idpMetadataURLstr = "https://dev-10065336.okta.com/app/exkd34w6nxTiIRwaW5d7/sso/saml/metadata"

	keyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse(idpMetadataURLstr)
	if err != nil {
		panic(err) // TODO handle error
	}

	// --- NEW: Extract Public Key Components for OIDC/JWKS ---
	pubKey, ok := keyPair.Leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		panic("Certificate public key is not an RSA key")
	}

	// 1. Generate a Key ID (KID) - Using a hash of the public key's DER encoding is common practice
	hasher := sha256.New()
	hasher.Write(keyPair.Leaf.RawSubjectPublicKeyInfo)
	signingKid = base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)[:10])

	// 2. Extract Modulus (N) and Exponent (E)
	n := base64UrlEncode(pubKey.N)
	// E = Public Exponent (Base64 URL-safe encoded)
	e := base64UrlEncode(big.NewInt(int64(pubKey.E)))

	// 3. Populate the global publicJWK struct
	publicJWK = &Jwk{
		Kty: "RSA",
		Kid: signingKid,
		Use: "sig",
		N:   n,
		E:   e,
	}

	rootURL, err := url.Parse(rootURLstr)
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	Server = samlidp.Server{
		IDP: saml.IdentityProvider{
			Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate: keyPair.Leaf,
			MetadataURL: *idpMetadataURL,
			SSOURL:      *rootURL,
			LogoutURL:   *rootURL,
		},
		Store: &storage,
	}

	samlSP, err = samlsp.New(samlsp.Options{
		URL: *rootURL,
		//EntityID:          "samltest.emapta.prod.authnull.com",
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		AllowIDPInitiated: true,
		IDPMetadata:       idpMetadata,
		//SignRequest:       true,
	})
	if err != nil {
		panic(err) // TODO handle error
	}
	log.Println("Loaded IdP EntityID:", samlSP.ServiceProvider.IDPMetadata.EntityID)
	log.Println("OIDC Signing KID:", signingKid) // Log the KID for debugging and JWT header use!

}
func (h *LoginHandler) FaviconHandler(c *gin.Context) {
	c.Header("Content-Type", "image/x-icon")
	c.Status(http.StatusOK)
}

func (h *LoginHandler) HandleNormalLogin(c *gin.Context) {
	var normalLoginResponse dto.NormalLoginResponse
	var normalLoginRequest dto.NormalLoginRequest

	if err := c.ShouldBindJSON(&normalLoginRequest); err != nil {
		log.Default().Println("Error:", err)
		normalLoginResponse.Code = 500
		normalLoginResponse.Message = "Error"
		normalLoginResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, normalLoginResponse)
		return
	}
	RequestID := normalLoginRequest.RequestID
	normalLoginRequest.Username = strings.ToLower(normalLoginRequest.Username)
	log.Default().Println("normalLoginRequest:", normalLoginRequest)

	var user models.User

	//drim the url

	orgname := strings.Split(normalLoginRequest.Url, ".")[1]

	db1 := db.GetConnectiontoDatabaseDynamically(orgname)

	if err := db1.Where("email_address = ?", normalLoginRequest.Username).First(&user).Error; err != nil {
		log.Default().Println("Error:", err)
		normalLoginResponse.Code = 500
		normalLoginResponse.Message = "Invalid Username"
		normalLoginResponse.Status = "error"
		normalLoginResponse.FirstLogin = user.FirstLogin
		c.JSON(http.StatusInternalServerError, normalLoginResponse)
		return
	}

	log.Default().Println("user:", user)

	// val, err := util.ComparePasswordAndHash(normalLoginRequest.Password, user.Password)
	// if err != nil {
	// 	log.Default().Println("Error:", err)
	// 	normalLoginResponse.Code = 500
	// 	normalLoginResponse.Message = "Error"
	// 	normalLoginResponse.Status = "error"
	// 	normalLoginResponse.FirstLogin = user.FirstLogin
	// 	c.JSON(http.StatusInternalServerError, normalLoginResponse)
	// 	return
	// }

	// if val == false {
	// 	log.Default().Println("Error:", err)
	// 	normalLoginResponse.Code = 401
	// 	normalLoginResponse.Message = "Invalid Password"
	// 	normalLoginResponse.Status = "Invalid Password"
	// 	normalLoginResponse.FirstLogin = user.FirstLogin
	// 	c.JSON(http.StatusInternalServerError, normalLoginResponse)
	// 	return
	// }

	//create session

	session := &saml.Session{}

	var role string

	if user.UserRoleID == 1 {
		role = "ADMIN"
	} else if user.UserRoleID == 3 {
		role = "ENDUSER"
	}

	session = &saml.Session{
		ID:         base64.StdEncoding.EncodeToString(util.RandomBytes(32)),
		NameID:     user.EmailAddress,
		CreateTime: saml.TimeNow(),
		ExpireTime: saml.TimeNow().Add(sessionMaxAge),
		Index:      hex.EncodeToString(util.RandomBytes(32)),
		UserName:   user.EmailAddress,
		// nolint:gocritic // Groups should be a slice here.
		Groups:         []string{role},
		UserEmail:      user.EmailAddress,
		UserCommonName: user.EmailAddress,
		UserSurname:    user.EmailAddress,
		UserGivenName:  user.EmailAddress,
		// CustomAttributes: response.Assertion.AttributeStatements[0].Attributes,

	}

	err := Server.Store.Put(fmt.Sprintf("/sessions/%s", session.ID), session)

	if err != nil {
		log.Default().Println("Error:", err)
		normalLoginResponse.Code = 500
		normalLoginResponse.Message = "Error"
		normalLoginResponse.Status = "error"
		normalLoginResponse.FirstLogin = user.FirstLogin
		c.JSON(http.StatusInternalServerError, normalLoginResponse)
		return
	}

	log.Default().Println("Session:", session.ID)

	normalLoginResponse.AccessToken = session.ID
	normalLoginResponse.Code = 200
	normalLoginResponse.Message = "Success"
	normalLoginResponse.FirstLogin = user.FirstLogin
	normalLoginResponse.Status = "ok"
	normalLoginResponse.Url = normalLoginRequest.Url
	if RequestID != "" {
		redis := db.GetRedisInstance()
		_, err := redis.Exists(RequestID).Result()
		if err != nil {
			log.Default().Println("Error:", err)
			normalLoginResponse.Code = 500
			normalLoginResponse.Message = "Error"
			normalLoginResponse.Status = "error"
			c.JSON(http.StatusInternalServerError, normalLoginResponse)
			return
		}
		log.Default().Println("RequestID:", RequestID)

		//Update The UserID in the Redis
		var separator = ":"
		userkey := fmt.Sprintf("%d%s%d%s%d", user.OrgID, separator, user.DomainId, separator, user.UserId)
		userkeyEncoded := base64.StdEncoding.EncodeToString([]byte(userkey))
		log.Default().Println("Redis Key in Okta Login : ", userkey)
		log.Default().Println("Redis Key Encoded in Okta Login : ", userkeyEncoded)

		err = redis.Set(RequestID, userkeyEncoded, 0).Err()
		if err != nil {
			log.Default().Println("Error:", err)
			normalLoginResponse.Code = 500
			normalLoginResponse.Message = "Error"
			normalLoginResponse.Status = "error"
			c.JSON(http.StatusInternalServerError, normalLoginResponse)
			return
		}
		log.Default().Println("Set Success:", RequestID)

	}

	var tenant models.Tenant

	err = db1.Where("id = ? and status = ? ", user.DomainId, "active").First(&tenant).Error
	if err != nil {
		log.Default().Println("Error:", err)
		normalLoginResponse.Code = 500
		normalLoginResponse.Message = "Tenant Not Found or Inactive"
		normalLoginResponse.Status = "error"
		c.JSON(http.StatusInternalServerError, normalLoginResponse)
		return
	}

	if tenant.SsoMfa == 3 {
		normalLoginResponse.SsoMfa = true
	} else {
		normalLoginResponse.SsoMfa = false
	}

	var userwallet models.UserWallets

	err = db1.Where("user_id = ?", user.UserId).First(&userwallet).Error
	if err != nil {
		log.Default().Println("Error:", err)
		normalLoginResponse.Code = 500
		normalLoginResponse.Message = "Error"
		normalLoginResponse.Status = "error"
		c.JSON(http.StatusInternalServerError, normalLoginResponse)
		return
	}
	normalLoginResponse.UserWalletStatus = userwallet.Status
	c.JSON(http.StatusOK, normalLoginResponse)
}

func GetSessionFromRedis(c *gin.Context) {
	//get the key from the request

	var GetSessionFromRedisRequest dto.GetSessionFromRedisRequest

	if err := c.ShouldBindJSON(&GetSessionFromRedisRequest); err != nil {
		log.Default().Println("Error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	key := GetSessionFromRedisRequest.Key

	redis := db.GetRedisInstance()

	sessionID, err := redis.Get(key).Result()
	if err != nil {
		log.Default().Println("Error:", err)
	}
	c.JSON(http.StatusOK, gin.H{"sessionID": sessionID})

}

func (h *LoginHandler) GetSession(c *gin.Context) {
	// Retrieve the Authorization header from the request
	ID := c.Request.Header.Get("Authorization")

	log.Default().Println("ID:", ID)

	//get session id from cookie set is same domain clinet.did.kloudlearn.com in name of session

	CookieData, err := c.Cookie("session")

	log.Default().Println("Cookie:", CookieData)

	var getSessionResponse *dto.GetSessionResponse

	session2 := &saml.Session{}

	err = Server.Store.Get(fmt.Sprintf("/sessions/%s", ID), &session2)
	if err != nil {
		log.Default().Println("Error:", err)
		getSessionResponse = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error at gettting session",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		c.JSON(http.StatusOK, getSessionResponse)
		return
	}
	if err := json.NewEncoder(c.Writer).Encode(session2); err != nil {
		log.Default().Println("Error:", err)
		getSessionResponse = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error while encoding",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		c.JSON(http.StatusOK, getSessionResponse)
		return
	}

	//log.Default().Println("GET Session:", session2)

	if saml.TimeNow().After(session2.ExpireTime) {
		getSessionResponse = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error session expired",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		c.JSON(http.StatusOK, getSessionResponse)
		return
	}

	session2.ExpireTime = saml.TimeNow().Add(sessionMaxAge)

	err = Server.Store.Put(fmt.Sprintf("/sessions/%s", ID), &session2)
	if err != nil {
		getSessionResponse = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error at updating session",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		c.JSON(http.StatusOK, getSessionResponse)
		return
	}
	err = Server.Store.Get(fmt.Sprintf("/sessions/%s", ID), &session2)
	if err != nil {
		log.Default().Println("Error:", err)
		getSessionResponse = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error at gettting session",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		c.JSON(http.StatusOK, getSessionResponse)
		return
	}

	log.Default().Println("GET Session:", session2)
	getSessionResponse = &dto.GetSessionResponse{
		Code:       200,
		Status:     "ok",
		Validation: true,
		Message:    "Success",
		User:       session2.NameID,
		UserRole:   session2.Groups[0],
	}
	c.JSON(http.StatusOK, getSessionResponse)
}

func (h *LoginHandler) LogoutHandler(c *gin.Context) {

	ID := c.Request.Header.Get("X-Authorization")
	log.Default().Printf("X-Authorization : %s", ID)

	//clear cookie
	err := Server.Store.Delete(fmt.Sprintf("/sessions/%s", ID))
	if err != nil {
		log.Default().Println("Error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Default().Println("Session deleted successfully")
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func (h *LoginHandler) HandleSamlResponse(c *gin.Context) {
	//var tokenValue string

	var handleSamlResponse *dto.HandleSamlResponse
	// Read the SAMLResponse from the request body
	samlResponse := c.PostForm("SAMLResponse")
	log.Default().Printf("SAML Response : %s\n", samlResponse)
	// Decode and parse the SAML response
	decodedResponse, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		log.Println("Error decoding SAML response:", err)
		handleSamlResponse = &dto.HandleSamlResponse{
			Code:    500,
			Status:  "Failed",
			Message: "Error Decoding SAML Response",
		}
		c.JSON(http.StatusInternalServerError, handleSamlResponse)
		return
	}
	var root RootElement
	var response saml.Response
	var logoutResponse saml.LogoutResponse
	err = xml.Unmarshal(decodedResponse, &root)
	if err != nil {
		log.Println("Error parsing SAML response:", err)
		handleSamlResponse = &dto.HandleSamlResponse{
			Code:    500,
			Status:  "Failed",
			Message: "Error Parsing SAML Response",
		}
		c.JSON(http.StatusInternalServerError, handleSamlResponse)
		return
	}
	//Switch case to check if the root element is LogoutResponse or Response

	switch root.XMLName.Local {
	case "Response":

		err = xml.Unmarshal(decodedResponse, &response)
		if err != nil {
			log.Println("Error parsing SAML Response:", err)
			handleSamlResponse = &dto.HandleSamlResponse{
				Code:    500,
				Status:  "Failed",
				Message: "Error Parsing SAML Response",
			}
			c.JSON(http.StatusInternalServerError, handleSamlResponse)
			return
		}

		log.Println("Successfully parsed SAML Response")
		log.Println("Issuer:", response.Assertion.Issuer.Value)

	case "LogoutResponse":

		err = xml.Unmarshal(decodedResponse, &logoutResponse)
		if err != nil {
			log.Println("Error parsing LogoutResponse:", err)
			handleSamlResponse = &dto.HandleSamlResponse{
				Code:    500,
				Status:  "Failed",
				Message: "Error Parsing Logout Response",
			}
			c.JSON(http.StatusInternalServerError, handleSamlResponse)
			return
		}

		log.Println("Successfully parsed LogoutResponse from:", logoutResponse.Issuer.Value)
		log.Println("Logout Status Code:", logoutResponse.Status.StatusCode.Value)

		handleSamlResponse = &dto.HandleSamlResponse{
			Code:    200,
			Status:  "Success",
			Message: "LogoutResponse handled successfully",
		}
		//c.JSON(http.StatusOK, handleSamlResponse)
		//return
		authnullLogoutUrl := "https://default.devsetup.dev.authnull.com/custom/Logout"
		log.Default().Println("Redirecting to Authnull Logout URL:", authnullLogoutUrl)

		c.Redirect(http.StatusFound, authnullLogoutUrl)
		return
	}

	session := &saml.Session{}
	user := User{}

	//Seeting Base URL from Audience URI
	audience := ""
	if len(response.Assertion.Conditions.AudienceRestrictions) > 0 {
		audience = response.Assertion.Conditions.AudienceRestrictions[0].Audience.Value
	} else {
		log.Println("No AudienceRestriction found in SAML response")
		handleSamlResponse = &dto.HandleSamlResponse{
			Code:    500,
			Status:  "Failed",
			Message: "Error Invalid SAML Response - No Audience Value Found",
		}
		c.JSON(http.StatusInternalServerError, handleSamlResponse)
		return
	}

	tenantName := strings.Split(audience, ".")[0]
	orgName := strings.Split(audience, ".")[1]
	log.Default().Println("Organization Name: ", orgName)
	log.Default().Printf("Tenant Name : %s", tenantName)
	db := db.GetConnectiontoDatabaseDynamically(orgName)

	var userCount int64
	var tenant models.Tenant
	var users models.User
	var role []string

	nameId := response.Assertion.Subject.NameID.Value

	log.Default().Printf("Name ID: %s", nameId)

	if err := db.Where("tenant_name ILIKE ? and status = ?", tenantName, "active").First(&tenant).Error; err != nil {
		handleSamlResponse = &dto.HandleSamlResponse{
			Code:    500,
			Status:  "Failed",
			Message: "Tenant Not Found or Inactive",
		}
		c.JSON(http.StatusInternalServerError, handleSamlResponse)
		return
	}

	tenantId := strconv.Itoa(int(tenant.Id))
	if err = db.Model(&models.User{}).Where("email_address = ? AND domain_id = ?", nameId, tenantId).Count(&userCount).Error; err != nil {
		log.Default().Println("Error:", err)
		handleSamlResponse = &dto.HandleSamlResponse{
			Code:    500,
			Status:  "Failed",
			Message: "User Table Not Found",
		}
		c.JSON(http.StatusInternalServerError, handleSamlResponse)
		return
	}

	if userCount == 0 {
		// Call AuthenticateUser
		err = util.OnboardUser(orgName, tenantName, nameId, audience)
		if err != nil {
			log.Println("User Onboarding Failed ", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		//Return success
		handleSamlResponse = &dto.HandleSamlResponse{
			Code:    200,
			Status:  "Success",
			Message: "User Onboarding Invites Sent Successfully",
		}
		// c.JSON(http.StatusOK, handleSamlResponse)

		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(util.SuccessPageTemplate))
		log.Default().Println("User Onboarding Invites Sent Successfully")

		//call logout handler to clear the session
		log.Default().Println("Calling SamlLogoutHandler to clear SAML session")
		util.SamlLogoutHandler(c, nameId, response.Assertion.AuthnStatements[0].SessionIndex)
		return

	} else {
		if err = db.Where("email_address = ?", nameId).First(&users).Error; err != nil {
			log.Default().Println("Error:", err)
			handleSamlResponse = &dto.HandleSamlResponse{
				Code:    500,
				Status:  "Failed",
				Message: "User Table Not Found",
			}
			c.JSON(http.StatusInternalServerError, handleSamlResponse)
			return
		}
		if users.UserRoleID == 1 {
			role = []string{"ADMIN"}
		} else if users.UserRoleID == 3 {
			role = []string{"ENDUSER"}
		}
		log.Default().Printf("Role : %s", role)

		user = User{
			Name:   response.Assertion.Subject.NameID.Value,
			Email:  response.Assertion.Subject.NameID.Value,
			Groups: role,
			//find attribute
			CommonName:        response.Assertion.Subject.NameID.Value,
			Surname:           response.Assertion.Subject.NameID.Value,
			GivenName:         response.Assertion.Subject.NameID.Value,
			ScopedAffiliation: response.Assertion.Subject.NameID.Value,
		}

		session = &saml.Session{
			ID:         base64.StdEncoding.EncodeToString(util.RandomBytes(32)),
			NameID:     user.Email,
			CreateTime: saml.TimeNow(),
			ExpireTime: saml.TimeNow().Add(sessionMaxAge),
			//Index: hex.EncodeToString(randomBytes(32)),
			Index:    response.Assertion.AuthnStatements[0].SessionIndex,
			UserName: user.Name,
			// nolint:gocritic // Groups should be a slice here.
			Groups:         user.Groups[:],
			UserEmail:      user.Email,
			UserCommonName: user.CommonName,
			UserSurname:    user.Surname,
			UserGivenName:  user.GivenName,
			// CustomAttributes: response.Assertion.AttributeStatements[0].Attributes,
		}

		err = Server.Store.Put(fmt.Sprintf("/sessions/%s", session.ID), session)

		if err != nil {
			log.Default().Println("Error:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}
		log.Default().Println("Session:", session.ID)
		log.Default().Println("Session Index :", session.Index)

		//data to sent to frontend while redirecting

		redirectParams := url.Values{}

		redirectParams.Set("userName", nameId)
		redirectParams.Set("first_login", "1")
		redirectParams.Set("token", session.ID) // or your actual token
		redirectParams.Set("url", fmt.Sprintf("%s.%s.dev.authnull.com", tenantName, orgName))

		finalRedirectURL := fmt.Sprintf(
			"https://ssc.authnull.com/ssc/signin?%s",
			redirectParams.Encode(),
		)

		log.Default().Println("Redirect URL:", finalRedirectURL)
		c.Redirect(http.StatusFound, finalRedirectURL)

	}
}

func (h *LoginHandler) SamlLogout(c *gin.Context) {

	rawHeader := c.Request.Header.Get("X-Authorization")
	log.Default().Printf("Raw X-Authorization: %s", rawHeader)

	// Extract the session ID by splitting on "&DOMAIN"
	parts := strings.Split(rawHeader, "&DOMAIN&")
	if len(parts) == 0 {
		log.Default().Println("Invalid X-Authorization header format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid X-Authorization header format"})
		return
	}

	sessionID := parts[0]
	log.Default().Printf("Extracted Session ID: %s", sessionID)

	log.Default().Printf(parts[1])
	//Splitting to get tenant name and org name
	domainParts := strings.Split(parts[1], ".")

	tenantName := domainParts[0]
	orgName := domainParts[1]
	log.Default().Printf("Org Name : %s", orgName)
	log.Default().Printf("Tenant Name: %s", tenantName)

	// Retrieve the session using the session ID
	var session saml.Session
	err := Server.Store.Get(fmt.Sprintf("/sessions/%s", sessionID), &session)
	if err != nil {
		log.Default().Println("Failed to retrieve session:", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	// Log session info
	log.Default().Printf("Session: %+v", session)
	log.Default().Printf("NameID: %s", session.NameID)
	log.Default().Printf("Index: %s", session.Index)

	//Delete the session
	err = Server.Store.Delete(fmt.Sprintf("/sessions/%s", sessionID))
	if err != nil {
		log.Default().Println("Error deleting session:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	db1 := db.GetConnectiontoDatabaseDynamically(orgName)

	var tenantTable models.Tenant

	err = db1.Where("tenant_name ILIKE ?", tenantName).First(&tenantTable).Error
	if err != nil {
		log.Print(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	//checking authentication_method table
	var authenticationMethod models.AuthenticationMethod
	err = db1.Where("tenant_id = ?", tenantTable.Id).First(&authenticationMethod).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if authenticationMethod.AuthenticationMethod == "OKTA" {
		//utils.LogoutHandler(c, session.NameID, session.Index, key, cert)
		//redirect to okta logout url
		// log.Default().Println("Redirecting to Okta logout URL")
		// c.Redirect(http.StatusMovedPermanently, "https://trial-1308598.okta.com/login/signout")
		//domain := "https://trial-1308598.okta.com"

		parsedUrl, err := url.Parse(authenticationMethod.MetadataUrl)
		if err != nil {
			panic(err)
		}

		domain := parsedUrl.Scheme + "://" + parsedUrl.Host
		log.Default().Printf("Okta app Domain: %s", domain)

		apiKey := authenticationMethod.APIKey

		client, err := okta.NewClient(context.Background(), okta.WithOrgUrl(domain), okta.WithToken(apiKey))
		if err != nil {
			fmt.Println("Error creating client:", err)
			return
		}
		log.Default().Println("=====Okta CLient", client)

		user, _, err := client.User.GetUser(session.NameID) // session.NameID = email
		if err != nil {
			log.Println("Error finding user:", err)
			return
		}

		_, err = client.User.EndAllUserSessions(user.Id, nil)
		if err != nil {
			log.Println("Error ending session:", err)
			return
		}
		log.Default().Printf("Session ended for Okta User Id : %s", user.Id)
		log.Default().Printf("Session ended for user with Email: %s", session.NameID)

		log.Println("Session revoked")

		return
	} else if authenticationMethod.AuthenticationMethod == "ONELOGIN" && authenticationMethod.ModuleName == "Emapta-ONELOGIN" {
		util.SamlLogoutHandler(c, session.NameID, session.Index)
		return
	}

	//c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// func to navigate to saml login page after sso mfa fails
func (h *LoginHandler) BackToLogin(c *gin.Context) {
	var backToSamlLoginRequest dto.BackToSamlLoginRequest

	// Bind the JSON request to the struct
	if err := c.BindJSON(&backToSamlLoginRequest); err != nil {
		log.Default().Printf("Error parsing request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	nameID := backToSamlLoginRequest.Email
	token := backToSamlLoginRequest.Token
	tenantUrl := backToSamlLoginRequest.Url
	log.Default().Printf("NameID: %s", nameID)
	log.Default().Printf("Token: %s", token)
	log.Default().Printf("Tenant URL: %s", tenantUrl)

	tenantName := strings.Split(tenantUrl, ".")[0]
	orgName := strings.Split(tenantUrl, ".")[1]

	log.Default().Printf("Organization Name: %s", orgName)
	log.Default().Printf("Tenant Name: %s", tenantName)

	db := db.GetConnectiontoDatabaseDynamically(orgName)
	var tenant models.Tenant
	if err := db.Where("tenant_name ILIKE ?", tenantName).First(&tenant).Error; err != nil {
		log.Default().Println("Error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Default().Printf("Tenant ID: %d", tenant.Id)

	// Check the authentication method
	var authenticationMethod models.AuthenticationMethod
	if err := db.Where("tenant_id = ?", tenant.Id).First(&authenticationMethod).Error; err != nil {
		log.Default().Println("Error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Default().Printf("Authentication Method: %s", authenticationMethod.AuthenticationMethod)

	// Retrieve the session using the session ID
	var session saml.Session
	err := Server.Store.Get(fmt.Sprintf("/sessions/%s", token), &session)
	if err != nil {
		log.Default().Println("Failed to retrieve session:", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}
	log.Default().Printf("Session: %+v", session)
	log.Default().Printf("Index: %s", session.Index)

	//Delete the session
	err = Server.Store.Delete(fmt.Sprintf("/sessions/%s", token))
	if err != nil {
		log.Default().Println("Error deleting session:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Default().Println("Authnull Session deleted successfully")
	//calling samllogout function to clear the session
	log.Default().Println("Checking authentication method for logout")

	if authenticationMethod.AuthenticationMethod == "OKTA" {

		parsedOktaUrl, err := url.Parse(authenticationMethod.MetadataUrl)
		if err != nil {
			panic(err)
		}
		domain := parsedOktaUrl.Scheme + "://" + parsedOktaUrl.Host
		log.Default().Printf("Okta app Domain: %s", domain)

		apiKey := authenticationMethod.APIKey

		client, err := okta.NewClient(context.Background(), okta.WithOrgUrl(domain), okta.WithToken(apiKey))
		if err != nil {
			fmt.Println("Error creating client:", err)
			return
		}
		log.Default().Println("=====Okta CLient", client)

		user, _, err := client.User.GetUser(session.NameID) // session.NameID = email
		if err != nil {
			log.Println("Error finding user:", err)
			return
		}

		_, err = client.User.EndAllUserSessions(user.Id, nil)
		if err != nil {
			log.Println("Error ending session:", err)
			return
		}
		log.Default().Printf("Session ended for Okta User Id : %s", user.Id)
		log.Default().Printf("Session ended for user with Email: %s", session.NameID)

		log.Println("Session revoked")

		return
	} else if authenticationMethod.AuthenticationMethod == "ONELOGIN" && authenticationMethod.ModuleName == "Emapta-ONELOGIN" {
		log.Default().Println("Calling SamlLogoutHandler for ONELOGIN")
		util.SamlLogoutHandler(c, nameID, session.Index)
		log.Default().Println("SamlLogout called successfully for ONELOGIN")
		//c.JSON(200, gin.H{"message": "SAML Logout successful"})
		return

	}
	// Log the successful logout
	//log.Default().Println("SamlLogout called successfully")
	c.JSON(200, gin.H{"message": "Redirected to tenant login page"})

	//calling saml handler to redirect to saml login page
	// utils.SamlHandler(c)
	// log.Default().Println("Redirected to SAML login page")
	// c.JSON(http.StatusOK, gin.H{"message": "Redirected to SAML login page"})
}

func getsession(sessionID string) (bool, string, string, error) {
	// Create a new request using http

	var resp *dto.GetSessionResponse

	session2 := &saml.Session{}

	err := Server.Store.Get(fmt.Sprintf("/sessions/%s", sessionID), &session2)
	if err != nil {
		log.Default().Println("Error:", err)
		resp = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		return false, "", "", nil

	}

	if saml.TimeNow().After(session2.ExpireTime) {
		resp = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		return false, "", "", nil
	}

	session2.ExpireTime = saml.TimeNow().Add(sessionMaxAge)

	err = Server.Store.Put(fmt.Sprintf("/sessions/%s", sessionID), &session2)
	if err != nil {
		resp = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		return false, "", "", nil
	}

	err = Server.Store.Get(fmt.Sprintf("/sessions/%s", sessionID), &session2)
	if err != nil {
		log.Default().Println("Error:", err)
		resp = &dto.GetSessionResponse{
			Code:       500,
			Status:     "error",
			Validation: false,
			Message:    "Error",
			User:       "",
		}
		return false, "", "", nil
	}

	log.Default().Println("GET Session:", session2)

	resp = &dto.GetSessionResponse{
		Code:       200,
		Status:     "ok",
		Validation: true,
		Message:    "Success",
		User:       session2.NameID,
	}

	log.Default().Println("resp:", resp)

	return true, session2.NameID, session2.Groups[0], nil

}

func (h *LoginHandler) SsoMfa(c *gin.Context) {
	var ssoMfaResponse dto.SsoMfaResponse
	var ssoMfaRequest dto.SsoMfaRequest

	//get the request from the body

	if err := c.ShouldBindJSON(&ssoMfaRequest); err != nil {
		log.Default().Println("Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	//get the session id from the request

	sessionID := ssoMfaRequest.Token

	//check if the session is valid

	isvalid, name, role, err := getsession(sessionID)
	name = strings.ToLower(name)
	log.Default().Println("role:", role)
	log.Default().Println("name:", name)
	log.Default().Println("isvalid:", isvalid)

	if err != nil {
		log.Default().Println("Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	if isvalid == false {
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error Session Expired"
		ssoMfaResponse.Status = "error Session Expired"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	var tenant models.Tenant

	//get db name from url

	dbname := strings.Split(ssoMfaRequest.Url, ".")[1]

	db1 := db.GetConnectiontoDatabaseDynamically(dbname)

	//get the tenant details

	err = db1.Where("site_url = ?", ssoMfaRequest.Url).First(&tenant).Error
	if err != nil {
		log.Default().Println("Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	//get the user details

	var user models.User

	err = db1.Where("email_address = ? and domain_id = ?", name, tenant.Id).First(&user).Error
	if err != nil {
		log.Default().Println("Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "User is not onboarded into the tenant"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}
	domainId, _ := strconv.Atoi(user.DomainId)
	//make a call to the sso mfa endpoint

	//url := os.Getenv("DO_AUTHNV4")
	url := "https://dev.api.authnull.com/authnull0/api/v1/authn/v3/do-authenticationV4"

	log.Default().Println("url:", url)

	log.Default().Println("user:", user)

	payload := map[string]interface{}{
		"Username":       user.EmailAddress,
		"CredentialType": "PLATFORM",
		"OrgId":          user.OrgID,
		"TenantId":       domainId,
		"RequestId":      ssoMfaRequest.RequestID,
	}

	payloadBytes, err := json.Marshal(payload)

	if err != nil {
		log.Default().Println("Marshal Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	log.Default().Println("payload:", string(payloadBytes))

	client := &http.Client{}

	// Create a new request using http

	req, err := http.NewRequest("POST", url, strings.NewReader(string(payloadBytes)))

	if err != nil {
		log.Default().Println("Create Request Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Send the request via a client

	resp, err := client.Do(req)

	if err != nil {
		log.Default().Println("Client Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	// Callers should close resp.Body when done reading from it

	defer resp.Body.Close()

	// Check the response

	if resp.StatusCode != http.StatusOK {

		log.Default().Println("Response code Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	// Read the data from the response

	body, err := io.ReadAll(resp.Body)

	if err != nil {

		log.Default().Println("Read data Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	log.Default().Println("Response:", string(body))

	var doAuthnResponse dto.DoAuthnResponse

	err = json.Unmarshal(body, &doAuthnResponse)

	if err != nil {

		log.Default().Println("Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	if doAuthnResponse.Code != 200 {

		log.Default().Println("Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	if !doAuthnResponse.IsValid {
		log.Default().Println("Error:", err)
		ssoMfaResponse.Code = 401
		ssoMfaResponse.Message = "PR Denied"
		ssoMfaResponse.Status = "PR Denied"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	ssoMfaResponse.Code = 200
	ssoMfaResponse.Message = "Success"
	ssoMfaResponse.Status = "ok"
	ssoMfaResponse.Data = true
	ssoMfaResponse.FirstLogin = user.FirstLogin

	//set the session id in the redis with the key userId orgid tenantid and value as session id
	redis := db.GetRedisInstance()
	log.Default().Println("Redis connection established successfully...")
	key := fmt.Sprintf("%d:%d:%d", user.OrgID, user.DomainId, user.UserId)

	value := sessionID

	err = redis.Set(key, value, 0).Err()

	if err != nil {
		log.Default().Println("Error:", err)
		ssoMfaResponse.Code = 500
		ssoMfaResponse.Message = "Error"
		ssoMfaResponse.Status = "error"

		c.JSON(http.StatusInternalServerError, ssoMfaResponse)
		return
	}

	c.JSON(http.StatusOK, ssoMfaResponse)

}

// This handler must be correctly registered for the GET method.
// NOTE: I am renaming the function to reflect its role as the initial Authorization Endpoint.
func (h *LoginHandler) ExternalMFAHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Authorization Endpoint hit! Method: %s", r.Method)

	var redirectURI, state, loginHint string

	// 1. Handle POST: Parse the Form Body
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			log.Printf("FATAL: Error parsing POST form body: %v", err)
			http.Error(w, "Error processing request data", http.StatusBadRequest)
			return
		}

		// --- NEW DEBUGGING CODE START ---
		log.Println("--- All Received POST Body Parameters ---")
		// r.Form holds all parameters from the body
		for key, values := range r.Form {
			// Print the key and all associated values (though usually just one value per key for OIDC)
			log.Printf("Key: %s, Value(s): %v", key, values)
		}
		log.Println("---------------------------------------")
		// --- NEW DEBUGGING CODE END ---

		// Read parameters from the parsed Form body
		redirectURI = r.Form.Get("redirect_uri")
		state = r.Form.Get("state")
		loginHint = r.Form.Get("login_hint")

	} else if r.Method == "GET" {
		// Fallback for GET (reading from URL query)
		query := r.URL.Query()
		redirectURI = query.Get("redirect_uri")
		state = query.Get("state")
		loginHint = query.Get("login_hint")
		// ... (You can add a similar loop here for GET if needed)

	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for required parameters
	if redirectURI == "" || state == "" {
		log.Println("FATAL: Missing required OIDC parameters.")
		http.Error(w, "Missing required OIDC parameters", http.StatusBadRequest)
		return
	}

	log.Printf("OIDC parameters successfully extracted. Redirect URI: %s", redirectURI)

	// SUCCESS path (rest of your logic goes here)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("<html><body>OIDC flow received successfully for user %s. Next step: JWT Signing.</body></html>", loginHint)))
}

func (h *LoginHandler) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Metadata endpoint called by Entra")

	// Define your Issuer URL base
	issuerURL := "https://dev.api.authnull.com"

	// Construct the full metadata response
	meta := dto.Metadata{
		// Standard OIDC Fields
		Issuer:                           issuerURL,
		AuthorizationEndpoint:            issuerURL + "/authentication/auth/external-mfa", // Your custom URL
		JwksURI:                          issuerURL + "/authentication/oauth2/v1/keys",    // IMPORTANT: Must implement this keys endpoint
		ResponseTypesSupported:           []string{"id_token", "token"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
		SubjectTypesSupported:            []string{"public"},
		ScopesSupported:                  []string{"openid", "profile"},

		// Custom EAM Fields
		Version:                "1.0.0",
		AuthenticationMode:     "Synchronous",
		AuthenticationEndpoint: issuerURL + "/authentication/auth/external-mfa",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(meta); err != nil {
		log.Println("Error encoding metadata:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
	log.Default().Printf("Response Metadata: %+v", meta)

}

// Remember to register this handler on the path specified in your OIDC metadata (e.g., /oauth2/v1/keys)
func (h *LoginHandler) JwksHandler(w http.ResponseWriter, r *http.Request) {
	if publicJWK == nil {
		log.Println("Error: JWKS not initialized. Init() failed?")
		http.Error(w, "JWKS not initialized", http.StatusInternalServerError)
		return
	}

	jwks := Jwks{
		Keys: []Jwk{*publicJWK},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Println("Error encoding JWKS:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Custom Base64 URL-safe encoder function (needed for N and E)
func base64UrlEncode(b *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}
