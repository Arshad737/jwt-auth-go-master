// middlewares/authz.go

package middlewares

import (
	"authapp/auth"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// Authz validates token and authorizes users
func Authz() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("Authorization")
		if clientToken == "" {
			c.JSON(403, "No Authorization header provided")
			c.Abort()
			return
		}

		extractedToken := strings.Split(clientToken, "Bearer ")

		if len(extractedToken) == 2 {
			clientToken = strings.TrimSpace(extractedToken[1])
		} else {
			c.JSON(400, "Incorrect Format of Authorization Token")
			c.Abort()
			return
		}

		jwtWrapper := auth.JwtWrapper{
			SecretKey: "verysecretkey",
			Issuer:    "AuthService",
		}

		claims, err := jwtWrapper.ValidateToken(clientToken)
		if err != nil {
			c.JSON(401, err.Error())
			c.Abort()
			return
		}

		c.Set("email", claims.Email)

		c.Next()

	}
}


//https://stackoverflow.com/questions/51834234/i-have-a-public-key-and-a-jwt-how-do-i-check-if-its-valid-in-go
func verifyToken(token, publicKey string) (bool, error) {
    key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(publicKey))
    if err != nil {
        return false, err
    }

    parts := strings.Split(token, ".")
    err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], key)
    if err != nil {
        return false, nil
    }
    return true, nil
}
