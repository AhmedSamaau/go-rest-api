package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const SECRETKEY = "supersecret"

func GenerateToken(email string, userId int64) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":  email,
		"userId": userId,
		"exp":    time.Now().Add(time.Hour * 2).Unix(),
	})

	return token.SignedString([]byte(SECRETKEY))
}

func VerifyToken(token string) (int64, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)

		if !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(SECRETKEY), nil
	})

	if err != nil {
		return 0, errors.New("could not parse token")
	}

	tokenIsValid := parsedToken.Valid
	if !tokenIsValid {
		return 0, errors.New("invalid token")
	}

	// this logic is for extracting the data from the token
	claims, ok := parsedToken.Claims.(jwt.MapClaims)

	if !ok {
		return 0, errors.New("invalid token claims")
	}

	// email := claims["email"].(string)
	userId := int64(claims["userId"].(float64))
	return userId, err
}
