package util

import (
	"log"
	"os"
	"strconv"

	"gopkg.in/gomail.v2"
)

func ValidateEmail(email string, message string, subject string) bool {
	m := gomail.NewMessage()

	m.SetHeader("From", "support@authnull.com")
	m.SetHeader("To", email)
	m.SetHeader("Subject", subject)

	Host := os.Getenv("SMTP_HOST")
	Port := os.Getenv("SMTP_PORT")
	Credential := os.Getenv("SMTP_PASSWORD")
	From := os.Getenv("SMTP_FROM")

	intPort, err := strconv.Atoi(Port)
	if err != nil {
		log.Default().Println("Port conversion failed!", err)
		return false
	}

	log.Default().Println(Host, Port, From, Credential)

	m.SetBody("text/html", message)
	d := gomail.NewDialer(Host, intPort, From, Credential)
	err = d.DialAndSend(m)
	if err != nil {
		log.Default().Println("Email sending failed!", err)
		return false
	}
	log.Default().Println("Email sent successfully!")
	return true
}
