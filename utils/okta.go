package util

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/samlidp"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

var Server *samlidp.Server

func LogoutHandler(c *gin.Context, nameId string, index string, key []byte, cert []byte) {
	log.Default().Printf("Okta Logout Handler")
	// Build LogoutRequest
	logoutRequestXML := buildOktaLogoutRequest(nameId, index)
	log.Default().Printf("Logout XML : %s", logoutRequestXML)

	signedLogoutXML, err := SignLogoutRequestXML(logoutRequestXML, key, cert)
	if err != nil {
		log.Printf("Error signing logout request: %v", err)
		c.String(http.StatusInternalServerError, "Failed to sign SAML Logout Request")

		return
	}
	log.Default().Printf("Signed Logout XML : %s", signedLogoutXML)
	encoded := base64.StdEncoding.EncodeToString([]byte(signedLogoutXML))
	log.Default().Printf("Encoded Logout Request : %s", encoded)
	// Build form and respond
	// data := LogoutFormData{
	// 	LogoutURL:   oktaLogoutURL,
	// 	SAMLRequest: signedRequest,
	// 	RelayState:  relayState,
	// }

	// log.Default().Println("Built Okta Logout Form")
	// log.Default().Printf("Building the logout template")

	// tmpl := template.Must(template.New("logoutForm").Parse(logoutFormTemplate))
	// c.Status(http.StatusOK)
	// c.Header("Content-Type", "text/html; charset=utf-8")

	// log.Default().Printf("Executing the logout template")

	// if err := tmpl.Execute(c.Writer, data); err != nil {
	// 	log.Printf("template execution failed: %v", err)
	// 	c.String(http.StatusInternalServerError, "Failed to generate logout form")
	// }

	// resp, err := http.PostForm(oktaLogoutURL, url.Values{
	// 	"SAMLRequest": {encoded},
	// 	"RelayState":  {relayState},
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// defer resp.Body.Close()

	// body, _ := io.ReadAll(resp.Body)
	// fmt.Println("Server responded with:")
	// fmt.Println(string(body))
	urlEncodedRequest := url.QueryEscape(encoded)
	redirectURL := fmt.Sprintf("%s?SAMLRequest=%s", oktaLogoutURL, urlEncodedRequest)

	fmt.Println("Redirect the user to this URL to initiate SLO:")
	fmt.Println(redirectURL)
	c.Redirect(http.StatusMovedPermanently, redirectURL)
	// c.JSON(http.StatusOK, gin.H{
	// 	"message": "Redirecting to Okta SLO",

	// 	"redirect_url": redirectURL,
	// })

	log.Default().Printf("Logout Handler exited")
}
func buildOktaLogoutRequest(nameID string, sessionIndex string) string {
	log.Default().Printf("BuildOkta Logout Request")
	now := time.Now().UTC().Format(time.RFC3339)
	requestID := "LO_" + uuid.New().String()

	xml := fmt.Sprintf(`
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="%s" Version="2.0" IssueInstant="%s" Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
  <samlp:SessionIndex>%s</samlp:SessionIndex>
</samlp:LogoutRequest>`,
		requestID, now, oktaLogoutURL, entityID, nameID, sessionIndex)

	log.Default().Printf("Generated Logout Request : %s", xml)

	return xml
}

// Parse RSA private key and return *rsa.PrivateKey
func parseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	log.Default().Printf("Parsing RSA private key from PEM")
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Default().Printf("Failed to parse PEM block")
		return nil, errors.New("failed to parse PEM block")
	}
	log.Default().Printf("PEM block parsed successfully")
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Default().Printf("Error parsing PKCS#8 private key: %v", err)
		return nil, fmt.Errorf("parse PKCS#8 failed: %w", err)
	}
	log.Default().Printf("PKCS#8 private key parsed successfully")
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		log.Default().Printf("Parsed key is not an RSA private key")
		return nil, errors.New("not an RSA private key")
	}
	log.Default().Printf("RSA private key parsed successfully")

	return rsaKey, nil
}

// SignLogoutRequestXML signs the XML and returns signed XML as string
// func SignLogoutRequestXML(logoutXML string, privateKeyPEM []byte) (string, error) {
// 	// Parse RSA private key
// 	privKey, err := parseRSAPrivateKeyFromPEM(privateKeyPEM)
// 	if err != nil {
// 		log.Default().Printf("Error parsing private key: %v", err)
// 		return "", err
// 	}
// 	log.Default().Printf("Private key parsed successfully")
// 	// Parse XML string
// 	doc := etree.NewDocument()
// 	if err := doc.ReadFromString(logoutXML); err != nil {
// 		log.Default().Printf("Error reading XML: %v", err)
// 		return "", fmt.Errorf("error reading XML: %w", err)

// 	}
// 	log.Default().Printf("XML parsed successfully")
// 	// Get root element (LogoutRequest)
// 	root := doc.Root()
// 	log.Default().Printf("Root element: %s", root.Tag)

// 	// Create signer
// 	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{
// 		PrivateKey: privKey,
// 	})
// 	ctx.Hash = crypto.SHA256
// 	log.Default().Printf("Signing context created")

// 	// Sign the XML root element
// 	signedEl, err := ctx.SignEnveloped(root)
// 	if err != nil {
// 		log.Default().Printf("Error signing XML: %v", err)
// 		return "", fmt.Errorf("error signing XML: %w", err)
// 	}

// 	// Replace root with signed element
// 	doc.SetRoot(signedEl)
// 	log.Default().Printf("XML signed successfully")

// 	signedStr, err := doc.WriteToString()
// 	if err != nil {
// 		log.Default().Printf("Error converting signed XML to string: %v", err)
// 		return "", fmt.Errorf("error converting signed XML to string: %w", err)

// 	}
// 	log.Default().Printf("Signed XML converted to string successfully")
// 	log.Default().Printf("Signed XML: %s", signedStr)
// 	return signedStr, nil
// }

func SignLogoutRequestXML(logoutXML string, key []byte, cert []byte) (string, error) {
	// Parse private key
	privKey, err := parseRSAPrivateKeyFromPEM(key)
	if err != nil {
		log.Default().Printf("Error parsing private key: %v", err)
		return "", err
	}
	log.Default().Printf("Private key parsed successfully")
	// Parse certificate
	pubCert, err := parseCertificateFromPEM(cert)
	if err != nil {
		log.Default().Printf("Error parsing certificate: %v", err)
		return "", err
	}
	log.Default().Printf("Certificate parsed successfully")
	// Parse XML
	doc := etree.NewDocument()
	if err := doc.ReadFromString(logoutXML); err != nil {
		log.Default().Printf("Error reading XML: %v", err)
		return "", fmt.Errorf("error reading XML: %w", err)
	}
	log.Default().Printf("XML parsed successfully")

	root := doc.Root()
	log.Default().Printf("Root element: %s", root.Tag)

	// Create signing context with both private key and cert
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{
		PrivateKey:  privKey,
		Certificate: [][]byte{pubCert.Raw},
	})
	log.Default().Printf("Signing context created with private key and certificate")
	ctx.Hash = crypto.SHA256
	log.Default().Printf("Hash algorithm set to SHA256")
	signedEl, err := ctx.SignEnveloped(root)
	if err != nil {
		log.Default().Printf("Error signing XML: %v", err)
		return "", fmt.Errorf("error signing XML: %w", err)
	}

	doc.SetRoot(signedEl)
	log.Default().Printf("XML signed successfully")

	signedStr, err := doc.WriteToString()
	if err != nil {
		log.Default().Printf("Error converting signed XML to string: %v", err)
		return "", fmt.Errorf("error converting signed XML to string: %w", err)
	}
	log.Default().Printf("Signed XML converted to string successfully")
	return signedStr, nil
}
func parseCertificateFromPEM(cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		log.Default().Printf("Failed to parse certificate PEM block")
		return nil, errors.New("failed to parse certificate PEM block")
	}
	log.Default().Printf("Certificate PEM block parsed successfully")
	pubCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Default().Printf("Failed to parse certificate: %v", err)
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	log.Default().Printf("Certificate parsed successfully")
	return pubCert, nil
}
