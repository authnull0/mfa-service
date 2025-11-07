package util

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"github.com/authnull0/mfa-service/db"
	"github.com/authnull0/mfa-service/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Calling SamlUserOnboard Function
func OnboardUser(orgName string, tenantName string, nameID string, audience string) error {

	db := db.GetConnectiontoDatabaseDynamically(orgName)

	var tenant models.Tenant

	if err := db.Where("tenant_name ILIKE ?", tenantName).First(&tenant).Error; err != nil {
		log.Default().Println("Error:", err)
		return fmt.Errorf("tenant not found: %v", err)
	}

	// If both checks passed, call the external onboarding API
	payload := map[string]interface{}{
		"OrgId":    tenant.OrganizationId,
		"TenantId": tenant.Id,
		"Email":    nameID,
	}

	payloadBytes, _ := json.Marshal(payload)
	log.Default().Printf("Calling SamlOnboard User API")

	req, err := http.NewRequest("POST", "https://prod.tenants.authnull.com/samlOnboardUser", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create onboarding request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("onboarding request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("onboarding API returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Println("User onboarded successfully")
	return nil
}

const (
	entityID = "https://www.okta.com/exkd34w6nxTiIRwaW5d7"
	acsURL   = "https://prod.api.authnull.com/saml/callback"
	// idpSSOURL         = "https://api-dev.platform.outsourcingit.com/auth/v1/saml/protocol/saml/auth/EMAPTA/AUTHNULL"
	idpSSOURL  = "https://api-staging.platform.emapta.com/auth/v1/saml/protocol/saml/auth/EMAPTA/AUTHNULL"
	relayState = "https://prod.api.authnull.com/saml/callback"
	// logoutURL         = "https://api-dev.platform.outsourcingit.com/auth/v1/saml/protocol/saml/auth/EMAPTA/AUTHNULL/logout"
	logoutURL         = "https://api-staging.platform.emapta.com/auth/v1/saml/protocol/saml/auth/EMAPTA/AUTHNULL/logout"
	oktaLogoutURL     = "https://trial-1308598.okta.com/app/trial-1308598_mytestapp_1/exkr6z8gpiLD0dI8S697/slo/saml"
	authnullLogoutURL = "https://default.emaptapam.prod.authnull.com/custom/Logout"
)

// Build minimal LogoutRequest XML
func buildLogoutRequest(nameID string, sessionIndex string) string {
	now := time.Now().UTC().Format(time.RFC3339)
	requestID := "LO_" + uuid.New().String()

	xml := fmt.Sprintf(` <samlp:LogoutRequest 
	xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
	xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
	ID="%s" Version="2.0" IssueInstant="%s" Destination="%s">   
	<saml:Issuer>%s</saml:Issuer>   
	<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>   
	<samlp:SessionIndex>%s</samlp:SessionIndex> 
	</samlp:LogoutRequest>`,
		requestID, now, logoutURL, entityID, nameID, sessionIndex)

	log.Println("Generated LogoutRequest XML:", xml)
	return xml
}

// Logout form HTML
const logoutFormTemplate = `
<html>
  <body onload="document.forms[0].submit()">
    <form method="POST" action="{{.LogoutURL}}">
      <input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />
      <input type="hidden" name="RelayState" value="{{.RelayState}}" />
      <noscript><input type="submit" value="Continue"/></noscript>
    </form>
  </body>
</html>
`

// LogoutFormData structure for logout form data
type LogoutFormData struct {
	LogoutURL   string
	SAMLRequest string
	RelayState  string
}

// SAML logout handler function

// func SamlLogoutHandler(c *gin.Context, nameId string, sessionIndex string) {
// 	log.Default().Println("SAML logout requested")
// 	log.Default().Printf("NameID: %s", nameId)
// 	log.Default().Printf("SessionIndex: %s", sessionIndex)

// 	logoutRequestXML := buildLogoutRequest(nameId, sessionIndex)
// 	deflated, err := deflate([]byte(logoutRequestXML)) // zlib compression
// 	if err != nil {
// 		log.Printf("deflate error: %v", err)
// 		c.String(http.StatusInternalServerError, "Failed to compress logout request")
// 		return
// 	}

// 	encoded := base64.StdEncoding.EncodeToString(deflated)
// 	log.Default().Printf("Encoded Logout Request : %s", encoded)
// 	redirectURL := fmt.Sprintf("%s?SAMLRequest=%s", logoutURL, url.QueryEscape(encoded))
// 	log.Default().Printf("Redirect URL: %s", redirectURL)
// 	c.Redirect(http.StatusFound, redirectURL)
// }
// func deflate(data []byte) ([]byte, error) {
// 	log.Default().Println("Deflating data")
// 	var buf bytes.Buffer
// 	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
// 	if err != nil {
// 		return nil, err
// 	}
// 	_, err = writer.Write(data)
// 	if err != nil {
// 		return nil, err
// 	}
// 	writer.Close()
// 	log.Default().Println("Data deflated successfully")
// 	log.Default().Printf("Deflated data: %s", buf.String())
// 	return buf.Bytes(), nil
// }

func SamlLogoutHandler(c *gin.Context, nameId string, index string) {
	log.Println("SAML logout requested")

	rawLogout := buildLogoutRequest(nameId, index)
	encodedLogout := base64.StdEncoding.EncodeToString([]byte(rawLogout))
	log.Default().Printf("Encoded Logout Response : %s", encodedLogout)

	// data := LogoutFormData{
	// 	LogoutURL:   logoutURL,
	// 	SAMLRequest: encodedLogout,
	// 	RelayState:  relayState,
	// }

	// log.Default().Printf("Building the logout template")
	// var wr http.ResponseWriter

	// tmpl := template.Must(template.New("logoutForm").Parse(logoutFormTemplate))
	// c.Status(http.StatusOK)
	// c.Header("Content-Type", "text/html; charset=utf-8")

	// log.Default().Printf("Executing the logout template")

	// if err := tmpl.Execute(wr, data); err != nil {
	// 	log.Printf("template execution failed: %v", err)
	// 	c.String(http.StatusInternalServerError, "Failed to generate logout form")
	// }
	resp, err := http.PostForm(logoutURL, url.Values{
		"SAMLRequest": {encodedLogout},
		"RelayState":  {relayState},
	})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Server responded with:")
	fmt.Println(string(body))

	// var buf bytes.Buffer

	// log.Default().Println("Executing template into buffer")
	// err := tmpl.Execute(&buf, data)
	// if err != nil {
	// 	log.Printf("Template execution failed: %v", err)
	// 	c.String(http.StatusInternalServerError, "Failed to generate logout form")
	// 	return
	// }

	// log.Printf("Template output preview : %s", buf.String())

	// Write buffer content to response writer
	// _, err = buf.WriteTo(c.Writer)
	// if err != nil {
	// 	log.Printf("Error writing template to response: %v", err)

	// }

	log.Default().Printf("Logout Form Generated Successfully")
	log.Default().Printf("Redirecting to Authnull Logout URL")

	//c.Redirect(http.StatusFound, authnullLogoutURL)
	c.JSON(200, gin.H{
		"message": "Logout form generated successfully",
	})
}

// Generates a minimal AuthnRequest XML
func buildAuthnRequest() string {
	now := time.Now().UTC().Format(time.RFC3339)
	requestID := "AN_" + uuid.New().String()

	xml := fmt.Sprintf(`
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" ProviderName="AUTHNULL" IssueInstant="%s" Destination="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`,
		requestID, now, idpSSOURL, acsURL, entityID)

	log.Default().Println("Generated AuthnRequest XML:", xml)

	return xml
}

// form data for login
const formTemplate = `
<html>
  <body onload="document.forms[0].submit()">
    <form method="POST" action="{{.SSOURL}}">
      <input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />
      <input type="hidden" name="RelayState" value="{{.RelayState}}" />
      <noscript><input type="submit" value="Continue"/></noscript>
    </form>
  </body>
</html>
`

type FormData struct {
	SSOURL      string
	SAMLRequest string
	RelayState  string
}

// SamlHandler function to handle Emapta OneLogin login requests
func SamlHandler(c *gin.Context) {

	//r := c.Request
	w := c.Writer
	log.Println("SAML login requested")
	rawRequest := buildAuthnRequest()
	encodedRequest := base64.StdEncoding.EncodeToString([]byte(rawRequest))

	data := FormData{
		SSOURL:      idpSSOURL,
		SAMLRequest: encodedRequest,
		RelayState:  relayState,
	}

	log.Default().Println("SAMLRequest:", rawRequest)

	// tmpl := template.Must(template.New("samlForm").Parse(formTemplate))
	// if err := tmpl.Execute(w, data); err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// }

	tmpl := template.Must(template.New("samlForm").Parse(formTemplate))
	c.Status(http.StatusOK)
	c.Header("Content-Type", "text/html; charset=utf-8")

	// Use gin's writer to write the response
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("template execution failed: %v", err)
		c.String(http.StatusInternalServerError, "Failed to generate form")
	}
}
