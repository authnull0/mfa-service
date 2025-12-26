package util

import (
	"os"

	"github.com/authnull0/mfa-service/db"
	"github.com/authnull0/mfa-service/models"
	"github.com/crewjam/saml"
)

func RandomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

var OrganizationDatabase map[int]string

func GetOrganizationDatabaseName(orgid int) (string, error) {

	var organization models.Organization

	// Get the organization from the database
	if OrganizationDatabase == nil {
		OrganizationDatabase = make(map[int]string)
	}

	if OrganizationDatabase[orgid] != "" {
		return OrganizationDatabase[orgid], nil
	}

	if orgid == 0 {
		return "", nil
	}

	if OrganizationDatabase[orgid] == "" {
		db := db.GetConnectiontoDatabaseDynamically(os.Getenv("DB_NAME"))
		err := db.Where("id = ?", orgid).First(&organization).Error
		if err != nil {
			return "", err
		}
		OrganizationDatabase[orgid] = organization.OrganizationName
	}

	return organization.OrganizationName, nil

}
