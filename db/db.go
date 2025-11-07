package db

import (
	"fmt"
	"os"
	"sync"

	"github.com/authnull0/mfa-service/models"
	"github.com/go-redis/redis"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var once sync.Once
var dba *gorm.DB
var client *redis.Client

var OrganizationDatabase map[string]*gorm.DB

// Global DB connection
func ConnectGlobalDB() (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable search_path=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_SCHEMA"),
	)
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

// Get tenant's DB name from global DB using tenant_id
func GetTenantDBName(globalDB *gorm.DB, OrgID int) (string, error) {
	var organization models.Organization
	if err := globalDB.Where("id = ?", OrgID).First(&organization).Error; err != nil {
		return "", err
	}
	return organization.OrganizationName, nil
}

// Connect to tenant's DB by db name
func ConnectTenantDB(tenantDB string) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable search_path=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		tenantDB,
		os.Getenv("DB_PORT"),
		os.Getenv("DB_SCHEMA"),
	)
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

func GetInstance(database string) (db *gorm.DB) {

	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	dbname := database
	schema := os.Getenv("DB_SCHEMA")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable search_path=%s", host, user, password, dbname, port, schema)
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true,
	}), &gorm.Config{})
	dba = db
	if err != nil {
		log.Panic().Msgf("Error connecting to the database at %s:%s/%s", host, port, dbname)
	}
	sqlDB, err := dba.DB()
	if err != nil {
		log.Panic().Msgf("Error getting GORM DB definition")
	}
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(2)
	log.Info().Msgf("Successfully established connection to %s:%s/%s", host, port, dbname)

	return dba
}

func GetConnectiontoDatabaseDynamically(database string) (db *gorm.DB) {

	if OrganizationDatabase[database] == nil {
		once.Do(func() {
			OrganizationDatabase = make(map[string]*gorm.DB)
		})

		OrganizationDatabase[database] = GetInstance(database)
		return OrganizationDatabase[database]
	} else {
		return OrganizationDatabase[database]
	}

}
func GetRedisInstance() *redis.Client {
	fmt.Println("Initialised Computed Attributes")

	//connection to redis
	client = redis.NewClient(&redis.Options{
		Addr:     "redis-master.authnull-io.svc.cluster.local:6379",
		Password: "kqe4M1DcaD",
		DB:       0,
	})
	//check if redis is connected
	pong, err := client.Ping().Result()
	fmt.Printf("Redis err : %s", pong)
	fmt.Printf("Error : %s", err)
	fmt.Println(pong, err)
	return client
}
