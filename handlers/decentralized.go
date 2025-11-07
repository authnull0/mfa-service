package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authnull0/mfa-service/config"
	"github.com/authnull0/mfa-service/models"
	"github.com/authnull0/mfa-service/models/dto"
	repositories "github.com/authnull0/mfa-service/repository"
	services "github.com/authnull0/mfa-service/service"
)

type DecentralizedHandler struct {
	Service *services.DecentralizedService
}

func NewDecentralizedHandler() *DecentralizedHandler {
	return &DecentralizedHandler{
		Service: services.NewDecentralizedService(),
	}
}

// @Summary      Begin TOTP Setup
// @Description  Start TOTP authenticator app setup process
// @Tags         TOTP
// @Accept       json
// @Produce      json
// @Param        request body dto.TOTPSetupRequest true "User information"
// @Success      200 {object} dto.TOTPSetupResponse
// @Failure      400 {object} dto.ErrorResponse
// @Failure      404 {object} dto.ErrorResponse
// @Failure      500 {object} dto.ErrorResponse
// @Router       /totp/beginSetup [post]
// BeginRegisterWallet generates wallet registration details
func (h *DecentralizedHandler) BeginRegisterWallet(c *gin.Context) {
	var req dto.RegisterWalletSetupRequest
	var walletKey string
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}
	orgname := strings.Split(req.Url, ".")[1]
	tenantname := strings.Split(req.Url, ".")[0]
	tenantDB, err := config.ConnectTenantDB(orgname)
	if err != nil {
		log.Printf("Failed to connect to tenant database: %v", err)
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "failed to connect to tenant database"})
		return
	}
	mfaRepo := repositories.NewMFARepository(tenantDB)
	tenant := mfaRepo.FindTenantId(tenantname)

	log.Printf("Starting wallet registration for email: %s, tenant: %d", req.Email, tenant.Id)

	user := mfaRepo.FindUserDetails(req.Email, tenant.Id)
	if user.UserId == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var existingWallets []models.UserWallets
	if err := tenantDB.Where("user_id = ? and domain_id =? and LOWER(status) = ?", user.UserId, tenant.Id, "pending").Find(&existingWallets).Error; err != nil {
		log.Default().Println(err)
		return
	}
	// var tenant models.Tenant
	// err = tenantDB.Where("id = ?", req.TenantID).First(&tenant).Error
	// if err != nil {
	// 	c.JSON(http.StatusNotFound, dto.ErrorResponse{Error: "tenant not found"})
	// 	return
	// }

	if len(existingWallets) > 0 {
		log.Default().Printf("Wallet already exists for user_id=%d, domain_id=%d", user.UserId, tenant.Id)
		walletKey = existingWallets[0].WalletKey + "&ORG&" + orgname

	} else {
		walletKey = uuid.New().String() + "&ORG&" + orgname

		log.Default().Printf("Using wallet key: %s", walletKey)
		client := &http.Client{}
		// url := os.Getenv("WALLET_SERVICE") + "/api/v1/walletService/registerDevice"
		url := "https://dev.api.authnull.com/api/v1/walletService/createWallet"
		log.Default().Printf("Wallet service URL: %s", url)
		payload := map[string]interface{}{
			"email":     req.Email,
			"walletKey": walletKey,
			"orgId":     tenant.OrganizationId,
		}

		jsonValue, err := json.Marshal(payload)
		if err != nil {
			log.Print(err.Error())

			response := dto.RegisterWalletSetupResponse{
				WalletKey: walletKey,
				Email:     req.Email,
				TenantID:  tenant.Id,
				Message:   "Failed to marshal payload",
			}
			c.JSON(http.StatusBadRequest, response)
		}

		request, err := http.NewRequest("POST", url, strings.NewReader(string(jsonValue)))

		if err != nil {
			log.Print(err.Error())
			response := dto.RegisterWalletSetupResponse{
				WalletKey: walletKey,
				Email:     req.Email,
				TenantID:  tenant.Id,
				Message:   "Failed to create request",
			}
			c.JSON(http.StatusBadRequest, response)
		}

		resp, err := client.Do(request)

		if err != nil {
			log.Print(err.Error())
			return
		}

		defer resp.Body.Close()
		log.Default().Printf("Wallet service response status: %s", resp.Status)
	}
	// Return the wallet registration details
	response := dto.RegisterWalletSetupResponse{
		WalletKey: walletKey,
		Email:     req.Email,
		TenantID:  tenant.Id,
		Message:   "Wallet registration initiated",
	}
	c.JSON(http.StatusOK, response)
}
