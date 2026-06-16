package handlers

import (
	"net/http"

	"github.com/authnull0/mfa-service/db"
	"github.com/authnull0/mfa-service/models/dto"
	repositories "github.com/authnull0/mfa-service/repository"
	util "github.com/authnull0/mfa-service/utils"
	"github.com/gin-gonic/gin"
)

type MFAProviderConfigHandler struct{}

func NewMFAProviderConfigHandler() *MFAProviderConfigHandler {
	return &MFAProviderConfigHandler{}
}

func (h *MFAProviderConfigHandler) SetMFAProvider(c *gin.Context) {
	var req dto.SetMFAProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	orgName, err := util.GetOrganizationDatabaseName(req.OrgId)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "unknown org"})
		return
	}
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)
	repo := repositories.NewProviderConfigRepository(tenantDB)

	resp, err := repo.Set(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal error"})
		return
	}
	c.JSON(resp.Code, resp)
}

func (h *MFAProviderConfigHandler) GetMFAProvider(c *gin.Context) {
	var req dto.GetMFAProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	orgName, err := util.GetOrganizationDatabaseName(req.OrgId)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "unknown org"})
		return
	}
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)
	repo := repositories.NewProviderConfigRepository(tenantDB)

	resp, err := repo.Get(req.OrgId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal error"})
		return
	}
	c.JSON(resp.Code, resp)
}

func (h *MFAProviderConfigHandler) DeleteMFAProvider(c *gin.Context) {
	var req dto.DeleteMFAProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	orgName, err := util.GetOrganizationDatabaseName(req.OrgId)
	if err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "unknown org"})
		return
	}
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)
	repo := repositories.NewProviderConfigRepository(tenantDB)

	resp, err := repo.Delete(req.OrgId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{Error: "internal error"})
		return
	}
	c.JSON(resp.Code, resp)
}

// GetProviderConfig is an internal endpoint consumed only by ad-service.
// Returns decrypted provider credentials so ad-service can build the right provider.
func (h *MFAProviderConfigHandler) GetProviderConfig(c *gin.Context) {
	var req dto.GetProviderConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{Error: "invalid request"})
		return
	}

	orgName, err := util.GetOrganizationDatabaseName(req.OrgId)
	if err != nil {
		c.JSON(http.StatusOK, dto.GetProviderConfigResponse{Provider: "expo"})
		return
	}
	tenantDB := db.GetConnectiontoDatabaseDynamically(orgName)
	repo := repositories.NewProviderConfigRepository(tenantDB)

	resp, err := repo.GetProviderConfig(req.OrgId)
	if err != nil {
		c.JSON(http.StatusOK, dto.GetProviderConfigResponse{Provider: "expo"})
		return
	}
	c.JSON(http.StatusOK, resp)
}
