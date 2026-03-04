package server

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"soa/homework-2/internal/api"
	"soa/homework-2/internal/auth"
	"soa/homework-2/internal/store"
)

type Server struct {
	productStore *store.ProductStore
	authStore    *store.AuthStore
	jwtManager   *auth.JWTManager
	refreshTTL   time.Duration
	orderIDSeq   uint64
}

func New(productStore *store.ProductStore, authStore *store.AuthStore, jwtManager *auth.JWTManager, refreshTTL time.Duration) *Server {
	return &Server{
		productStore: productStore,
		authStore:    authStore,
		jwtManager:   jwtManager,
		refreshTTL:   refreshTTL,
	}
}

func (s *Server) Register(ctx context.Context, request api.RegisterRequestObject) (api.RegisterResponseObject, error) {
	if request.Body == nil {
		return api.Register400JSONResponse(validationError("request body is required", map[string]interface{}{
			"fields": []map[string]string{{"field": "body", "violation": "must be present"}},
		})), nil
	}

	email := normalizeEmail(string(request.Body.Email))
	role := api.USER
	if request.Body.Role != nil {
		role = *request.Body.Role
	}

	passwordHash, err := auth.HashPassword(request.Body.Password)
	if err != nil {
		return nil, err
	}

	user, err := s.authStore.CreateUser(ctx, email, passwordHash, role)
	if err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return api.Register409JSONResponse(userAlreadyExistsError()), nil
		}
		return nil, err
	}

	return api.Register201JSONResponse(api.AuthRegisterResponse{
		UserId: user.ID,
		Email:  openapi_types.Email(user.Email),
		Role:   user.Role,
	}), nil
}

func (s *Server) Login(ctx context.Context, request api.LoginRequestObject) (api.LoginResponseObject, error) {
	if request.Body == nil {
		return api.Login400JSONResponse(validationError("request body is required", map[string]interface{}{
			"fields": []map[string]string{{"field": "body", "violation": "must be present"}},
		})), nil
	}

	email := normalizeEmail(string(request.Body.Email))
	user, err := s.authStore.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return api.Login401JSONResponse(authInvalidCredentialsError()), nil
		}
		return nil, err
	}
	if !auth.VerifyPassword(request.Body.Password, user.PasswordHash) {
		return api.Login401JSONResponse(authInvalidCredentialsError()), nil
	}

	accessToken, expiresIn, err := s.jwtManager.GenerateAccessToken(user.ID, user.Role)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshExpiresAt, err := s.jwtManager.GenerateRefreshToken(user.ID, user.Role, s.refreshTTL)
	if err != nil {
		return nil, err
	}

	if err := s.authStore.SaveRefreshToken(ctx, auth.HashToken(refreshToken), user.ID, refreshExpiresAt); err != nil {
		return nil, err
	}

	return api.Login200JSONResponse(api.AuthTokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	}), nil
}

func (s *Server) RefreshAccessToken(ctx context.Context, request api.RefreshAccessTokenRequestObject) (api.RefreshAccessTokenResponseObject, error) {
	if request.Body == nil {
		return api.RefreshAccessToken400JSONResponse(validationError("request body is required", map[string]interface{}{
			"fields": []map[string]string{{"field": "body", "violation": "must be present"}},
		})), nil
	}

	refreshToken := strings.TrimSpace(request.Body.RefreshToken)
	if refreshToken == "" {
		return api.RefreshAccessToken400JSONResponse(validationError("refresh token validation failed", map[string]interface{}{
			"fields": []map[string]string{{"field": "refresh_token", "violation": "must not be empty"}},
		})), nil
	}

	refreshClaims, err := s.jwtManager.ParseRefreshToken(refreshToken)
	if err != nil {
		return api.RefreshAccessToken401JSONResponse(refreshTokenInvalidError()), nil
	}

	token, err := s.authStore.GetRefreshToken(ctx, auth.HashToken(refreshToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return api.RefreshAccessToken401JSONResponse(refreshTokenInvalidError()), nil
		}
		return nil, err
	}
	if token.UserID != refreshClaims.UserID {
		return api.RefreshAccessToken401JSONResponse(refreshTokenInvalidError()), nil
	}

	user, err := s.authStore.GetUserByID(ctx, refreshClaims.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return api.RefreshAccessToken401JSONResponse(refreshTokenInvalidError()), nil
		}
		return nil, err
	}

	accessToken, expiresIn, err := s.jwtManager.GenerateAccessToken(user.ID, user.Role)
	if err != nil {
		return nil, err
	}

	return api.RefreshAccessToken200JSONResponse(api.AuthAccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	}), nil
}

func (s *Server) CreateOrder(_ context.Context, request api.CreateOrderRequestObject) (api.CreateOrderResponseObject, error) {
	if request.Body == nil {
		return api.CreateOrder400JSONResponse(validationError("request body is required", map[string]interface{}{
			"fields": []map[string]string{{"field": "body", "violation": "must be present"}},
		})), nil
	}

	orderID := int64(atomic.AddUint64(&s.orderIDSeq, 1))
	return api.CreateOrder201JSONResponse(api.OrderCreateResponse{
		OrderId:   orderID,
		Status:    "CREATED",
		CreatedAt: time.Now().UTC(),
	}), nil
}

func (s *Server) ListProducts(ctx context.Context, request api.ListProductsRequestObject) (api.ListProductsResponseObject, error) {
	page := int32(0)
	size := int32(20)

	if request.Params.Page != nil {
		page = *request.Params.Page
	}
	if request.Params.Size != nil {
		size = *request.Params.Size
	}

	result, err := s.productStore.List(ctx, store.ListParams{
		Page:     int(page),
		Size:     int(size),
		Status:   request.Params.Status,
		Category: request.Params.Category,
	})
	if err != nil {
		return nil, err
	}

	return api.ListProducts200JSONResponse{
		Items:         result.Items,
		TotalElements: result.TotalElements,
		Page:          int32(result.Page),
		Size:          int32(result.Size),
	}, nil
}

func (s *Server) CreateProduct(ctx context.Context, request api.CreateProductRequestObject) (api.CreateProductResponseObject, error) {
	if request.Body == nil {
		return api.CreateProduct400JSONResponse(validationError("request body is required", map[string]interface{}{
			"fields": []map[string]string{{"field": "body", "violation": "must be present"}},
		})), nil
	}

	product, err := s.productStore.Create(ctx, *request.Body)
	if err != nil {
		return api.CreateProduct400JSONResponse(validationError("product validation failed", map[string]interface{}{
			"fields": []map[string]string{{"field": "price", "violation": err.Error()}},
		})), nil
	}

	return api.CreateProduct201JSONResponse(product), nil
}

func (s *Server) DeleteProduct(ctx context.Context, request api.DeleteProductRequestObject) (api.DeleteProductResponseObject, error) {
	product, err := s.productStore.Archive(ctx, request.Id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return api.DeleteProduct404JSONResponse(productNotFoundError()), nil
		}
		return nil, err
	}

	return api.DeleteProduct200JSONResponse(product), nil
}

func (s *Server) GetProduct(ctx context.Context, request api.GetProductRequestObject) (api.GetProductResponseObject, error) {
	product, err := s.productStore.GetByID(ctx, request.Id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return api.GetProduct404JSONResponse(productNotFoundError()), nil
		}
		return nil, err
	}

	return api.GetProduct200JSONResponse(product), nil
}

func (s *Server) UpdateProduct(ctx context.Context, request api.UpdateProductRequestObject) (api.UpdateProductResponseObject, error) {
	if request.Body == nil {
		return api.UpdateProduct400JSONResponse(validationError("request body is required", map[string]interface{}{
			"fields": []map[string]string{{"field": "body", "violation": "must be present"}},
		})), nil
	}

	product, err := s.productStore.Update(ctx, request.Id, *request.Body)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return api.UpdateProduct404JSONResponse(productNotFoundError()), nil
		}
		return api.UpdateProduct400JSONResponse(validationError("product validation failed", map[string]interface{}{
			"fields": []map[string]string{{"field": "price", "violation": err.Error()}},
		})), nil
	}

	return api.UpdateProduct200JSONResponse(product), nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
