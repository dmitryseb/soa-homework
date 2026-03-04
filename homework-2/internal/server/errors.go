package server

import (
	"encoding/json"
	"net/http"

	"soa/homework-2/internal/api"
)

func validationError(message string, details map[string]interface{}) api.ErrorResponse {
	return api.ErrorResponse{
		ErrorCode: api.VALIDATIONERROR,
		Message:   message,
		Details:   detailsPtr(details),
	}
}

func productNotFoundError() api.ErrorResponse {
	return api.ErrorResponse{
		ErrorCode: api.PRODUCTNOTFOUND,
		Message:   "product not found",
	}
}

func tokenExpiredError() api.ErrorResponse {
	return api.ErrorResponse{
		ErrorCode: api.TOKENEXPIRED,
		Message:   "access token expired",
	}
}

func tokenInvalidError() api.ErrorResponse {
	return api.ErrorResponse{
		ErrorCode: api.TOKENINVALID,
		Message:   "access token invalid",
	}
}

func refreshTokenInvalidError() api.ErrorResponse {
	return api.ErrorResponse{
		ErrorCode: api.REFRESHTOKENINVALID,
		Message:   "refresh token invalid",
	}
}

func userAlreadyExistsError() api.ErrorResponse {
	return api.ErrorResponse{
		ErrorCode: api.USERALREADYEXISTS,
		Message:   "user with this email already exists",
	}
}

func authInvalidCredentialsError() api.ErrorResponse {
	return api.ErrorResponse{
		ErrorCode: api.AUTHINVALIDCREDENTIALS,
		Message:   "invalid email or password",
	}
}

func internalError() api.ErrorResponse {
	return api.ErrorResponse{
		ErrorCode: api.INTERNALERROR,
		Message:   "internal server error",
	}
}

func detailsPtr(details map[string]interface{}) *map[string]interface{} {
	if len(details) == 0 {
		return nil
	}
	return &details
}

func RequestErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	resp := validationError(
		"request validation failed",
		map[string]interface{}{
			"reason": err.Error(),
		},
	)
	writeJSONError(w, http.StatusBadRequest, resp)
}

func ResponseErrorHandler(w http.ResponseWriter, _ *http.Request, _ error) {
	writeJSONError(w, http.StatusInternalServerError, internalError())
}

func writeJSONError(w http.ResponseWriter, status int, payload api.ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
