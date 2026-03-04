package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"

	"soa/homework-2/internal/api"
)

func NewOpenAPIValidationMiddleware() (func(http.Handler) http.Handler, error) {
	swagger, err := api.GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("load swagger: %w", err)
	}

	// Disable host checks so local runs through different hosts/ports still validate request payloads.
	swagger.Servers = nil
	if err := swagger.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("validate swagger: %w", err)
	}

	router, err := legacyrouter.NewRouter(swagger)
	if err != nil {
		return nil, fmt.Errorf("build router: %w", err)
	}

	return OpenAPIValidationMiddleware(router), nil
}

func OpenAPIValidationMiddleware(router routers.Router) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route, pathParams, err := router.FindRoute(r)
			if err != nil {
				// Keep default not-found / method-not-allowed behavior.
				next.ServeHTTP(w, r)
				return
			}

			input := &openapi3filter.RequestValidationInput{
				Request:    r,
				PathParams: pathParams,
				Route:      route,
				Options: &openapi3filter.Options{
					AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
					MultiError:         true,
				},
			}

			if err := openapi3filter.ValidateRequest(r.Context(), input); err != nil {
				writeJSONError(w, http.StatusBadRequest, validationError("request validation failed", validationDetailsFromOpenAPIError(err)))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func validationDetailsFromOpenAPIError(err error) map[string]interface{} {
	violations := make([]map[string]string, 0, 4)
	collectValidationViolations(err, "request", &violations)
	if len(violations) == 0 {
		violations = append(violations, map[string]string{
			"field":     "request",
			"violation": err.Error(),
		})
	}
	return map[string]interface{}{"fields": violations}
}

func collectValidationViolations(err error, fallbackField string, violations *[]map[string]string) {
	if err == nil {
		return
	}

	var requestErr *openapi3filter.RequestError
	if errors.As(err, &requestErr) {
		field := fallbackField
		if requestErr.Parameter != nil {
			field = requestErr.Parameter.Name
		} else if requestErr.RequestBody != nil {
			field = "body"
		}

		if requestErr.Err != nil {
			collectValidationViolations(requestErr.Err, field, violations)
			return
		}

		message := requestErr.Reason
		if strings.TrimSpace(message) == "" {
			message = requestErr.Error()
		}
		addViolation(violations, field, message)
		return
	}

	var schemaErr *openapi3.SchemaError
	if errors.As(err, &schemaErr) {
		field := fieldFromSchemaPointer(schemaErr.JSONPointer(), fallbackField)
		message := strings.TrimSpace(schemaErr.Reason)
		if message == "" {
			message = schemaErr.Error()
		}
		addViolation(violations, field, message)
		return
	}

	var parseErr *openapi3filter.ParseError
	if errors.As(err, &parseErr) {
		field := fieldFromParsePath(parseErr.Path(), fallbackField)
		message := strings.TrimSpace(parseErr.Reason)
		if message == "" {
			message = parseErr.Error()
		}
		addViolation(violations, field, message)
		return
	}

	var multi openapi3.MultiError
	if errors.As(err, &multi) {
		for _, nested := range multi {
			collectValidationViolations(nested, fallbackField, violations)
		}
		return
	}

	addViolation(violations, fallbackField, err.Error())
}

func fieldFromSchemaPointer(pointer []string, fallback string) string {
	parts := make([]string, 0, len(pointer))
	for _, p := range pointer {
		switch p {
		case "", "body", "query", "path", "header", "request", "response":
			continue
		default:
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return fallback
	}
	return strings.Join(parts, ".")
}

func fieldFromParsePath(path []any, fallback string) string {
	parts := make([]string, 0, len(path))
	for _, p := range path {
		text := strings.TrimSpace(fmt.Sprint(p))
		if text == "" {
			continue
		}
		switch text {
		case "body", "query", "path", "header", "request", "response":
			continue
		default:
			parts = append(parts, text)
		}
	}
	if len(parts) == 0 {
		return fallback
	}
	return strings.Join(parts, ".")
}

func addViolation(violations *[]map[string]string, field, message string) {
	field = strings.TrimSpace(field)
	if field == "" {
		field = "request"
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = "invalid value"
	}

	*violations = append(*violations, map[string]string{
		"field":     field,
		"violation": message,
	})
}
