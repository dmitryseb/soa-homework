package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"soa/homework-2/internal/api"
)

var ErrNotFound = errors.New("not found")

type ProductStore struct {
	db *sql.DB
}

type ListParams struct {
	Page     int
	Size     int
	Status   *api.ProductStatus
	Category *string
}

type ListResult struct {
	Items         []api.ProductResponse
	TotalElements int64
	Page          int
	Size          int
}

func NewProductStore(db *sql.DB) *ProductStore {
	return &ProductStore{db: db}
}

func (s *ProductStore) Create(ctx context.Context, body api.ProductCreate) (api.ProductResponse, error) {
	price, err := normalizePrice(body.Price)
	if err != nil {
		return api.ProductResponse{}, err
	}

	var product api.ProductResponse
	err = s.db.QueryRowContext(
		ctx,
		`INSERT INTO products (name, description, price, stock, category, status)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, name, description, price, stock, category, status, created_at, updated_at`,
		body.Name,
		nullableString(body.Description),
		price,
		body.Stock,
		body.Category,
		body.Status,
	).Scan(
		&product.Id,
		&product.Name,
		&product.Description,
		&product.Price,
		&product.Stock,
		&product.Category,
		&product.Status,
		&product.CreatedAt,
		&product.UpdatedAt,
	)
	if err != nil {
		return api.ProductResponse{}, err
	}

	return product, nil
}

func (s *ProductStore) GetByID(ctx context.Context, id int64) (api.ProductResponse, error) {
	var product api.ProductResponse
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, name, description, price, stock, category, status, created_at, updated_at
		 FROM products
		 WHERE id = $1`,
		id,
	).Scan(
		&product.Id,
		&product.Name,
		&product.Description,
		&product.Price,
		&product.Stock,
		&product.Category,
		&product.Status,
		&product.CreatedAt,
		&product.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ProductResponse{}, ErrNotFound
		}
		return api.ProductResponse{}, err
	}

	return product, nil
}

func (s *ProductStore) List(ctx context.Context, params ListParams) (ListResult, error) {
	where := "WHERE 1=1"
	args := make([]any, 0, 4)
	argPos := 1

	if params.Status != nil {
		where += " AND status = $" + strconv.Itoa(argPos)
		args = append(args, *params.Status)
		argPos++
	}

	if params.Category != nil {
		where += " AND category = $" + strconv.Itoa(argPos)
		args = append(args, *params.Category)
		argPos++
	}

	var total int64
	countQuery := "SELECT COUNT(*) FROM products " + where
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return ListResult{}, err
	}

	offset := params.Page * params.Size
	listQuery := fmt.Sprintf(`
		SELECT id, name, description, price, stock, category, status, created_at, updated_at
		FROM products
		%s
		ORDER BY id
		LIMIT $%d OFFSET $%d`, where, argPos, argPos+1)
	args = append(args, params.Size, offset)

	rows, err := s.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()

	items := make([]api.ProductResponse, 0, params.Size)
	for rows.Next() {
		var item api.ProductResponse
		if err := rows.Scan(
			&item.Id,
			&item.Name,
			&item.Description,
			&item.Price,
			&item.Stock,
			&item.Category,
			&item.Status,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return ListResult{}, err
		}
		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}

	return ListResult{
		Items:         items,
		TotalElements: total,
		Page:          params.Page,
		Size:          params.Size,
	}, nil
}

func (s *ProductStore) Update(ctx context.Context, id int64, body api.ProductUpdate) (api.ProductResponse, error) {
	price, err := normalizePrice(body.Price)
	if err != nil {
		return api.ProductResponse{}, err
	}

	var product api.ProductResponse
	err = s.db.QueryRowContext(
		ctx,
		`UPDATE products
		 SET name = $1,
		     description = $2,
		     price = $3,
		     stock = $4,
		     category = $5,
		     status = $6
		 WHERE id = $7
		 RETURNING id, name, description, price, stock, category, status, created_at, updated_at`,
		body.Name,
		nullableString(body.Description),
		price,
		body.Stock,
		body.Category,
		body.Status,
		id,
	).Scan(
		&product.Id,
		&product.Name,
		&product.Description,
		&product.Price,
		&product.Stock,
		&product.Category,
		&product.Status,
		&product.CreatedAt,
		&product.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ProductResponse{}, ErrNotFound
		}
		return api.ProductResponse{}, err
	}

	return product, nil
}

func (s *ProductStore) Archive(ctx context.Context, id int64) (api.ProductResponse, error) {
	var product api.ProductResponse
	err := s.db.QueryRowContext(
		ctx,
		`UPDATE products
		 SET status = 'ARCHIVED'
		 WHERE id = $1
		 RETURNING id, name, description, price, stock, category, status, created_at, updated_at`,
		id,
	).Scan(
		&product.Id,
		&product.Name,
		&product.Description,
		&product.Price,
		&product.Stock,
		&product.Category,
		&product.Status,
		&product.CreatedAt,
		&product.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ProductResponse{}, ErrNotFound
		}
		return api.ProductResponse{}, err
	}

	return product, nil
}

func normalizePrice(raw string) (string, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return "", fmt.Errorf("must be a valid decimal")
	}
	if value < 0.01 {
		return "", fmt.Errorf("must be greater than or equal to 0.01")
	}
	return raw, nil
}

func nullableString(src *string) any {
	if src == nil {
		return nil
	}
	return *src
}
