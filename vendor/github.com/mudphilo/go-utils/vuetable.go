package library

import (
	"database/sql"
	"fmt"
	"github.com/mudphilo/go-utils/models"
	"log"
	"os"
	"strconv"
	"strings"
)

func GetVueTableData(db *sql.DB, paginator models.Paginator) models.Pagination {

	search := paginator.VueTable
	joins := paginator.Joins
	fields := paginator.Fields
	orWhere := paginator.OrWhere
	groupBy := paginator.GroupBy
	params := paginator.Params
	tableName := paginator.TableName
	primaryKey := paginator.PrimaryKey

	isDebug,_ := strconv.ParseInt(os.Getenv("DEBUG"),10,64)

	perPage := int(search.PerPage)
	page := int(search.Page)

	joinQuery := strings.Join(joins[:], " ")
	field := strings.Join(fields[:], ",")

	whereQuery := func() string {

		if len(orWhere) > 0 {

			return strings.Join(orWhere[:], " AND ")
		}
		return "1"
	}

	group := func() string {

		if len(groupBy) > 0 {

			return fmt.Sprintf("GROUP BY %s", strings.Join(groupBy[:], " , "))

		}

		return ""
	}

	// build order by query

	orderBy := ""

	if len(search.Sort) > 0 {

		sortPrams := strings.Split(search.Sort, "|")

		column := sortPrams[0]
		direction := sortPrams[1]
		orderBy = fmt.Sprintf("ORDER BY %s %s ", column, direction)
	}

	// count query
	countQuery := fmt.Sprintf("SELECT count(%s) as total FROM %s %s WHERE %s ", primaryKey, tableName, joinQuery, whereQuery())

	total := 0

	dbUtil := Db{DB: db}
	dbUtil.SetQuery(countQuery)
	dbUtil.SetParams(params...)

	if isDebug != 0 {

		log.Printf("Count Query | %s",countQuery)
		log.Printf("Params | %v",params...)

	}


	err := dbUtil.FetchOne().Scan(&total)
	 if err != nil {

	 	log.Printf("got error retrieving total number of records %s ",err.Error())
		return models.Pagination{}
	}

	// calculate offset
	lastPage := CalculateTotalPages(total, perPage)

	currentPage := page - 1
	offset := 0

	if currentPage > 0 {

		offset = perPage * currentPage

	} else {

		currentPage = 0
		offset = 0
	}

	if offset > total {

		offset = total - (currentPage * perPage)
	}

	from := offset + 1
	currentPage++

	limit := fmt.Sprintf(" LIMIT %d,%d", offset, perPage)

	sqlQuery := fmt.Sprintf("SELECT %s FROM %s %s WHERE %s %s %s %s ", field, tableName, joinQuery, whereQuery(), group(), orderBy, limit)

	if isDebug != 0 {

		log.Printf("Data Query | %s",sqlQuery)

	}

	var resp models.Pagination

	// pull records

	// retrieve user roles
	dbUtil.SetQuery(sqlQuery)

	rows, err := dbUtil.Fetch()
	if err != nil {

		log.Printf("error pulling vuetable data %s",err.Error())

		resp.Total = total
		resp.PerPage = perPage
		resp.CurrentPage = currentPage
		resp.LastPage = lastPage
		resp.From = from
		resp.To = 0
		resp.Data = make(map[string]interface{})
		return resp

	}

	defer rows.Close()

	data := paginator.Results(rows)
	resp.Total = total
	resp.PerPage = perPage
	resp.CurrentPage = currentPage
	resp.LastPage = lastPage
	resp.From = from
	resp.To = offset + len(data)
	resp.Data = data
	return resp
}

func DownloadVueTableData(db *sql.DB, paginator models.Paginator) (rowData []interface{}, headrs []string) {

	search := paginator.VueTable
	joins := paginator.Joins
	fields := paginator.Fields
	orWhere := paginator.OrWhere
	groupBy := paginator.GroupBy
	params := paginator.Params
	tableName := paginator.TableName
	primaryKey := paginator.PrimaryKey
	isDebug,_ := strconv.ParseInt(os.Getenv("DEBUG"),10,64)

	joinQuery := strings.Join(joins[:], " ")
	field := strings.Join(fields[:], ",")

	var headers []string

	for _, h := range fields {

		parts := strings.Split(h," ")
		headers = append(headers,parts[len(parts) - 1])
	}

	whereQuery := func() string {

		if len(orWhere) > 0 {

			return strings.Join(orWhere[:], " AND ")
		}
		return "1"
	}

	group := func() string {

		if len(groupBy) > 0 {

			return fmt.Sprintf("GROUP BY %s", strings.Join(groupBy[:], " , "))

		}

		return ""
	}

	// build order by query

	orderBy := ""

	if len(search.Sort) > 0 {

		sortPrams := strings.Split(search.Sort, "|")

		column := sortPrams[0]
		direction := sortPrams[1]
		orderBy = fmt.Sprintf("ORDER BY %s %s ", column, direction)
	}

	// count query
	countQuery := fmt.Sprintf("SELECT count(%s) as total FROM %s %s WHERE %s ", primaryKey, tableName, joinQuery, whereQuery())

	total := 0

	dbUtil := Db{DB: db}
	dbUtil.SetQuery(countQuery)
	dbUtil.SetParams(params...)
	if isDebug != 0 {

		log.Printf("Count Query | %s",countQuery)
		log.Printf("Params | %v",params...)

	}
	err := dbUtil.FetchOne().Scan(&total)
	if err != nil {

		log.Printf("got error retrieving total number of records %s ",err.Error())
		return nil,headers
	}

	sqlQuery := fmt.Sprintf("SELECT %s FROM %s %s WHERE %s %s %s ", field, tableName, joinQuery, whereQuery(), group(), orderBy)

	// pull records

	// retrieve user roles
	dbUtil.SetQuery(sqlQuery)
	if isDebug != 0 {

		log.Printf("Data Query | %s",sqlQuery)

	}
	rows, err := dbUtil.Fetch()
	if err != nil {

		log.Printf("error pulling vuetable data %s",err.Error())
		return nil, headers

	}

	defer rows.Close()

	rowData = paginator.Results(rows)
	return rowData, headers
}
