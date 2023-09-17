package library

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

// router and DB instance
type Db struct {
	DB     *sql.DB
	TX     *sql.Tx
	Query  string
	Dialect string `default:"mysql"`
	Params []interface{}
	Result []interface{}
}

const DbError = "Got error  preparing a.Query %s a.Params %v error %s "

func (a *Db) InsertQuery() (lastInsertID int64, err error) {

	if a.Dialect == "postgres" {

		var lastInsertId sql.NullInt64

		err = a.DB.QueryRow(a.Query,a.Params...).Scan(&lastInsertId)
		if err != nil {

			log.Printf(DbError, a.Query, a.Params, err.Error())
			return 0, err
		}

		return lastInsertId.Int64, nil

	}

	stmt, err := a.DB.Prepare(a.Query)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return 0, err
	}

	defer stmt.Close()

	res, err := stmt.Exec(a.Params...)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return 0, err
	}

	lastInsertId, err := res.LastInsertId()
	if err != nil {
		log.Printf(DbError, a.Query, a.Params, err.Error())
		return 0, err
	}

	return lastInsertId, nil
}

func (a *Db) UpdateQuery() (rowsAffected int64, err error) {


	stmt, err := a.DB.Prepare(a.Query)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return 0, err
	}

	defer stmt.Close()

	res, err := stmt.Exec(a.Params...)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return 0, err
	}

	rowsaffected, err := res.RowsAffected()
	if err != nil {
		log.Printf(DbError, a.Query, a.Params, err.Error())
		return 0, err
	}

	return rowsaffected, nil
}

func (a *Db) InsertInTransaction() (lastInsertID *int64, err error) {

	wasNil :=false

	if a.TX == nil {

		wasNil = true
		a.TX, err = a.DB.Begin()
		if err != nil {

			log.Printf("Got error starting transaction %s ", err.Error())
			return nil, err
		}

	}

	stmt, err := a.TX.Prepare(a.Query)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	defer stmt.Close()

	res, err := stmt.Exec(a.Params...)
	if err != nil {

		if wasNil {

			_ = a.TX.Rollback()
		}
		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	lastInsertId, err := res.LastInsertId()
	if err != nil {

		if wasNil {

			_ = a.TX.Rollback()
		}
		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	if wasNil {

		_ = a.TX.Rollback()
	}

	return &lastInsertId, nil
}

func (a *Db) InsertIgnore() (lastInsertID *int64, err error) {

	if a.Dialect == "postgres" {


	}

	stmt, err := a.DB.Prepare(a.Query)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	defer stmt.Close()

	res, err := stmt.Exec(a.Params...)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	lastInsertId, err := res.LastInsertId()
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, nil
	}

	return &lastInsertId, nil
}

func (a *Db) InsertIgnoreInTransaction() (lastInsertID *int64, err error) {

	stmt, err := a.TX.Prepare(a.Query)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	defer stmt.Close()

	res, err := stmt.Exec(a.Params...)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	lastInsertId, err := res.LastInsertId()
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, nil
	}

	return &lastInsertId, nil
}

func (a *Db) UpdateInTransaction() (rowsAffected *int64, err error) {

	stmt, err := a.TX.Prepare(a.Query)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	defer stmt.Close()

	res, err := stmt.Exec(a.Params...)
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	rowsaffected, err := res.RowsAffected()
	if err != nil {

		log.Printf(DbError, a.Query, a.Params, err.Error())
		return nil, err
	}

	return &rowsaffected, nil
}

func (a *Db) FetchOne() *sql.Row {

	if a.Dialect == "mysql" {

		_, err := a.DB.Exec("SET SESSION sql_mode=(SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY',''))")
		if err != nil {

			log.Printf("error disabling ONLY_FULL_GROUP_BY %s", err.Error())
		}

	}

	return a.DB.QueryRow(a.Query, a.Params...)
}

func (a *Db) Fetch() (*sql.Rows, error) {

	if a.Dialect == "mysql" {

		_, err := a.DB.Exec("SET SESSION sql_mode=(SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY',''))")
		if err != nil {

			log.Printf("error disabling ONLY_FULL_GROUP_BY %s", err.Error())
		}

	}

	rows, err := a.DB.Query(a.Query, a.Params...)
	if err != nil {

		log.Printf("error fetching results from database using query %s  error %s",a.Query,err.Error())
	}

	return rows, err
}

func (a *Db) SetParams(params ...interface{}) {

	a.Params = params
}

func (a *Db) SetQuery(query string) {

	a.Query = query
}

func (a *Db) setResults(result ...interface{}) {

	a.Result = result
}

func (a *Db) Upsert(tableName string, data map[string]interface{},updates []string) (int64, error) {

	var placeHoldersParts,updatesPart,columns []string
	var params []interface{}

	x := 0

	for column, param := range data {

		x++
		params = append(params, param)
		columns = append(columns, column)
		if a.Dialect == "postgres" {

			placeHoldersParts = append(placeHoldersParts,fmt.Sprintf("$%d",x))

		} else {

			placeHoldersParts = append(placeHoldersParts,"?")

		}
	}

	updateString := ""

	if updates != nil {

		for _, f := range updates {

			updatesPart = append(updatesPart,fmt.Sprintf("%s=VALUES(%s)",f,f))
		}

		updateString = fmt.Sprintf("ON DUPLICATE KEY UPDATE %s ",strings.Join(updatesPart,","))
	}

	sqlQueryParts := fmt.Sprintf("INSERT INTO %s (%s) %s (%s) %s",tableName,strings.Join(columns,","),a.getValueKeyword(),strings.Join(placeHoldersParts,","),updateString)

	a.SetQuery(sqlQueryParts)
	a.SetParams(params...)
	return a.InsertQuery()
}

func (a *Db) Update(tableName string, andCondition,data map[string]interface{}) (int64, error) {

	var conditions,columns []string
	var params []interface{}

	x := 0
	for column, param := range data {

		x++
		params = append(params, param)
		if a.Dialect == "postgres" {

			columns = append(columns, fmt.Sprintf("%s = $%d ",column,x))

		} else {

			columns = append(columns, fmt.Sprintf("%s = ? ",column))

		}
	}

	for column, value := range andCondition {

		x++
		if a.Dialect == "postgres" {

			conditions = append(conditions, fmt.Sprintf("%s = $%d ", column, x))

		} else {

			conditions = append(conditions, fmt.Sprintf("%s = ? ", column))

		}

		params = append(params, value)

	}

	sqlQueryParts := fmt.Sprintf("UPDATE  %s SET %s WHERE %s ",tableName,strings.Join(columns,","),strings.Join(conditions," AND "))

	a.SetQuery(sqlQueryParts)
	a.SetParams(params...)
	return a.UpdateQuery()
}

func (a *Db) Delete(tableName string, andCondition map[string]interface{}) (int64, error) {

	var conditions []string
	var params []interface{}

	x := 0
	for column, value := range andCondition {

		x++
		if a.Dialect == "postgres"{

			conditions = append(conditions, fmt.Sprintf("%s = $%d ",column,x))

		} else {

			conditions = append(conditions, fmt.Sprintf("%s = ? ",column))

		}
		params = append(params, value)
	}

	sqlQueryParts := fmt.Sprintf("DELETE FROM %s WHERE %s ",tableName,strings.Join(conditions," AND "))

	a.SetQuery(sqlQueryParts)
	a.SetParams(params...)
	return a.UpdateQuery()
}

func (a *Db) UpsertData(tableName string,primaryKey string, data map[string]interface{},conflicts,updates []string) (int64, error) {

	var placeHoldersParts,updatesPart,columns []string
	var params []interface{}

	x := 0
	for column, param := range data {

		x++
		params = append(params, param)
		columns = append(columns, column)

		if a.Dialect == "postgres" {

			placeHoldersParts = append(placeHoldersParts,fmt.Sprintf("$%d",x))

		} else {

			placeHoldersParts = append(placeHoldersParts,"?")

		}
	}

	updateString := ""

	if updates != nil {

		for _, f := range updates {

			if a.Dialect == "postgres" {

				//excluded.
				updatesPart = append(updatesPart, fmt.Sprintf("%s=excluded.%s", f, f))

			} else {

				updatesPart = append(updatesPart, fmt.Sprintf("%s=VALUES(%s)", f, f))

			}
		}

		if a.Dialect == "postgres" {

			updateString = fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET %s ",strings.Join(conflicts, ","),  strings.Join(updatesPart, ","))

		} else {

			updateString = fmt.Sprintf("ON DUPLICATE KEY UPDATE %s ", strings.Join(updatesPart, ","))

		}
	}

	var sqlQueryParts = ""

	if a.Dialect == "postgres" {

		if len(primaryKey) > 0 {

			sqlQueryParts = fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) %s RETURNING %s",tableName,strings.Join(columns,","),strings.Join(placeHoldersParts,","),updateString,primaryKey)

		} else {

			sqlQueryParts = fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) %s ",tableName,strings.Join(columns,","),strings.Join(placeHoldersParts,","),updateString)

		}

	} else {

		sqlQueryParts = fmt.Sprintf("INSERT INTO %s (%s) VALUE (%s) %s",tableName,strings.Join(columns,","),strings.Join(placeHoldersParts,","),updateString)

	}

	a.SetQuery(sqlQueryParts)
	a.SetParams(params...)
	return a.InsertQuery()
}

func (a *Db) getValueKeyword() string {


	if a.Dialect == "postgres" {

		return "VALUES"
	}

	return "VALUES"
}