package db

import (
	"database/sql"
	"errors"
	"fmt"
	"goconnect/common"
	"log"
	"strings"

	"github.com/go-gorp/gorp"
	_ "github.com/mattn/go-sqlite3"
)

//cDB ..
type cDB struct {
	db    *sql.DB
	dbMap *gorp.DbMap
}

//---------------------------------------------------------------------------------------

//NormalizeString for IDatabase
func (thisPt *cDB) NormalizeString(input string) string {
	blackList := []string{"'", "\"", "--", ",", " and ", " union ", " or "}
	out := input
	for _, b := range blackList {
		out = strings.ReplaceAll(out, b, "")
	}
	return out
}

//---------------------------------------------------------------------------------------

//LoadObject for IDatabase
func (thisPt *cDB) LoadObject(objects interface{}, query string, args ...interface{}) error {

	//simple sql injection check
	for i, arg := range args {
		if str, ok := arg.(string); ok == true {
			args[i] = thisPt.NormalizeString(str)
		}
	}

	finalQuery := fmt.Sprintf(query, args...)

	_, err := thisPt.dbMap.Select(objects, finalQuery)
	return err
}

//---------------------------------------------------------------------------------------

//RemoveObject for IDatabase
func (thisPt *cDB) RemoveObject(tableName string, object interface{}) error {
	_, err := thisPt.dbMap.Delete(object)
	return err
}

//---------------------------------------------------------------------------------------

//UpdateObject for IDatabase
func (thisPt *cDB) UpdateObject(tableName string, object interface{}) error {
	_, err := thisPt.dbMap.Update(object)
	return err
}

//---------------------------------------------------------------------------------------

//SerializeObject for IDatabase
func (thisPt *cDB) SerializeObject(tableName string, object interface{}) error {
	return thisPt.dbMap.Insert(object)
}

//---------------------------------------------------------------------------------------

//Register for IDatabase
func (thisPt *cDB) Register(tableName string, object interface{}) error {
	thisPt.dbMap.AddTableWithName(object, tableName)
	return thisPt.dbMap.CreateTablesIfNotExists()
}

//---------------------------------------------------------------------------------------

//
func (thisPt *cDB) init(driver string, params string) error {
	db, err := sql.Open(driver, params)
	if err != nil {
		return err
	}
	thisPt.db = db
	if driver == "sqlite3" {
		thisPt.dbMap = &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	} else {
		return errors.New("unsupported database driver")
	}
	return nil
}

//---------------------------------------------------------------------------------------

//Create database object
func Create(driver string, params string) common.IDatabase {
	obj := new(cDB)
	if err := obj.init(driver, params); err != nil {
		log.Printf("can not create database object with error %v \n", err)
		return nil
	}
	return obj
}
