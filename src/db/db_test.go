package db

import "testing"

type testObject struct {
	ID          int64  `db:"id, primarykey, autoincrement"`
	ValueNumber int64  `db:"ValueNumber"`
	ValueString string `db:"ValueString,size:1024"`
}

type testObject2 struct {
	ID          int64  `db:"id, primarykey, autoincrement"`
	ValueNumber int64  `db:"ValueNumber"`
	ValueString string `db:"-"`
}

func TestDB(t *testing.T) {
	db := cDB{}

	if db.init("sqlite3", "/tmp/test.db") != nil {
		t.Fatalf("can not create database object")
	}

	if db.Register("test", testObject{}) != nil {
		t.Fatalf("can not create database table")
	}

	if db.Register("test2", testObject2{}) != nil {
		t.Fatalf("can not create database table")
	}

	err := db.SerializeObject("test", &testObject{ValueNumber: 10})
	if err != nil {
		t.Fatalf("can not insert database object %v", err)
	}

	var objects []testObject
	err = db.LoadObject(&objects, "select * from test")
	if err != nil {
		t.Fatalf("can load objects %v", err)
	}

	if len(objects) < 1 {
		t.Fatalf("can load objects")
	}

	err = db.UpdateObject("test", &testObject{ID: 1, ValueNumber: 20, ValueString: "hello"})
	if err != nil {
		t.Fatalf("can not insert database object %v", err)
	}

	//CHECK DELETE and UPDATE
	objects = nil
	err = db.LoadObject(&objects, "select * from test where id=%d", 1)
	if err != nil {
		t.Fatalf("can load objects %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("can load objects")
	}
	if objects[0].ValueNumber != 20 {
		t.Fatalf("update failed")
	}

	objects = nil
	err = db.LoadObject(&objects, "select * from test where ValueString='%s'", "11' or 1=1 or ValueString='")
	if err != nil {
		t.Fatalf("can load objects %v", err)
	}
	if len(objects) != 0 {
		t.Fatalf("sql injection !!!")
	}

	//remove objects
	err = db.RemoveObject("test", &testObject{ID: 1})
	if err != nil {
		t.Fatalf("can not insert database object %v", err)
	}

	objects = nil
	if err = db.LoadObject(&objects, "select * from test where id=%d", 1); err != nil || len(objects) != 0 {
		t.Fatalf("can not insert database object %v", err)
	}

}
