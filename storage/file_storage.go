// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"

	// TODO: this should be more generic, not DAM pb.
	pb "google3/third_party/hcls_federated_access/dam/api/v1/go_proto"
)

const (
	storageType    = "file"
	storageVersion = "v0"
)

var (
	// ProjectRoot locates resources of project.
	ProjectRoot = os.Getenv("PROJECT_ROOT")
)

type FileStorage struct {
	service string
	path    string
	cache   *StorageCache
	mutex   *sync.Mutex
}

func NewFileStorage(service, path string) *FileStorage {
	path = filepath.Join(ProjectRoot, path)
	// Add the service name directory to the path:
	// 1. Add the full service name if the subdirectory exists; or
	// 2. The base service name (i.e. before the first "-" character).
	servicePath := filepath.Join(path, service)
	if err := checkFile(servicePath); err == nil {
		path = servicePath
	} else {
		path = filepath.Join(path, strings.Split(service, "-")[0])
	}
	log.Printf("file storage for service %q using path %q.", service, path)
	f := &FileStorage{
		service: strings.Split(service, "-")[0],
		path:    path,
		cache:   NewStorageCache(),
		mutex:   &sync.Mutex{},
	}

	return f
}

func (f *FileStorage) Info() map[string]string {
	return map[string]string{
		"type":    storageType,
		"version": storageVersion,
		"service": f.service,
		"path":    f.path,
	}
}

func (f *FileStorage) Exists(datatype, realm, user, id string, rev int64) (bool, error) {
	fn := f.fname(datatype, realm, user, id, rev)
	if _, ok := f.cache.GetEntity(fn); ok {
		return true, nil
	}
	err := checkFile(fn)
	if err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (f *FileStorage) Read(datatype, realm, user, id string, rev int64, content proto.Message) error {
	return f.ReadTx(datatype, realm, user, id, rev, content, nil)
}

func (f *FileStorage) ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx Tx) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	fname := f.fname(datatype, realm, user, id, rev)
	if tx == nil || !tx.IsUpdate() {
		if data, ok := f.cache.GetEntity(fname); ok {
			content.Reset()
			proto.Merge(content, data)
			return nil
		}
	}

	if tx == nil {
		var err error
		tx, err = f.Tx(false)
		if err != nil {
			return fmt.Errorf("file read lock error: %v", err)
		}
		defer tx.Finish()
	}

	if err := checkFile(fname); err != nil {
		return err
	}
	file, err := os.Open(fname)
	if err != nil {
		return fmt.Errorf("file %q I/O error: %v", fname, err)
	}
	defer file.Close()
	if err := jsonpb.Unmarshal(file, content); err != nil && err != io.EOF {
		return fmt.Errorf("file %q invalid JSON: %v", fname, err)
	}
	if rev == LatestRev {
		f.cache.PutEntity(fname, content)
	}
	return nil
}

func (f *FileStorage) MultiReadTx(datatype, realm, user string, content map[string]map[string]proto.Message, typ proto.Message, tx Tx) error {
	return fmt.Errorf("file storage does not support MultiReadTx")
}

func (f *FileStorage) ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error {
	return f.ReadHistoryTx(datatype, realm, user, id, content, nil)
}

func (f *FileStorage) ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx Tx) error {
	if tx == nil {
		var err error
		tx, err = f.Tx(false)
		if err != nil {
			return fmt.Errorf("history file read lock error: %v", err)
		}
		defer tx.Finish()
	}

	hfname := f.historyName(datatype, realm, user, id)
	if err := checkFile(hfname); err != nil {
		return err
	}
	b, err := ioutil.ReadFile(hfname)
	if err != nil {
		return fmt.Errorf("history file %q I/O error: %v", hfname, err)
	}
	full := `{"history":[` + string(b[:len(b)]) + "]}"
	his := &pb.History{}
	if err := jsonpb.Unmarshal(strings.NewReader(full), his); err != nil {
		return fmt.Errorf("history file %q invalid JSON: %v", hfname, err)
	}
	for _, he := range his.History {
		*content = append(*content, proto.Message(he))
	}
	f.cache.PutHistory(hfname, *content)
	return nil
}

func (f *FileStorage) Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error {
	return fmt.Errorf("file storage does not support Write")
}

func (f *FileStorage) WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx Tx) error {
	return fmt.Errorf("file storage does not support WriteTx")
}

// Delete a record.
func (f *FileStorage) Delete(datatype, realm, user, id string, rev int64) error {
	return fmt.Errorf("file storage does not support Delete")
}

// DeleteTx delete a record with transaction.
func (f *FileStorage) DeleteTx(datatype, realm, user, id string, rev int64, tx Tx) error {
	return fmt.Errorf("file storage does not support DeleteTx")
}

// MultiDeleteTx deletes all records of a certain data type within a realm.
func (f *FileStorage) MultiDeleteTx(datatype, realm, user string, tx Tx) error {
	return fmt.Errorf("file storage does not support MultiDeleteTx")
}

// Wipe deletes all records within a realm.
func (f *FileStorage) Wipe(realm string) error {
	return fmt.Errorf("file storage does not support Wipe")
}

func (f *FileStorage) Tx(update bool) (Tx, error) {
	return &FileTx{
		writer: update,
	}, nil
}

func (f *FileStorage) fname(datatype, realm, user, id string, rev int64) string {
	r := LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	// TODO: use path.Join(...)
	return fmt.Sprintf("%s/%s_%s%s_%s_%s.json", f.path, datatype, realm, UserFragment(user), id, r)
}

func (f *FileStorage) historyName(datatype, realm, user, id string) string {
	return fmt.Sprintf("%s/%s_%s%s_%s_%s.json", f.path, datatype, realm, UserFragment(user), id, HistoryRevName)
}

func checkFile(path string) error {
	_, err := os.Stat(path)
	return err
}

type FileTx struct {
	writer bool
}

func (tx *FileTx) Finish() {
}

func (tx *FileTx) Rollback() {
	// NOT SUPPORTED
}

func (tx *FileTx) IsUpdate() bool {
	return tx.writer
}

func UserFragment(user string) string {
	if user == DefaultUser {
		return ""
	}
	return "_" + user
}
