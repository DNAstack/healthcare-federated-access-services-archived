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

package dam

import (
	"net/http"

	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

func (s *Service) realmFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "realm",
		NameField:           "realm",
		PathPrefix:          realmPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return newRealmHandler(s, w, r)
		},
	}
}

type realmHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.RealmRequest
	item  *pb.Realm
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func newRealmHandler(s *Service, w http.ResponseWriter, r *http.Request) *realmHandler {
	return &realmHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.RealmRequest{},
	}
}

func (h *realmHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}

func (h *realmHandler) LookupItem(name string, vars map[string]string) bool {
	// Accept any name that passes the name check.
	h.item = &pb.Realm{}
	return true
}

func (h *realmHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.Realm{}
	}
	return nil
}

func (h *realmHandler) Get(name string) error {
	if h.item != nil {
		httputil.SendResponse(h.item, h.w)
	}
	return nil
}

func (h *realmHandler) Post(name string) error {
	// Accept, but do nothing.
	return nil
}

func (h *realmHandler) Put(name string) error {
	// Accept, but do nothing.
	return nil
}

func (h *realmHandler) Patch(name string) error {
	// Accept, but do nothing.
	return nil
}

func (h *realmHandler) Remove(name string) error {
	if err := h.s.store.Wipe(name); err != nil {
		return err
	}
	if name == storage.DefaultRealm {
		return h.s.ImportFiles(importDefault)
	}
	return h.s.unregisterRealm(h.cfg, name)
}

func (s *Service) unregisterRealm(cfg *pb.DamConfig, realm string) error {
	if s.warehouse == nil {
		return nil
	}
	return s.warehouse.RegisterAccountProject(realm, "", 0, 0)
}

func (h *realmHandler) CheckIntegrity() *status.Status {
	return nil
}

func (h *realmHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	// Accept, but do nothing.
	return nil
}
