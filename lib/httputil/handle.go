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

package httputil

import (
	"encoding/json"
	"net/http"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
)

// WriteRPCResp writes reponse and error.
// Can be used to create an HTTP handler from a GRPC handler.
//
//  func (h *FooHTTPHandler) GetFoo(w http.ResponseWriter, r *http.Request) {
// 	  req := &fpb.GetFooRequest{Name: r.RequestURI}
// 	  resp := &fpb.Foo{}
// 	  err := fooServer.GetFoo(r.Context(), req, resp)
// 	  WriteRPCResp(w, resp, err)
//   }
//
// To return the detailed RPC Status error back to client as response, use:
//   WriteRPCResp(w, status.Convert(err).Proto(), nil)
//
// TODO: reconcile and ensure consistency with
//                  common.NewStatus() and common.SendStatus().
func WriteRPCResp(w http.ResponseWriter, resp interface{}, err error) {
	if err != nil {
		code := FromError(err)
		http.Error(w, err.Error(), code)
		return
	}

	WriteCorsHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		glog.Errorf("json.NewEncoder(writer).Encode(resp) failed: %v", err)
		http.Error(w, "encoding the response failed", http.StatusInternalServerError)
		return
	}
}

// WriteProtoResp writes an error status to the response.
func WriteProtoResp(w http.ResponseWriter, m proto.Message) {
	WriteCorsHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	if err := (&jsonpb.Marshaler{}).Marshal(w, m); err != nil {
		glog.Errorf("(&jsonpb.Marshaler{}).Marshal(w,resp) failed: %v", err)
		http.Error(w, "encoding the response status failed", http.StatusInternalServerError)
		return
	}
}

// WriteStatus writes an error status to the response.
func WriteStatus(w http.ResponseWriter, s *status.Status) {
	if s == nil {
		return
	}
	w.WriteHeader(HTTPStatus(s.Code()))
	WriteProtoResp(w, s.Proto())
}

// WriteCorsHeaders writes CORS headers (https://www.w3.org/TR/cors) to the response.
func WriteCorsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Origin, Accept, Authorization, X-Link-Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
}

// WriteHTMLResp writes a "text/html" type string to the ResponseWriter.
func WriteHTMLResp(w http.ResponseWriter, b []byte) {
	WriteCorsHeaders(w)
	w.Header().Set("Content-Type", "text/html")
	w.Write(b)
}

// WriteJSONResp writes "application.json" type string to the ResponseWriter.
func WriteJSONResp(w http.ResponseWriter, b []byte) {
	WriteCorsHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Write(b)
}

// WriteRedirect writes a redirect to the provider URL.
// If the provided URL is relative, it will be relative to the request URL.
func WriteRedirect(w http.ResponseWriter, r *http.Request, redirect string) {
	WriteCorsHeaders(w)
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}
