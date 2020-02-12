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
	"net/http"

	glog "github.com/golang/glog" /* copybara-comment */
)

// LivenessCheckHandler implements an application liveness checker for Google App Engine Flex apps
func LivenessCheckHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSONResp(w, []byte(`{"status":"Service is Up and Running"}`))
}

// StopHandler will cause make the server exit.
func StopHandler(w http.ResponseWriter, r *http.Request) {
	glog.Exitf("Stop handler is called. The server is stopping.")
}

// NewPageHandler creates a new handler that serves the given HTML page.
func NewPageHandler(page string) func(w http.ResponseWriter, r *http.Request) {
	return Page{Page: page}.Handler
}

// Page is handler for a fixed HTML page.
type Page struct {
	Page string
}

// Handler serve the stored page.
func (s Page) Handler(w http.ResponseWriter, r *http.Request) {
	WriteHTMLResp(w, []byte(s.Page))
}
