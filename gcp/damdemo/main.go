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

// Binary damdemo is a demo of DAM.
package main

import (
	"flag"
	"net/http"
	"strings"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */

	glog "github.com/golang/glog" /* copybara-comment */
)

var (
	hydraURL = osenv.MustVar("HYDRA_PUBLIC_URL")
	damURL   = osenv.MustVar("DAM_URL")
	project  = osenv.MustVar("PROJECT")
	srvName  = osenv.MustVar("TYPE")

	port = osenv.VarWithDefault("DAMDEMO_PORT", "8092")
)

const (
	htmlFile        = "pages/hydra-dam-test.html"
	staticDirectory = "assets/serve/"
)

func main() {
	flag.Parse()

	serviceinfo.Project = project
	serviceinfo.Type = "damdemo"
	serviceinfo.Name = srvName

	b, err := srcutil.Read(htmlFile)
	if err != nil {
		glog.Exitf("srcutil.Read(%v) failed: %v", htmlFile, err)
	}

	page := string(b)
	page = strings.ReplaceAll(page, "${HYDRA_URL}", hydraURL)
	page = strings.ReplaceAll(page, "${DAM_URL}", damURL)

	http.HandleFunc("/test", httputil.NewPageHandler(page))
	http.HandleFunc("/liveness_check", httputil.LivenessCheckHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(
		http.Dir(srcutil.Path(staticDirectory)))))

	glog.Infof("DAM Demo listing on port %s", port)
	glog.Exit(http.ListenAndServe(":"+port, nil))
}
