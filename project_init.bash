#!/bin/bash

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

PROJECT=${PROJECT}

print_usage() {
  echo -e ${RED?}'Usage: project_init [-h] [-p project_id]'${RESET?}
  echo -e ${RED?}'  -h \t show this help usage'${RESET?}
  echo -e ${RED?}'  -p \t GCP project_id to deploy to'${RESET?}
}

while getopts ':hp:' flag; do
  case "${flag}" in
    h) print_usage
       exit 1 ;;
    p) PROJECT="${OPTARG}" ;;
    *) echo -e ${RED?}'Unknown flag: -'${flag}${RESET?}
       print_usage
       exit 1 ;;
  esac
done

if [[ "${PROJECT}" == "" ]]; then
  echo -e ${RED?}'Must provide a project via $PROJECT or -p project'${RESET?}
  print_usage
  exit 1
fi

PROJECT_NUMBER=$(gcloud projects list --filter="${PROJECT?}" --format="value(PROJECT_NUMBER)")
if [[ "$?" != 0 ]]; then
  exit 1
fi

echo -e ${GREEN?}'Preparing the GCP project for deployment.'${RESET?}
# Enbable the required APIs.
echo -e ${GREEN?}'Enabling the required APIs.'${RESET?}

gcloud services enable \
  appengine.googleapis.com \
  appengineflex.googleapis.com \
  appenginestandard.googleapis.com \
  sql-component.googleapis.com \
  sqladmin.googleapis.com \
  datastore.googleapis.com \
  iam.googleapis.com \
  cloudbuild.googleapis.com \
  bigquery.googleapis.com \
  storage-component.googleapis.com \
  cloudkms.googleapis.com

# Create a GAE app.
gcloud app create --region=us-central

# Grant the required permissions.
echo -e ${GREEN?}'Granting the required permissions.'${RESET?}

gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT?}@appspot.gserviceaccount.com --role roles/cloudkms.cryptoKeyEncrypterDecrypter
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT?}@appspot.gserviceaccount.com --role roles/iam.serviceAccountTokenCreator

gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/cloudsql.client
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/editor
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/resourcemanager.projectIamAdmin

# TODO: make region configurable.

# Setup Cloud SQL
# Create a CloudSQL db-f1-micro (memory=128M, disk=250G) postgres 11 instance in us-central-1.
echo -e ${GREEN?}'Creating Cloud SQL database for Hydra.'${RESET?}

gcloud sql instances create hydra --database-version=POSTGRES_11 \
  --tier=db-f1-micro --region=us-central1
# Create user: name="${NAME}", password="${PASSWORD}"
gcloud sql users create hydra --instance=hydra --password=hydra
# Create database ic
gcloud sql databases create ic --instance=hydra
# Create database dam
gcloud sql databases create dam --instance=hydra

echo -e ${GREEN?}'Creating a GCS bucket with an example file.'${RESET?}

gsutil mb gs://${PROJECT?}-test-dataset
tempdir=`mktemp -d`
pushd $tempdir
echo "This is an example" > example.txt
gsutil cp example.txt gs://${PROJECT?}-test-dataset
popd
rm -rf $tempdir

# Deploy a simple defaut app to GAE default service.
echo -e ${GREEN?}'Deploy a helloworld to GAE default service.'${RESET?}

tempdir=`mktemp -d`
pushd $tempdir
git clone https://github.com/GoogleCloudPlatform/golang-samples.git
pushd golang-samples/appengine/go11x/helloworld
gcloud -q app deploy .
popd
popd
rm -rf $tempdir

echo -e ${GREEN?}'Building Base Hydra Docker Image.'${RESET?}
gcloud builds submit --config deploy/build/hydra/cloudbuild.yaml .

echo -e ${GREEN?}'Project initialization complete.'${RESET?}
