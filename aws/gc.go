package aws

import (
	"context"
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
)

// Run starts background processes of AccountWarehouse
func (wh *AccountWarehouse) Run(ctx context.Context)  {
	fmt.Printf("++++ Calling aws run ++++ \n")
	wh.keyGC.Run(ctx)
}

// Register AWS access key
func (wh *AccountWarehouse) RegisterAccountProject(project string, tx storage.Tx) error {
	//_, err := wh.keyGC.RegisterWork()
	fmt.Printf("*** Registering aws project ****")
	_, err := wh.keyGC.RegisterWork(project, nil, tx)
	return err
}

func (wh *AccountWarehouse) DeregisterAccountProject()  {

}

func (wh *AccountWarehouse) UpdateSettings()  {

}
