package processaws

import (
	context2 "context"
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	processlib "github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/process"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1"
	"golang.org/x/net/context"
	"time"
)

const (
	keyScheduleFrequency    = time.Hour
	maxKeyScheduleFrequency = 12 * time.Hour
)

// define a garbage collector background process for policies and keys
type KeyGc struct {
	name    string
	aw      clouds.AccountManager
	process *processlib.Process
	wait    func(ctx context.Context, duration time.Duration) bool
}

// method to create a new garbage collector
func NewKeyGC(name string, warehouse clouds.AccountManager, store storage.Store, maxRequestedTTL time.Duration, keysPerAccount int) *KeyGc{
	k := &KeyGc{
		name:    name,
		aw:      warehouse,
	}

	defaultParams := &pb.Process_Params{
		IntParams: map[string]int64{
			"maxRequestedTtl": int64(maxRequestedTTL.Seconds()),
			"keysPerAccount":  int64(keysPerAccount),
			"keyTtl":          int64(timeutil.KeyTTL(maxRequestedTTL, keysPerAccount).Seconds()),
		},
	}

	fmt.Printf("*** Calling New Process *** \n")

	k.process = processlib.NewProcess(name, k, store, keyScheduleFrequency, defaultParams)

	return k
}

func (k *KeyGc) RegisterWork(workName string, params *pb.Process_Params, tx storage.Tx) (*pb.Process_Work, error) {
	return k.process.RegisterWork(workName, params, tx)
}

func (k *KeyGc) UnregisterWork(workName string, tx storage.Tx) error  {
	return k.process.UnregisterWork(workName, tx)
}

func (k *KeyGc) UpdateSettings(maxRequestedTTL time.Duration, keysPerAccount int, tx storage.Tx) error {
	keyTTL := timeutil.KeyTTL(maxRequestedTTL, keysPerAccount)
	settings := &pb.Process_Params{
		IntParams: map[string]int64{
			"maxRequestedTtl": int64(maxRequestedTTL.Seconds()),
			"keysPerAccount":  int64(keysPerAccount),
			"keyTtl":          int64(keyTTL.Seconds()),
		},
	}
	scheduleFrequency := keyTTL / 10
	if scheduleFrequency > maxKeyScheduleFrequency {
		scheduleFrequency = maxKeyScheduleFrequency
	}
	return k.process.UpdateSettings(scheduleFrequency, settings, tx)
}

// WaitCondition registers a callback that is called and checks conditions before every wait cycle.
func (k *KeyGc) WaitCondition(fn func(ctx context.Context, duration time.Duration) bool) {
	k.wait = fn
}

// processlib implementations
func (k *KeyGc) ProcessActiveWork(ctx context2.Context, state *pb.Process, workName string, work *pb.Process_Work, process *processlib.Process) error {
	panic("implement me process active work")
}

func (k *KeyGc) CleanupWork(ctx context2.Context, state *pb.Process, workName string, process *processlib.Process) error {
	panic("implement me cleanup work")
}

func (k *KeyGc) Wait(ctx context2.Context, duration time.Duration) bool {
	fmt.Printf("!!!!!WAITING!!!!! \n")
	if k.wait != nil && !k.wait(ctx, duration) {
		return false
	}
	time.Sleep(duration)
	return true
}

// Run schedules a background process.
func (k *KeyGc) Run(ctx context.Context)  {
	fmt.Printf("++++ Calling aws run ++++ \n")
	k.process.Run(ctx)
}
