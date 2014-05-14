package platform

import (
	"os"
)

type Platform struct{}

const name = "platform"

func (self *Platform) Name() string {
	return name
}

func (self *Platform) Collect() (result interface{}, err error) {
    result, err = getPlatformInfo()
    return
}

func getPlatformInfo() (platformInfo map[string]interface{}, err error) {
    platformInfo = make(map[string]interface{})

    hostname, err := os.Hostname()
    if err != nil {
        return platformInfo, err
    }
    platformInfo["hostname"] = hostname

    return
}
