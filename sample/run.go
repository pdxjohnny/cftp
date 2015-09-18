package sample

import (
	"fmt"

	"github.com/spf13/viper"
)

func Run() {
	fmt.Println("Hello", viper.GetString("name"))
}
