// A tiny local Redis for smoke tests: miniredis serving real RESP on a TCP port.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func main() {
	mr, err := miniredis.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(mr.Addr())
	select { case <-time.After(30 * time.Minute): }
}
