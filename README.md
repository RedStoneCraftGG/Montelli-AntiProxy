# Montelli-AntiProxy
A simple tool to detect proxies based on IP Address. Suitable for use in Dragonfly-MC to prevent proxy usage (not quite...)

## Usage

```go
package main

import (
    "fmt"
    "github.com/redstonecraftgg/montelli-antiproxy"
)

func main() {
    ips := []string{
        "127.0.0.1",     // localhost
        "192.168.1.100", // private
        "8.8.8.8",       // public
    }

    for _, ip := range ips {
        if CheckIP(ip) {
            fmt.Println(ip, "is Not Allowed")
        } else {
            fmt.Println(ip, "is Allowed")
        }
    }
}
```

*Note*: Localhost checking is disabled by default. Enable it manually in the config.

*Additional Note*: Yes, I'm playing WuWa and I use the Montelli name just for fun.
