package main

import (
    "encoding/json"
    "io"
    "os"
    "os/exec"
)

type XrayConfig struct {
    Log       *LogConfig               `json:"log"`
    Inbounds  []map[string]interface{} `json:"inbounds"`
    Outbounds []map[string]interface{} `json:"outbounds"`
    Routing   *RoutingConfig           `json:"routing"`
}

type LogConfig struct {
    LogLevel string `json:"loglevel"`
}

type RoutingConfig struct {
    Rules []map[string]interface{} `json:"rules"`
}

func buildXrayConfig(outbounds []map[string]interface{}, startPort int, user, pass string) *XrayConfig {
    inbounds := []map[string]interface{}{}
    rules := []map[string]interface{}{}
    allOutbounds := []map[string]interface{}{{"protocol": "freedom", "tag": "direct"}}

    for idx, out := range outbounds {
        tag := fmt.Sprintf("out_%d", idx)
        out["tag"] = tag
        port := startPort + idx
        inTag := fmt.Sprintf("socks_in_%d", port)

        inbounds = append(inbounds, map[string]interface{}{
            "port": port, "listen": "0.0.0.0", "protocol": "socks",
            "settings": map[string]interface{}{
                "auth": "password",
                "accounts": []map[string]string{
                    {"user": user, "pass": pass},
                },
                "udp": true,
            },
            "tag": inTag,
        })
        allOutbounds = append(allOutbounds, out)
        rules = append(rules, map[string]interface{}{
            "type": "field", "inboundTag": []string{inTag}, "outboundTag": tag,
        })
    }
    return &XrayConfig{
        Log: &LogConfig{LogLevel: "none"}, Inbounds: inbounds, 
        Outbounds: allOutbounds, Routing: &RoutingConfig{Rules: rules},
    }
}

func saveConfig(config *XrayConfig, filename string) error {
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(filename, data, 0644)
}

func startXrayBackground(configFile, bin string) *exec.Cmd {
    cmd := exec.Command(bin, "run", "-c", configFile)
    logFile, _ := os.OpenFile("eval_xray.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    cmd.Stdout = logFile
    cmd.Stderr = logFile
    cmd.Start()
    return cmd
}

func startXrayFinal(configFile, bin string) *exec.Cmd {
    cmd := exec.Command(bin, "run", "-c", configFile)
    cmd.Stdout = io.Discard
    cmd.Stderr = io.Discard
    cmd.Start()
    return cmd
}
