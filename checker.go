package main

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "time"

    "golang.org/x/net/proxy"
)

func checkSingleProxy(port int, user, pass string) bool {
    auth := &proxy.Auth{User: user, Password: pass}
    dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), auth, &net.Dialer{Timeout: 5 * time.Second})
    if err != nil {
        return false
    }

    client := &http.Client{
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                return dialer.Dial(network, addr)
            },
        },
        Timeout: 10 * time.Second,
    }

    resp, err := client.Get("http://www.gstatic.com/generate_204")
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    return resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK
}

func checkProxiesParallel(outbounds []map[string]interface{}, startPort int, user, pass string, needed int) []map[string]interface{} {
    type result struct {
        index   int
        isAlive bool
    }
    resultsChan := make(chan result, len(outbounds))
    var workingOutbounds []map[string]interface{}

    for i := range outbounds {
        go func(idx int) {
            resultsChan <- result{index: idx, isAlive: checkSingleProxy(startPort+idx, user, pass)}
        }(i)
    }

    checked := 0
    for res := range resultsChan {
        checked++
        if res.isAlive {
            workingOutbounds = append(workingOutbounds, outbounds[res.index])
        }
        if needed > 0 && len(workingOutbounds) >= needed {
            break
        }
        if checked == len(outbounds) {
            break
        }
    }
    return workingOutbounds
}

// Новая функция для перепроверки: возвращает map[индекс]жив_ли
func checkProxiesStatus(outbounds []map[string]interface{}, startPort int, user, pass string) map[int]bool {
    type result struct {
        index   int
        isAlive bool
    }
    resultsChan := make(chan result, len(outbounds))
    status := make(map[int]bool)

    for i := range outbounds {
        go func(idx int) {
            resultsChan <- result{index: idx, isAlive: checkSingleProxy(startPort+idx, user, pass)}
        }(i)
    }

    for i := 0; i < len(outbounds); i++ {
        res := <-resultsChan
        status[res.index] = res.isAlive
    }
    return status
}
