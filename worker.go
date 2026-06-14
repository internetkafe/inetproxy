package main
import (
    "bufio"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "strings"
    "time"
)
type Worker struct {
    SubFile    string
    SocksUser  string
    SocksPass  string
    StartPort  int
    MaxProxies int
    XrayBin    string
}
func (w *Worker) Run() (working, spares []map[string]interface{}) {
    subURLs, err := readSubURLs(w.SubFile)
    if err != nil {
        log.Fatalf("Ошибка чтения файла подписок: %v", err)
    }
    allURIs := fetchSubscriptionsParallel(subURLs)
    log.Printf("Всего получено сырых строк из подписок: %d", len(allURIs))
    var rawOutbounds []map[string]interface{}
    for _, uri := range allURIs {
        uri = strings.TrimSpace(uri)
        var out map[string]interface{}
        var parseErr error
        if strings.HasPrefix(uri, "vless://") {
            out, parseErr = parseVLESS(uri)
        } else if strings.HasPrefix(uri, "vmess://") {
            out, parseErr = parseVMess(uri)
        } else if strings.HasPrefix(uri, "ss://") {
            out, parseErr = parseShadowsocks(uri)
        } else if strings.HasPrefix(uri, "trojan://") {
            out, parseErr = parseTrojan(uri)
        }
        if parseErr == nil && out != nil {
            rawOutbounds = append(rawOutbounds, out)
        }
    }
    if len(rawOutbounds) == 0 {
        log.Fatal("Валидных конфигов не найдено")
    }
    log.Printf("Успешно распарсено конфигов: %d. Начинаю проверку батчами...", len(rawOutbounds))
    batchSize := 150
    var workingOutbounds []map[string]interface{}
    checkedIndex := 0
    for i := 0; i < len(rawOutbounds); i += batchSize {
        if w.MaxProxies > 0 && len(workingOutbounds) >= w.MaxProxies {
            break
        }
        end := i + batchSize
        if end > len(rawOutbounds) {
            end = len(rawOutbounds)
        }
        batch := rawOutbounds[i:end]
        checkedIndex = end
        log.Printf("-> Проверка батча %d - %d из %d...", i+1, end, len(rawOutbounds))
        evalConfig := buildXrayConfig(batch, w.StartPort, w.SocksUser, w.SocksPass)
        evalFile := "eval_config.json"
        saveConfig(evalConfig, evalFile)
        evalCmd := startXrayBackground(evalFile, w.XrayBin)
        time.Sleep(5 * time.Second)
        needed := 0
        if w.MaxProxies > 0 {
            needed = w.MaxProxies - len(workingOutbounds)
        }
        aliveInBatch := checkProxiesParallel(batch, w.StartPort, w.SocksUser, w.SocksPass, needed)
        if evalCmd != nil && evalCmd.Process != nil {
            evalCmd.Process.Kill()
            evalCmd.Wait()
        }
        workingOutbounds = append(workingOutbounds, aliveInBatch...)
        log.Printf("   Найдено живых в батче: %d. Всего живых: %d", len(aliveInBatch), len(workingOutbounds))
    }
    if w.MaxProxies > 0 && len(workingOutbounds) > w.MaxProxies {
        workingOutbounds = workingOutbounds[:w.MaxProxies]
    }
    // Все, что не проверено или осталось после лимита, уходит в запас
    spares = rawOutbounds[checkedIndex:]
    return workingOutbounds, spares
}
func readSubURLs(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    var urls []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" && !strings.HasPrefix(line, "#") {
            urls = append(urls, line)
        }
    }
    return urls, scanner.Err()
}
func fetchSubscriptionsParallel(urls []string) []string {
    uriChan := make(chan []string, len(urls))
    var allURIs []string
    for _, u := range urls {
        go func(url string) {
            uris, err := fetchSubscription(url)
            if err != nil {
                uriChan <- nil
                return
            }
            uriChan <- uris
        }(u)
    }
    for i := 0; i < len(urls); i++ {
        uris := <-uriChan
        if uris != nil {
            allURIs = append(allURIs, uris...)
        }
    }
    return allURIs
}
func fetchSubscription(url string) ([]string, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("HTTP статус: %d", resp.StatusCode)
    }
    bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
    bodyString := strings.TrimSpace(string(bodyBytes))
    // Пытаемся декодировать всё тело как Base64 (очищая от пробелов и переносов)
    decoded, err := decodeBase64(bodyString)
    if err == nil && len(decoded) > 0 {
        decStr := string(decoded)
        // Проверка на адекватность: если после декодирования появились ссылки,
используем их
        if strings.Contains(decStr, "://") {
            return strings.Split(decStr, "\n"), nil
        }
    }
    // Если декодирование не удалось или это не Base64, значит файл уже в открытом виде
    return strings.Split(bodyString, "\n"), nil
}
