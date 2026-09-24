package fastime

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// 分级日志器：同时写标准输出与程序目录下的 fastime.log。
// 等级由 LOG_LEVEL 控制：debug(详细，含每次请求/拨号/缓存细节) > info > error(仅错误)。
type logger struct {
	mu  sync.Mutex
	lvl int
	out io.Writer
}

const (
	lvlDebug = iota
	lvlInfo
	lvlError
)

func parseLevel(s string) int {
	switch s {
	case "debug":
		return lvlDebug
	case "error":
		return lvlError
	default:
		return lvlInfo
	}
}

func newLogger(level string) *logger {
	out := io.Writer(os.Stdout)
	// 日志文件写在当前工作目录（APK/Magisk/桌面端均可写场景下生效）
	if f, err := os.OpenFile("fastime.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		out = io.MultiWriter(os.Stdout, f)
	}
	return &logger{lvl: parseLevel(level), out: out}
}

func (l *logger) logf(lvl int, tag, format string, args ...any) {
	if lvl < l.lvl {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s [%s] %s\n",
		time.Now().Format("15:04:05.000000"), tag, fmt.Sprintf(format, args...))
}

func (l *logger) Debugf(f string, a ...any) { l.logf(lvlDebug, "DEBUG", f, a...) }
func (l *logger) Infof(f string, a ...any)  { l.logf(lvlInfo, "INFO", f, a...) }
func (l *logger) Errorf(f string, a ...any) { l.logf(lvlError, "ERROR", f, a...) }
