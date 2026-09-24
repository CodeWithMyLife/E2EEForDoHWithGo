package fastime

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 分级日志器：同时写标准输出与 fastime.log。
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

// openLogFile 依次尝试：当前工作目录 → 用户主目录。
// macOS .app 双击启动时工作目录是 /（不可写），回退到 ~/fastime.log。
func openLogFile() *os.File {
	if f, err := os.OpenFile("fastime.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		return f
	}
	if home, err := os.UserHomeDir(); err == nil {
		if f, err := os.OpenFile(filepath.Join(home, "fastime.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			return f
		}
	}
	return nil
}

func newLogger(level string) *logger {
	out := io.Writer(os.Stdout)
	if f := openLogFile(); f != nil {
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
