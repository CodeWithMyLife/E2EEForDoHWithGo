//go:build android

package fastime

import (
	"os"
	"os/exec"
	"strings"
)

// Android root/守护进程场景：bionic 不会给非 App 进程注入 TZ 环境变量，
// Go 的 time.Local 因此回退成 UTC，日志时间比本地慢 8 小时。
// 启动时（任何日志输出之前）从系统属性 persist.sys.timezone 读出
// 真实时区并写入 TZ，之后 time.Local 即与系统设置一致。
func init() {
	if os.Getenv("TZ") != "" {
		return // 用户显式设置过时区，尊重之
	}
	out, err := exec.Command("getprop", "persist.sys.timezone").Output()
	if err != nil {
		return
	}
	if tz := strings.TrimSpace(string(out)); tz != "" {
		_ = os.Setenv("TZ", tz) // 须在首次使用本地时间之前生效
	}
}
