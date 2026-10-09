//go:build linux

package fastime

import "os"

// protectFromOOM 把本进程的 oom_score_adj 设为最小值（-1000），让 Android LMK /
// 内核 OOM killer 永远最后才考虑杀我们——本地中继被杀了，指向它的客户端全部断流。
// 需要 root（写 /proc/self/oom_score_adj 负值要 CAP_SYS_RESOURCE）；失败静默
// 忽略——这只是保命优化，不影响功能。
func protectFromOOM() {
	_ = os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0644)
}
