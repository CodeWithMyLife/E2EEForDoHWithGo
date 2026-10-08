//go:build !linux

package fastime

// protectFromOOM 非 Linux 平台无 oom_score_adj 机制，空实现。
func protectFromOOM() {}
